package org.wolpmessenger.devicetrust.e2ee

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.wolpmessenger.devicetrust.Journal
import org.wolpmessenger.devicetrust.alert.AlertSink
import org.wolpmessenger.devicetrust.api.E2ee
import org.wolpmessenger.devicetrust.api.E2eeException
import org.wolpmessenger.devicetrust.api.E2eeFailure
import org.wolpmessenger.devicetrust.api.E2eePeerState
import org.wolpmessenger.devicetrust.api.E2eePeerTrust
import org.wolpmessenger.devicetrust.api.RaspFinding
import org.wolpmessenger.devicetrust.api.RaspReaction
import org.wolpmessenger.devicetrust.api.Vault
import org.wolpmessenger.devicetrust.keys.KeystoreKeys
import org.wolpmessenger.devicetrust.store.TrustStore
import java.io.ByteArrayInputStream
import java.io.File
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.Instant

/**
 * Secret chats put together for the app (specs/002, story 3): the protocol and its files
 * ([SecretChats]), the key directory ([KeyDirectoryClient], [KeySync]), this device's passport signed
 * by the device key in the Keystore, and the alerts to the gateway.
 *
 * The account is the one in the device certificate, so everything here exists only while the device
 * is enrolled; without a certificate every operation is `NOT_ENROLLED`.
 */
internal class E2eeService<D>(
    private val dir: File,
    private val vault: Vault,
    private val store: TrustStore,
    private val keys: KeystoreKeys,
    private val trust: PassportTrust,
    private val directory: D,
    private val alerts: AlertSink,
    private val now: () -> Instant,
    /** The Kratos session cookie: after [wipe] nothing is published until another session appears. */
    private val cookie: () -> String? = { null },
    /** Monotonic milliseconds, for [syncIfDue]. */
    private val monotonicMs: () -> Long = { System.nanoTime() / 1_000_000 },
) : E2ee where D : KeyDirectory, D : OwnRecord {

    private class Session(val user: String, val chats: SecretChats, val sync: KeySync)

    private class Signed(val serial: String, val identityKey: ByteArray, val passport: Passport)

    @Volatile
    private var session: Session? = null

    @Volatile
    private var signed: Signed? = null

    @Volatile
    private var syncedAt: Pair<String, Long>? = null // certificate serial to monotonic time of the last good pass

    /**
     * Written by [wipe]: a digest of the session that was signed out of (or [NO_SESSION]). No
     * publication while it lasts. A file beside the key files: the ban has to outlive the process.
     */
    private val signedOut = File(dir.path + ".signed-out")

    override suspend fun encrypt(peer: String, text: String): String = io { chats.encrypt(peer, text) }

    override suspend fun decrypt(peer: String, envelope: String): String = io { chats.decrypt(peer, envelope) }

    override suspend fun peerState(peer: String): E2eePeerState = io {
        val (trust, changed) = chats.peerState(peer)
        E2eePeerState(E2eePeerTrust.valueOf(trust.name), changed)
    }

    override suspend fun safetyNumber(peer: String): String? = io { chats.safetyNumber(peer) }

    override suspend fun setVerified(peer: String, verified: Boolean, safetyNumber: String?): Unit = io { chats.setVerified(peer, verified, safetyNumber) }

    override suspend fun keyChangeSeen(peer: String): Unit = io { chats.keyChangeSeen(peer) }

    override suspend fun resetSession(peer: String): Unit = io { chats.resetSession(peer) }

    override suspend fun wipe(): Unit = withContext(Dispatchers.IO) {
        // first: a pass starting now, or the next process, must not publish the keys back
        runCatching { signedOut.writeText(cookie()?.let(::digest) ?: NO_SESSION) }
        val s = runCatching { current() }.getOrNull()
        if (s != null) {
            // peers get "no device" instead of encrypting to a key that is about to be erased
            try {
                withTimeout(DIRECTORY_TIMEOUT_MS) { directory.remove(s.chats.directoryId()) }
            } catch (e: Exception) {
                Journal.event("e2ee_wipe", "the directory record stays: ${(e as? E2eeException)?.failure?.code ?: e.javaClass.simpleName}")
            }
            s.chats.wipe()
        } else {
            dir.listFiles()?.forEach { it.delete() } // not enrolled: nothing to remove from the directory
        }
        signed = null
        syncedAt = null
    }

    /**
     * One pass of [KeySync]; false when it has to be repeated (locked, not enrolled, no network,
     * signed out).
     * Never throws: it runs in the background.
     */
    suspend fun sync(): Boolean = try {
        io {
            val serial = store.load().active?.serialHex ?: throw E2eeException(E2eeFailure.NOT_ENROLLED)
            if (signedOut.exists()) {
                val out = runCatching { signedOut.readText() }.getOrDefault(NO_SESSION)
                val session = cookie()
                if (session == null || digest(session) == out) throw E2eeException(E2eeFailure.NOT_ENROLLED) // nobody is signed in
                signedOut.delete()
            }
            sync.sync()
            syncedAt = serial to monotonicMs()
        }
        true
    } catch (e: CancellationException) {
        throw e
    } catch (e: E2eeException) {
        Journal.event("e2ee_sync_failed", e.failure.code + (e.cause?.message?.takeIf { it.startsWith("key directory answered") }?.let { " $it" } ?: ""))
        false
    } catch (e: Exception) {
        Journal.event("e2ee_sync_failed", e.javaClass.simpleName)
        false
    }

    /**
     * [sync] when the last good pass was with another certificate (the passport in the directory is
     * the old one, FR-023) or longer than [SYNC_EVERY_MS] ago (FR-024, FR-025).
     */
    suspend fun syncIfDue(): Boolean {
        val serial = store.load().active?.serialHex ?: return false
        val last = syncedAt
        if (last != null && last.first == serial && monotonicMs() - last.second < SYNC_EVERY_MS) return true
        return sync()
    }

    private suspend fun <T> io(block: suspend Session.() -> T): T = withContext(Dispatchers.IO) { current().block() }

    /** The device certificate chain in use, the device certificate first. */
    private fun chain(): Pair<String, List<X509Certificate>> {
        val active = store.load().active ?: throw E2eeException(E2eeFailure.NOT_ENROLLED)
        val chain = KeystoreKeys.deviceKeyNumber(active.alias)?.let(store::readChain)?.takeIf { it.isNotEmpty() } ?: throw E2eeException(E2eeFailure.NOT_ENROLLED)
        return active.alias to chain
    }

    /** The protocol state of the account in the device certificate. */
    private fun current(): Session {
        val user = uri(chain().second.first(), USER_URN) ?: throw E2eeException(E2eeFailure.NOT_ENROLLED)
        session?.takeIf { it.user == user }?.let { return it }
        synchronized(this) {
            session?.takeIf { it.user == user }?.let { return it }
            val chats = SecretChats(user, dir, vault, directory, PassportCheck(trust, now), ::ownPassport, ::badPassport) { now().toEpochMilli() }
            val sync = KeySync(user, chats, directory, ::ownPassport, ::foreignKey, File(dir, "published"))
            return Session(user, chats, sync).also { session = it }
        }
    }

    /**
     * This device's passport: the device key in the Keystore signs the identity key (FR-010). Made
     * once per certificate — a passport holds nothing secret.
     */
    private suspend fun ownPassport(identityKey: ByteArray): Passport = withContext(Dispatchers.IO) {
        val (alias, chain) = chain()
        val device = chain.first()
        val serial = device.serialNumber.toString(16)
        signed?.takeIf { it.serial == serial && it.identityKey.contentEquals(identityKey) }?.let { return@withContext it.passport }
        val user = uri(device, USER_URN)
        val deviceId = uri(device, DEVICE_URN)
        val key = runCatching { keys.privateKey(alias) }.getOrNull()
        if (user == null || deviceId == null || key == null) throw E2eeException(E2eeFailure.NOT_ENROLLED)
        val passport = try {
            // the trusted root, if the gateway sent it along, is not part of a passport
            Passport.sign(key, user, deviceId, identityKey, chain.filter { c -> trust.roots.none { it == c } }.take(Passport.MAX_CERTIFICATES))
        } catch (e: Exception) {
            throw E2eeException(E2eeFailure.NOT_ENROLLED, e) // the device key is gone or unusable
        }
        signed = Signed(serial, identityKey, passport)
        passport
    }

    /** FR-017. The peer goes into the detail: one message per peer and fault a day (S2 §7.4). */
    private fun badPassport(peer: String, fault: PassportFault) {
        Journal.event("e2ee_bad_passport", fault.name)
        runCatching { alerts.report(listOf(RaspFinding(BAD_PASSPORT, RaspReaction.REPORT, "${fault.name} $peer"))) }
    }

    private fun foreignKey() {
        Journal.event("e2ee_foreign_key")
        runCatching { alerts.report(listOf(RaspFinding(FOREIGN_KEY, RaspReaction.REPORT))) }
    }

    /** The session cookie is not kept in a file as it is. */
    private fun digest(session: String): String =
        MessageDigest.getInstance("SHA-256").digest(session.toByteArray()).joinToString("") { "%02x".format(it) }

    internal companion object {
        /** Check ids of the alerts; the gateway takes any `^[A-Z0-9_]{1,48}$`. */
        const val BAD_PASSPORT = "E2EE_BAD_PASSPORT"
        const val FOREIGN_KEY = "E2EE_FOREIGN_KEY"

        const val SYNC_EVERY_MS = 60L * 60 * 1000

        /** A sign-out must not wait for a slow key directory. */
        const val DIRECTORY_TIMEOUT_MS = 4_000L
        private const val NO_SESSION = ""

        private const val USER_URN = "urn:wolp:user:"
        private const val DEVICE_URN = "urn:wolp:device:"
        private const val SAN_URI = 6

        private fun uri(c: X509Certificate, prefix: String): String? = runCatching {
            c.subjectAlternativeNames.orEmpty().filter { it[0] == SAN_URI }.map { it[1] as String }
                .singleOrNull { it.startsWith(prefix) }?.removePrefix(prefix)?.takeIf { it.isNotEmpty() }
        }.getOrNull()

        /**
         * What the build trusts (FR-012): [roots] — PEM text with the root certificates of the contour,
         * [issuers] — SHA-256 of the public key (SPKI, hex) of every authority that issues device
         * certificates. Null when the app configured neither; one without the other is a mistake.
         */
        fun trust(roots: List<String>, issuers: List<String>): PassportTrust? {
            if (roots.isEmpty() && issuers.isEmpty()) return null
            require(roots.isNotEmpty() && issuers.isNotEmpty()) { "e2eeRoots and e2eeIssuers go together" }
            require(issuers.all { HEX64.matches(it) }) { "e2eeIssuers: SHA-256 of the issuer's public key, 64 hex digits" }
            val factory = CertificateFactory.getInstance("X.509")
            val certificates = roots.flatMap { pem -> factory.generateCertificates(ByteArrayInputStream(pem.toByteArray())).map { it as X509Certificate } }
            require(certificates.isNotEmpty()) { "e2eeRoots: no certificate in the PEM text" }
            return PassportTrust(certificates, issuers)
        }

        private val HEX64 = Regex("^[0-9a-fA-F]{64}$")
    }
}
