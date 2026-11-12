package org.wolpmessenger.devicetrust.e2ee

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.signal.libsignal.protocol.DuplicateMessageException
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.InvalidKeyIdException
import org.signal.libsignal.protocol.NoSessionException
import org.signal.libsignal.protocol.ReusedBaseKeyException
import org.signal.libsignal.protocol.SessionBuilder
import org.signal.libsignal.protocol.SessionCipher
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.ecc.ECKeyPair
import org.signal.libsignal.protocol.ecc.ECPublicKey
import org.signal.libsignal.protocol.fingerprint.NumericFingerprintGenerator
import org.signal.libsignal.protocol.groups.state.SenderKeyRecord
import org.signal.libsignal.protocol.kem.KEMKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyType
import org.signal.libsignal.protocol.kem.KEMPublicKey
import org.signal.libsignal.protocol.message.CiphertextMessage
import org.signal.libsignal.protocol.message.PreKeySignalMessage
import org.signal.libsignal.protocol.message.SignalMessage
import org.signal.libsignal.protocol.state.IdentityKeyStore
import org.signal.libsignal.protocol.state.KyberPreKeyRecord
import org.signal.libsignal.protocol.state.PreKeyBundle
import org.signal.libsignal.protocol.state.PreKeyRecord
import org.signal.libsignal.protocol.state.SessionRecord
import org.signal.libsignal.protocol.state.SignalProtocolStore
import org.signal.libsignal.protocol.state.SignedPreKeyRecord
import org.wolpmessenger.devicetrust.api.E2eeException
import org.wolpmessenger.devicetrust.api.E2eeFailure
import org.wolpmessenger.devicetrust.api.Vault
import java.io.File
import java.time.Instant
import java.util.Base64
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Secret-chat keys and encryption (specs/002, story 1): libsignal over files under the Vault.
 * No call returns a private key or signs the caller's data (FR-003).
 *
 * Every operation runs alone (FR-008), reads the state from disk, and writes it back only when it
 * succeeded — a refused or interrupted operation leaves the state as it was (FR-004, FR-005).
 *
 * A peer's key is accepted only with a passport that passes [PassportCheck] (story 2); once
 * accepted it is remembered and the passport is not asked for again until the key changes.
 *
 * The key directory is reached through [KeyDirectory] ([KeyDirectoryClient]); [KeySync] keeps this
 * device's record there. The bridge is story 4.
 */
internal class SecretChats(
    /** Own account id: the libsignal address name. A user has exactly one device, so the device id is always 1. */
    private val me: String,
    dir: File,
    vault: Vault,
    private val directory: KeyDirectory,
    private val passports: PassportCheck,
    /** This device's passport for its identity key; throws [E2eeException] `NOT_ENROLLED` without a device certificate. */
    private val ownPassport: suspend (identityKey: ByteArray) -> Passport,
    /** A passport that failed a check: goes to the gateway through the alert channel (FR-017). */
    private val onBadPassport: (peer: String, fault: PassportFault) -> Unit = { _, _ -> },
    private val now: () -> Long = System::currentTimeMillis,
) {
    private val store = SecretStore(dir, vault)
    private val mutex = Mutex()
    private val self = SignalProtocolAddress(me, DEVICE)

    /** Encrypts [text] for [peer]; the first message to a peer (and the first after [resetSession]) takes their keys from the directory. */
    suspend fun encrypt(peer: String, text: String): String {
        if (peer == me) throw E2eeException(E2eeFailure.NO_DEVICE) // one device per user: nobody to encrypt to
        sealed(peer, text, fresh = null)?.let { return it }
        // the directory is asked outside the lock: a slow network must not hold up decryption
        val keys = directory.fetch(peer)
        return sealed(peer, text, keys)!!
    }

    /** Envelope, or null when there is no usable session and no [fresh] keys to build one from. */
    private suspend fun sealed(peer: String, text: String, fresh: PeerKeys?): String? = mutex.withLock {
        val account = store.account()
        val state = store.peer(account, peer)
        val signal = SignalStore(account, state, SignalProtocolAddress(peer, DEVICE))
        val at = Instant.ofEpochMilli(now())
        if (state.trust == PeerTrust.REVERIFY) throw E2eeException(E2eeFailure.REVERIFY)
        if (!signal.hasUsableSession(at)) {
            if (fresh == null) return@withLock null
            accept(state, peer, fresh.identityKey, fresh.passport)
            if (state.trust == PeerTrust.REVERIFY) {
                store.save(state) // the change must be seen by the web app, the message is not sent
                throw E2eeException(E2eeFailure.REVERIFY)
            }
            try {
                // trap: the builder takes (store, remote, local), the cipher (store, local, remote)
                SessionBuilder(signal, signal.remote, self).process(bundle(fresh), at)
            } catch (e: Exception) {
                throw E2eeException(E2eeFailure.BAD_PASSPORT, e) // a prekey not signed by the identity key it came with
            }
        }
        val message = try {
            SessionCipher(signal, self, signal.remote).encrypt(text.toByteArray(), at)
        } catch (e: Exception) {
            throw E2eeException(E2eeFailure.UNDECRYPTABLE, e)
        }
        // FR-013: until the peer answers, every message carries the passport — the peer checks it without the directory
        val passport = if (message.type == CiphertextMessage.PREKEY_TYPE) "." + B64.encodeToString(ownPassport(account.identity.publicKey.serialize()).encode()) else ""
        commit(account, state)
        ENVELOPE + message.type + "." + B64.encodeToString(message.serialize()) + passport
    }

    /**
     * Decides whether [identityKey] is [user]'s key (FR-012 – FR-015). A key accepted before is not
     * checked again; a new one needs a passport. Marks a change; a peer verified by safety number
     * goes to `REVERIFY`.
     */
    private fun accept(peer: Peer, user: String, identityKey: ByteArray, passport: Passport?, incoming: Boolean = false) {
        val known = peer.identity
        if (known != null && known.contentEquals(identityKey) && peer.trust != PeerTrust.UNVERIFIED) return
        if (passport == null) throw E2eeException(E2eeFailure.NO_PASSPORT)
        try {
            passports.verify(user, identityKey, passport)
        } catch (e: PassportRejected) {
            // a first message that waited on the server longer than its certificate lived is not an attack:
            // it is undecryptable and comes back through recovery with a fresh passport
            if (incoming && e.fault == PassportFault.EXPIRED) throw E2eeException(E2eeFailure.UNDECRYPTABLE, e)
            onBadPassport(user, e.fault)
            throw E2eeException(E2eeFailure.BAD_PASSPORT, e)
        }
        if (known != null && !known.contentEquals(identityKey)) {
            peer.changed = true
            if (peer.trust == PeerTrust.VERIFIED) peer.trust = PeerTrust.REVERIFY
        }
        if (peer.trust == PeerTrust.UNVERIFIED) peer.trust = PeerTrust.PASSPORT
        peer.identity = identityKey
        peer.dirty = true
    }

    /** Decrypts an envelope made by the peer's [encrypt]. A second decryption of the same envelope is `DUPLICATE`. */
    suspend fun decrypt(peer: String, envelope: String): String = mutex.withLock {
        val account = store.account()
        val state = store.peer(account, peer)
        val signal = SignalStore(account, state, SignalProtocolAddress(peer, DEVICE))
        val plain = try {
            if (!envelope.startsWith(ENVELOPE)) throw IllegalArgumentException("not an $ENVELOPE envelope")
            val parts = envelope.substring(ENVELOPE.length).split('.')
            val bytes = Base64.getUrlDecoder().decode(parts[1])
            val cipher = SessionCipher(signal, self, signal.remote)
            when (parts[0].toInt()) {
                CiphertextMessage.PREKEY_TYPE -> {
                    val message = PreKeySignalMessage(bytes)
                    val passport = parts.getOrNull(2)?.let { Passport.decode(Base64.getUrlDecoder().decode(it)) }
                    accept(state, peer, message.identityKey.serialize(), passport, incoming = true)
                    cipher.decrypt(message)
                }
                CiphertextMessage.WHISPER_TYPE -> cipher.decrypt(SignalMessage(bytes))
                else -> throw IllegalArgumentException("unknown message type")
            }
        } catch (e: E2eeException) {
            throw e // no_passport, bad_passport, undecryptable (expired passport)
        } catch (e: DuplicateMessageException) {
            throw E2eeException(E2eeFailure.DUPLICATE, e)
        } catch (e: Exception) {
            throw E2eeException(E2eeFailure.UNDECRYPTABLE, e)
        }
        commit(account, state)
        String(plain)
    }

    /**
     * Recovery (FR-009): sets the current session with [peer] aside. The next [encrypt] takes the
     * peer's keys from the directory and builds a new one; the old one still decrypts what the peer
     * sent with it. The remembered key of the peer is not touched.
     */
    suspend fun resetSession(peer: String): Unit = mutex.withLock {
        val account = store.account()
        val state = store.peer(account, peer)
        val record = state.session?.let(::SessionRecord) ?: return@withLock
        record.archiveCurrentState()
        state.session = record.serialize()
        store.save(state)
    }

    /** The peer's state for the web app; reading it takes the "key changed" mark off (FR-014). */
    suspend fun peerState(peer: String): Pair<PeerTrust, Boolean> = mutex.withLock {
        val state = store.peer(store.account(), peer)
        val changed = state.changed
        if (changed) {
            state.changed = false
            store.save(state)
        }
        state.trust to changed
    }

    /** 60 digits to compare with the peer (FR-016), or null while no key of the peer is accepted. */
    suspend fun safetyNumber(peer: String): String? = mutex.withLock {
        val account = store.account()
        val theirs = store.peer(account, peer).identity ?: return@withLock null
        NumericFingerprintGenerator(5200)
            .createFor(2, me.toByteArray(), account.identity.publicKey, peer.toByteArray(), IdentityKey(theirs))
            .displayableFingerprint.displayText
    }

    /** The user compared the safety number ([verified]) or drops the mark; both end `REVERIFY`. */
    suspend fun setVerified(peer: String, verified: Boolean): Unit = mutex.withLock {
        val state = store.peer(store.account(), peer)
        if (state.identity == null || state.trust == PeerTrust.UNVERIFIED) return@withLock
        state.trust = if (verified) PeerTrust.VERIFIED else PeerTrust.PASSPORT
        store.save(state)
    }

    /**
     * What to publish to the key directory: the identity key, the current signed and post-quantum
     * prekeys (made on first use) and [oneTime] new one-time prekeys. Public halves only.
     */
    suspend fun ownKeys(oneTime: Int): OwnKeys = mutex.withLock {
        val account = store.account()
        if (account.currentSignedId == 0) newSignedKeys(account)
        dropExpired(account)
        val made = List(oneTime) {
            val id = account.nextPreKeyId++
            val pair = ECKeyPair.generate()
            account.preKeys[id] = PreKeyRecord(id, pair).serialize()
            OneTimeKey(id, pair.publicKey.serialize())
        }
        store.save(account)
        val signed = SignedPreKeyRecord(account.signed.getValue(account.currentSignedId).record)
        val kyber = KyberPreKeyRecord(account.kyber.getValue(account.currentKyberId).record)
        OwnKeys(
            account.identity.publicKey.serialize(),
            account.registrationId,
            SignedKey(signed.id, signed.keyPair.publicKey.serialize(), signed.signature),
            SignedKey(kyber.id, kyber.keyPair.publicKey.serialize(), kyber.signature),
            made,
        )
    }

    /**
     * Replaces the signed and post-quantum prekeys when the current ones are older than [olderThanMs];
     * the replaced ones decrypt for 30 more days (FR-007). Returns whether they were replaced — the
     * caller then publishes [ownKeys].
     */
    suspend fun rotateSignedKeys(olderThanMs: Long = 0): Boolean = mutex.withLock {
        val account = store.account()
        val current = account.signed[account.currentSignedId] ?: return@withLock false // nothing published yet
        if (now() - SignedPreKeyRecord(current.record).timestamp < olderThanMs) return@withLock false
        newSignedKeys(account)
        dropExpired(account)
        store.save(account)
        true
    }

    /**
     * This installation's `deviceId` in the key directory. It changes with the identity key: the
     * directory never takes a one-time key id twice for one device, and a new account counts them from 1.
     */
    suspend fun directoryId(): String = mutex.withLock {
        val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(store.account().nameKey, "HmacSHA256")) }
        mac.doFinal("key-directory device".toByteArray()).take(16).joinToString("") { "%02x".format(it) }
    }

    /** Own identity key, public half (33 bytes): what the directory must hold for this account. */
    suspend fun identityKey(): ByteArray = mutex.withLock { store.account().identity.publicKey.serialize() }

    private fun newSignedKeys(account: Account) {
        val at = now()
        account.signed[account.currentSignedId]?.replacedAt = at
        account.kyber[account.currentKyberId]?.replacedAt = at
        val key = account.identity.privateKey
        val signed = ECKeyPair.generate()
        account.currentSignedId = account.nextSignedId++
        account.signed[account.currentSignedId] = KeptKey(
            SignedPreKeyRecord(account.currentSignedId, at, signed, key.calculateSignature(signed.publicKey.serialize())).serialize(),
        )
        val kyber = KEMKeyPair.generate(KEMKeyType.KYBER_1024)
        account.currentKyberId = account.nextKyberId++
        account.kyber[account.currentKyberId] = KeptKey(
            KyberPreKeyRecord(account.currentKyberId, at, kyber, key.calculateSignature(kyber.publicKey.serialize())).serialize(),
        )
    }

    private fun dropExpired(account: Account) {
        val limit = now() - KEEP_REPLACED_MS
        account.signed.values.removeIf { it.replacedAt in 1..limit }
        account.kyber.values.removeIf { it.replacedAt in 1..limit }
        account.usedBaseKeys.removeIf { it.kyberId !in account.kyber }
    }

    /** The peer file first: a crash in between leaves a session and an unspent prekey, which a repeat of the message tolerates. */
    private suspend fun commit(account: Account, peer: Peer) {
        if (peer.dirty) store.save(peer)
        if (account.dirty) store.save(account)
    }

    private fun bundle(k: PeerKeys): PreKeyBundle = PreKeyBundle(
        k.registrationId, DEVICE,
        k.oneTimePreKey?.id ?: PreKeyBundle.NULL_PRE_KEY_ID, k.oneTimePreKey?.let { ECPublicKey(it.publicKey) },
        k.signedPreKey.id, ECPublicKey(k.signedPreKey.publicKey), k.signedPreKey.signature,
        IdentityKey(k.identityKey),
        k.pqPreKey.id, KEMPublicKey(k.pqPreKey.publicKey), k.pqPreKey.signature,
    )

    /** libsignal's view of the state for one operation with one peer; marks what it changed. */
    private class SignalStore(private val account: Account, private val peer: Peer, val remote: SignalProtocolAddress) : SignalProtocolStore {
        fun hasUsableSession(at: Instant): Boolean = peer.session?.let { SessionRecord(it).hasSenderChain(at) } ?: false

        override fun getIdentityKeyPair(): IdentityKeyPair = account.identity
        override fun getLocalRegistrationId(): Int = account.registrationId

        override fun saveIdentity(address: SignalProtocolAddress, identityKey: IdentityKey): IdentityKeyStore.IdentityChange {
            val bytes = identityKey.serialize()
            val before = peer.identity
            if (before != null && before.contentEquals(bytes)) return IdentityKeyStore.IdentityChange.NEW_OR_UNCHANGED
            peer.identity = bytes
            peer.dirty = true
            return if (before == null) IdentityKeyStore.IdentityChange.NEW_OR_UNCHANGED else IdentityKeyStore.IdentityChange.REPLACED_EXISTING
        }

        /** Only the key [accept] let through: libsignal never takes a peer's key on its own. */
        override fun isTrustedIdentity(address: SignalProtocolAddress, identityKey: IdentityKey, direction: IdentityKeyStore.Direction): Boolean =
            address == remote && peer.trust != PeerTrust.UNVERIFIED && peer.identity?.contentEquals(identityKey.serialize()) == true

        override fun getIdentity(address: SignalProtocolAddress): IdentityKey? = peer.identity?.takeIf { address == remote }?.let(::IdentityKey)

        override fun loadSession(address: SignalProtocolAddress): SessionRecord? = peer.session?.takeIf { address == remote }?.let(::SessionRecord)

        override fun loadExistingSessions(addresses: List<SignalProtocolAddress>): List<SessionRecord> =
            addresses.map { loadSession(it) ?: throw NoSessionException(it, "no session") }

        override fun getSubDeviceSessions(name: String): List<Int> = emptyList()

        override fun storeSession(address: SignalProtocolAddress, record: SessionRecord) {
            check(address == remote) { "session of another peer" }
            peer.session = record.serialize()
            peer.dirty = true
        }

        override fun containsSession(address: SignalProtocolAddress): Boolean = address == remote && peer.session != null

        override fun deleteSession(address: SignalProtocolAddress) {
            if (address == remote && peer.session != null) {
                peer.session = null
                peer.dirty = true
            }
        }

        override fun deleteAllSessions(name: String) = deleteSession(SignalProtocolAddress(name, DEVICE))

        override fun loadPreKey(preKeyId: Int): PreKeyRecord = PreKeyRecord(account.preKeys[preKeyId] ?: throw InvalidKeyIdException("no one-time prekey"))

        override fun storePreKey(preKeyId: Int, record: PreKeyRecord) {
            account.preKeys[preKeyId] = record.serialize()
            account.dirty = true
        }

        override fun containsPreKey(preKeyId: Int): Boolean = preKeyId in account.preKeys

        override fun removePreKey(preKeyId: Int) {
            if (account.preKeys.remove(preKeyId) != null) account.dirty = true
        }

        override fun loadSignedPreKey(signedPreKeyId: Int): SignedPreKeyRecord =
            SignedPreKeyRecord(account.signed[signedPreKeyId]?.record ?: throw InvalidKeyIdException("no signed prekey"))

        override fun loadSignedPreKeys(): List<SignedPreKeyRecord> = account.signed.values.map { SignedPreKeyRecord(it.record) }

        override fun storeSignedPreKey(signedPreKeyId: Int, record: SignedPreKeyRecord) {
            account.signed[signedPreKeyId] = KeptKey(record.serialize())
            account.dirty = true
        }

        override fun containsSignedPreKey(signedPreKeyId: Int): Boolean = signedPreKeyId in account.signed

        override fun removeSignedPreKey(signedPreKeyId: Int) {
            if (account.signed.remove(signedPreKeyId) != null) account.dirty = true
        }

        override fun loadKyberPreKey(kyberPreKeyId: Int): KyberPreKeyRecord =
            KyberPreKeyRecord(account.kyber[kyberPreKeyId]?.record ?: throw InvalidKeyIdException("no post-quantum prekey"))

        override fun loadKyberPreKeys(): List<KyberPreKeyRecord> = account.kyber.values.map { KyberPreKeyRecord(it.record) }

        override fun storeKyberPreKey(kyberPreKeyId: Int, record: KyberPreKeyRecord) {
            account.kyber[kyberPreKeyId] = KeptKey(record.serialize())
            account.dirty = true
        }

        override fun containsKyberPreKey(kyberPreKeyId: Int): Boolean = kyberPreKeyId in account.kyber

        /** The post-quantum prekey is multi-use, so it stays; the same first message a second time is refused. */
        override fun markKyberPreKeyUsed(kyberPreKeyId: Int, signedPreKeyId: Int, baseKey: ECPublicKey) {
            val used = UsedBaseKey(kyberPreKeyId, signedPreKeyId, Base64.getEncoder().encodeToString(baseKey.serialize()))
            if (!account.usedBaseKeys.add(used)) throw ReusedBaseKeyException("first message replayed")
            account.dirty = true
        }

        // no group chats: a secret chat is two people
        override fun storeSenderKey(sender: SignalProtocolAddress, distributionId: UUID, record: SenderKeyRecord) = Unit
        override fun loadSenderKey(sender: SignalProtocolAddress, distributionId: UUID): SenderKeyRecord? = null
    }

    internal companion object {
        /** FR-031. The older `E2EE1:` envelope of the web app is not read. */
        const val ENVELOPE = "E2EE2:"
        private val B64 = Base64.getUrlEncoder().withoutPadding()
        private const val DEVICE = 1
        private const val KEEP_REPLACED_MS = 30L * 24 * 60 * 60 * 1000
    }
}
