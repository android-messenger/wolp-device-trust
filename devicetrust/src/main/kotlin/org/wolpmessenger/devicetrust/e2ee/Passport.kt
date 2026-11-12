package org.wolpmessenger.devicetrust.e2ee

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.CertPathValidator
import java.security.cert.CertificateFactory
import java.security.cert.PKIXCertPathValidatorResult
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.time.Duration
import java.time.Instant
import java.util.Date

/**
 * Proof that an identity key belongs to an enrolled device of a user (specs/002, FR-010, FR-011):
 * the device key's signature over [signedBytes] and the device certificate with its intermediates,
 * the device certificate first.
 */
internal class Passport(val signature: ByteArray, val certificates: List<ByteArray>) {
    /** `len16(signature) ‖ count ‖ (len16(certificate))*` — the third part of the first message's envelope. */
    fun encode(): ByteArray = ByteArrayOutputStream().apply {
        len16(signature)
        write(certificates.size)
        certificates.forEach { len16(it) }
    }.toByteArray()

    companion object {
        private const val LABEL = "wolp-e2ee-passport-v1"
        const val MAX_CERTIFICATES = 4

        /**
         * What the device key signs (ECDSA P-256, SHA-256):
         * `"wolp-e2ee-passport-v1" ‖ len16(user) ‖ user ‖ len16(deviceId) ‖ deviceId ‖ len16(identityKey) ‖ identityKey`,
         * lengths big-endian, strings UTF-8, [identityKey] as libsignal serializes it (33 bytes).
         * The label has no length before it, as in the renewal signature.
         */
        fun signedBytes(user: String, deviceId: String, identityKey: ByteArray): ByteArray = ByteArrayOutputStream().apply {
            write(LABEL.toByteArray(Charsets.US_ASCII))
            len16(user.toByteArray())
            len16(deviceId.toByteArray())
            len16(identityKey)
        }.toByteArray()

        /** This device's passport; [deviceKey] is the key of the device certificate [chain]`[0]`. */
        fun sign(deviceKey: PrivateKey, user: String, deviceId: String, identityKey: ByteArray, chain: List<X509Certificate>): Passport {
            val sig = Signature.getInstance("SHA256withECDSA").run {
                initSign(deviceKey)
                update(signedBytes(user, deviceId, identityKey))
                sign()
            }
            return Passport(sig, chain.map { it.encoded })
        }

        /** Throws on anything that is not exactly an [encode]d passport. */
        fun decode(bytes: ByteArray): Passport {
            val d = DataInputStream(ByteArrayInputStream(bytes))
            fun blob() = ByteArray(d.readUnsignedShort()).also(d::readFully)
            val signature = blob()
            val count = d.readUnsignedByte()
            require(count in 1..MAX_CERTIFICATES) { "certificate count" }
            val certificates = List(count) { blob() }
            require(d.available() == 0) { "trailing bytes" }
            return Passport(signature, certificates)
        }

        private fun ByteArrayOutputStream.len16(b: ByteArray) {
            require(b.size <= 0xFFFF)
            write(b.size ushr 8)
            write(b.size and 0xFF)
            write(b)
        }
    }
}

/** Which of the five checks failed (F3 §3.2); goes into the alert, never to the web app. */
internal enum class PassportFault { MALFORMED, CHAIN, ISSUER, NOT_DEVICE, USER, EXPIRED, SIGNATURE }

internal class PassportRejected(val fault: PassportFault, cause: Throwable? = null) : Exception(fault.name, cause)

/**
 * What a build trusts: the root certificates of its contour and the certificate authorities
 * allowed to issue device certificates, by SHA-256 of their public key (SPKI), lowercase hex.
 * Baked into the build; a production build carries no test root (FR-012).
 */
internal class PassportTrust(val roots: List<X509Certificate>, issuers: Collection<String>) {
    val issuers: Set<String> = issuers.map { it.lowercase() }.toSet()
}

/** The receiving phone's check of a passport: five checks of F3 §3.2, no network. */
internal class PassportCheck(private val trust: PassportTrust, private val now: () -> Instant) {
    /** Returns normally when [identityKey] belongs to an enrolled device of [user]; throws [PassportRejected]. */
    fun verify(user: String, identityKey: ByteArray, passport: Passport) {
        val factory = CertificateFactory.getInstance("X.509")
        val chain = try {
            require(passport.certificates.size in 1..Passport.MAX_CERTIFICATES)
            passport.certificates.map { factory.generateCertificate(ByteArrayInputStream(it)) as X509Certificate }
        } catch (e: Exception) {
            throw PassportRejected(PassportFault.MALFORMED, e)
        }
        val device = chain[0]

        // 4. valid now, or expired no more than 7 days ago: a phone that was off keeps its key
        val at = now()
        val notAfter = device.notAfter.toInstant()
        if (at.isBefore(device.notBefore.toInstant()) || at.isAfter(notAfter.plus(GRACE))) throw PassportRejected(PassportFault.EXPIRED)

        // 1. issued by our authority…
        val issuerKey = try {
            val params = PKIXParameters(trust.roots.map { TrustAnchor(it, null) }.toSet()).apply {
                isRevocationEnabled = false
                date = Date.from(if (at.isAfter(notAfter)) notAfter else at)
            }
            val path = factory.generateCertPath(chain.filter { c -> trust.roots.none { it == c } })
            val result = CertPathValidator.getInstance("PKIX").validate(path, params) as PKIXCertPathValidatorResult
            if (path.certificates.size > 1) (path.certificates[1] as X509Certificate).publicKey else result.trustAnchor.trustedCert.publicKey
        } catch (e: Exception) {
            throw PassportRejected(PassportFault.CHAIN, e)
        }
        // …and by an authority allowed to issue device certificates
        val spki = MessageDigest.getInstance("SHA-256").digest(issuerKey.encoded).joinToString("") { "%02x".format(it) }
        if (spki !in trust.issuers) throw PassportRejected(PassportFault.ISSUER)

        // 2. a device certificate, not a CA and not a certificate of ours for another purpose
        val uris = try {
            device.subjectAlternativeNames.orEmpty().filter { it[0] == SAN_URI }.map { it[1] as String }
        } catch (e: Exception) {
            throw PassportRejected(PassportFault.NOT_DEVICE, e)
        }
        val deviceId = uris.filter { it.startsWith(DEVICE_URN) }.singleOrNull()?.removePrefix(DEVICE_URN)
        val owner = uris.filter { it.startsWith(USER_URN) }.singleOrNull()?.removePrefix(USER_URN)
        val clientAuth = runCatching { device.extendedKeyUsage }.getOrNull()?.contains(CLIENT_AUTH) == true
        if (device.basicConstraints != -1 || !clientAuth || deviceId.isNullOrEmpty() || owner.isNullOrEmpty()) throw PassportRejected(PassportFault.NOT_DEVICE)

        // 3. issued to the account we are talking to
        if (owner != user) throw PassportRejected(PassportFault.USER)

        // 5. the device key signed exactly this identity key for this account and device
        val signed = try {
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(device.publicKey)
                update(Passport.signedBytes(user, deviceId, identityKey))
                verify(passport.signature)
            }
        } catch (e: Exception) {
            false
        }
        if (!signed) throw PassportRejected(PassportFault.SIGNATURE)
    }

    private companion object {
        val GRACE: Duration = Duration.ofDays(7)
        const val SAN_URI = 6
        const val DEVICE_URN = "urn:wolp:device:"
        const val USER_URN = "urn:wolp:user:"
        const val CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
    }
}
