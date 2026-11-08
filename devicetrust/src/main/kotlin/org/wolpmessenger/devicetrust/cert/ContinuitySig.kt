package org.wolpmessenger.devicetrust.cert

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.MessageDigest

/**
 * Bytes signed by the **current** device key when moving to a new key (S3 §5.4, §5.6):
 * ```
 * prefix ‖ len16(deviceId) ‖ deviceId(UTF-8) ‖ len16(serial) ‖ serial(big-endian, unsigned)
 *   ‖ nonce(32) ‖ SHA-256(SPKI of the new key) ‖ SHA-256(attestationChain[0] ‖ … ‖ [n])
 * ```
 * Shared vectors with the gateway: `testvectors/continuity/continuity-v1.json`.
 */
internal object ContinuitySig {
    const val RENEW = "wolp-renew-v1"
    const val REATTEST = "wolp-reattest-v1"

    fun payload(prefix: String, deviceId: String, certSerial: BigInteger, nonce: ByteArray, newSpki: ByteArray, newChain: List<ByteArray>): ByteArray {
        require(nonce.size == 32) { "nonce must be 32 bytes" }
        val out = ByteArrayOutputStream()
        out.write(prefix.toByteArray(Charsets.US_ASCII))
        out.len16(deviceId.toByteArray(Charsets.UTF_8))
        out.len16(unsignedBigEndian(certSerial))
        out.write(nonce)
        out.write(sha256(newSpki))
        out.write(MessageDigest.getInstance("SHA-256").apply { newChain.forEach(::update) }.digest())
        return out.toByteArray()
    }

    /** Magnitude without the two's-complement sign byte (`BigInteger.toByteArray` adds one when the high bit is set). */
    fun unsignedBigEndian(n: BigInteger): ByteArray {
        require(n.signum() >= 0)
        val b = n.toByteArray()
        return if (b.size > 1 && b[0] == 0.toByte()) b.copyOfRange(1, b.size) else b
    }

    private fun ByteArrayOutputStream.len16(b: ByteArray) {
        require(b.size <= 0xFFFF)
        write(b.size ushr 8); write(b.size and 0xFF); write(b)
    }

    private fun sha256(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b)
}
