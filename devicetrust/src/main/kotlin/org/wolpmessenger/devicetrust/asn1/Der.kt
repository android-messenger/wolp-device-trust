package org.wolpmessenger.devicetrust.asn1

import java.io.ByteArrayOutputStream

/**
 * Minimal DER encoder — exactly what a PKCS#10 request needs (S2 §6.2: no BouncyCastle).
 * Every function returns a complete TLV.
 */
internal object Der {
    private const val INTEGER = 0x02
    private const val BIT_STRING = 0x03
    private const val OID = 0x06
    private const val SEQUENCE = 0x30
    private const val SET = 0x31

    fun sequence(vararg items: ByteArray): ByteArray = tlv(SEQUENCE, concat(*items))
    fun set(vararg items: ByteArray): ByteArray = tlv(SET, concat(*items))

    /** `[n] IMPLICIT` constructed (e.g. `[0]` attributes of CertificationRequestInfo). */
    fun contextConstructed(n: Int, vararg items: ByteArray): ByteArray {
        require(n in 0..30)
        return tlv(0xA0 or n, concat(*items))
    }

    /** Non-negative INTEGER from a small value. */
    fun integer(value: Long): ByteArray {
        require(value >= 0)
        var bytes = java.math.BigInteger.valueOf(value).toByteArray() // two's complement, minimal, sign byte if needed
        if (bytes.isEmpty()) bytes = byteArrayOf(0)
        return tlv(INTEGER, bytes)
    }

    /** BIT STRING with no unused bits. */
    fun bitString(content: ByteArray): ByteArray = tlv(BIT_STRING, byteArrayOf(0) + content)

    fun oid(dotted: String): ByteArray {
        val arcs = dotted.split('.').map { it.toLong() }
        require(arcs.size >= 2 && arcs[0] in 0..2 && (arcs[0] == 2L || arcs[1] < 40)) { "bad OID $dotted" }
        val out = ByteArrayOutputStream()
        base128(arcs[0] * 40 + arcs[1], out)
        for (arc in arcs.drop(2)) base128(arc, out)
        return tlv(OID, out.toByteArray())
    }

    fun tlv(tag: Int, content: ByteArray): ByteArray = byteArrayOf(tag.toByte()) + length(content.size) + content

    internal fun length(n: Int): ByteArray {
        require(n >= 0)
        if (n < 0x80) return byteArrayOf(n.toByte())
        val bytes = generateSequence(n) { it ushr 8 }.takeWhile { it > 0 }.map { (it and 0xFF).toByte() }.toList().reversed()
        return byteArrayOf((0x80 or bytes.size).toByte()) + bytes.toByteArray()
    }

    private fun base128(value: Long, out: ByteArrayOutputStream) {
        val groups = ArrayList<Int>()
        var v = value
        do {
            groups += (v and 0x7F).toInt()
            v = v ushr 7
        } while (v > 0)
        for (i in groups.indices.reversed()) out.write(if (i > 0) groups[i] or 0x80 else groups[i])
    }

    private fun concat(vararg parts: ByteArray): ByteArray {
        val out = ByteArrayOutputStream(parts.sumOf { it.size })
        parts.forEach(out::write)
        return out.toByteArray()
    }
}
