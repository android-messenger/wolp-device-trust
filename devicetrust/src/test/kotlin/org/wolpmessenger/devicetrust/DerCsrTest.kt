package org.wolpmessenger.devicetrust

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.wolpmessenger.devicetrust.asn1.Csr
import org.wolpmessenger.devicetrust.asn1.Der
import java.io.File
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.concurrent.TimeUnit

class DerCsrTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    @Test
    fun `DER primitives`() {
        assertEquals("7f", hex(Der.length(127)))
        assertEquals("8180", hex(Der.length(128)))
        assertEquals("820100", hex(Der.length(256)))
        assertEquals("020100", hex(Der.integer(0)))
        assertEquals("02020080", hex(Der.integer(128)))
        assertEquals("06082a8648ce3d040302", hex(Der.oid(Csr.OID_ECDSA_WITH_SHA256)))
        assertEquals("060a2b06010401d679020111", hex(Der.oid("1.3.6.1.4.1.11129.2.1.17")))
        assertEquals("3000", hex(Der.sequence()))
        assertEquals("a000", hex(Der.contextConstructed(0)))
        assertEquals("030200ff", hex(Der.bitString(byteArrayOf(-1))))
    }

    private fun keyPair() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    @Test
    fun `CSR structure and signature verify independently of OpenSSL`() {
        val kp = keyPair()
        val csr = Csr.build(kp.public, kp.private)
        val outer = Tlv.read(csr, 0)
        assertEquals(0x30, outer.tag)
        assertEquals(csr.size, outer.end)
        val info = Tlv.read(csr, outer.contentStart)
        val alg = Tlv.read(csr, info.end)
        val sig = Tlv.read(csr, alg.end)
        assertEquals(outer.end, sig.end)
        assertArrayEquals(Der.sequence(Der.oid(Csr.OID_ECDSA_WITH_SHA256)), csr.copyOfRange(alg.start, alg.end))
        assertEquals(0x03, sig.tag)
        assertEquals("no unused bits", 0, csr[sig.contentStart].toInt())

        // info = SEQUENCE { INTEGER 0, SEQUENCE {} (empty subject), SPKI, [0] {} }
        val version = Tlv.read(csr, info.contentStart)
        val subject = Tlv.read(csr, version.end)
        val spki = Tlv.read(csr, subject.end)
        val attrs = Tlv.read(csr, spki.end)
        assertEquals("020100", hex(csr.copyOfRange(version.start, version.end)))
        assertEquals("3000", hex(csr.copyOfRange(subject.start, subject.end)))
        assertArrayEquals(kp.public.encoded, csr.copyOfRange(spki.start, spki.end))
        assertEquals("a000", hex(csr.copyOfRange(attrs.start, attrs.end)))
        assertEquals(info.end, attrs.end)

        val ok = Signature.getInstance("SHA256withECDSA").run {
            initVerify(kp.public)
            update(csr, info.start, info.end - info.start)
            verify(csr.copyOfRange(sig.contentStart + 1, sig.end))
        }
        assertTrue(ok)
    }

    /** Minimal DER TLV reader for the assertions. */
    private data class Tlv(val tag: Int, val start: Int, val contentStart: Int, val end: Int) {
        companion object {
            fun read(b: ByteArray, off: Int): Tlv {
                val first = b[off + 1].toInt() and 0xFF
                var len = first
                var hdr = 2
                if (first >= 0x80) {
                    val n = first and 0x7F
                    len = 0
                    for (i in 0 until n) len = (len shl 8) or (b[off + 2 + i].toInt() and 0xFF)
                    hdr += n
                }
                return Tlv(b[off].toInt() and 0xFF, off, off + hdr, off + hdr + len)
            }
        }
    }

    @Test
    fun `OpenSSL accepts the CSR, sees an empty subject and the same public key`() {
        assumeTrue("openssl not installed", runCatching { run("openssl", "version") }.isSuccess)
        val kp = keyPair()
        val der = File(tmp.root, "req.der").apply { writeBytes(Csr.build(kp.public, kp.private)) }
        val verify = run("openssl", "req", "-inform", "DER", "-in", der.path, "-verify", "-noout", "-subject")
        assertTrue(verify, verify.contains("verify OK"))
        assertTrue(verify, verify.lines().any { it.trim() == "subject=" })
        val pem = run("openssl", "req", "-inform", "DER", "-in", der.path, "-pubkey", "-noout")
        val b64 = pem.lines().filter { it.isNotBlank() && !it.startsWith("-----") }.joinToString("")
        assertArrayEquals(kp.public.encoded, Base64.getDecoder().decode(b64))
    }

    private fun run(vararg cmd: String): String {
        val p = ProcessBuilder(*cmd).redirectErrorStream(true).start()
        val out = p.inputStream.bufferedReader().readText()
        check(p.waitFor(30, TimeUnit.SECONDS) && p.exitValue() == 0) { "${cmd.joinToString(" ")} failed: $out" }
        return out
    }
}
