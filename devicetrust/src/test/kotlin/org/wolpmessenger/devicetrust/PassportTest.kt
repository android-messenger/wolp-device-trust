package org.wolpmessenger.devicetrust

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.fail
import org.junit.Test
import org.wolpmessenger.devicetrust.e2ee.Passport
import org.wolpmessenger.devicetrust.e2ee.PassportCheck
import org.wolpmessenger.devicetrust.e2ee.PassportFault
import org.wolpmessenger.devicetrust.e2ee.PassportRejected
import org.wolpmessenger.devicetrust.e2ee.PassportTrust
import java.security.cert.X509Certificate
import java.time.Instant

/** specs/002, story 2: one test per row of the table of checks in F3 §3.2. */
class PassportTest {
    private val now = Instant.ofEpochMilli(1_800_000_000_000L)
    private val ca = TestCa(at = now)
    private val key = TestCa.ecKey()
    private val identity = ByteArray(33) { (it + 5).toByte() }
    private val user = "6c926576-0000-4000-8000-000000000001"
    private val device = "01JCZ8K3W9D5V7H2Q4N6M8P0RT"

    private fun passport(cert: X509Certificate = ca.device(user, device, key), chain: List<X509Certificate> = listOf(cert, ca.issuer)) =
        Passport.sign(key.private, user, device, identity, chain)

    private fun check(p: Passport, trust: PassportTrust = ca.trust, at: Instant = now, who: String = user, id: ByteArray = identity) =
        PassportCheck(trust) { at }.verify(who, id, p)

    private fun rejected(fault: PassportFault, block: () -> Unit) {
        try {
            block()
            fail("expected $fault")
        } catch (e: PassportRejected) {
            assertEquals(fault, e.fault)
        }
    }

    @Test
    fun `a good passport passes, with the root in the chain or without the intermediate's sibling`() {
        check(passport())
        val cert = ca.device(user, device, key)
        check(passport(cert, listOf(cert, ca.issuer, ca.root)))
    }

    @Test
    fun `1 - a certificate of another authority`() {
        val other = TestCa("other", now)
        rejected(PassportFault.CHAIN) { check(passport(other.device(user, device, key), listOf(other.device(user, device, key), other.issuer))) }
        // a self-made chain that only names our issuer
        rejected(PassportFault.CHAIN) { check(passport(other.device(user, device, key), listOf(other.device(user, device, key), ca.issuer))) }
        // the device certificate alone: the intermediate is not baked in
        rejected(PassportFault.CHAIN) { check(passport(chain = listOf(ca.device(user, device, key)))) }
    }

    @Test
    fun `1 - our root, but the issuer is not in the list`() {
        val trust = PassportTrust(listOf(ca.root), listOf("00".repeat(32)))
        rejected(PassportFault.ISSUER) { check(passport(), trust) }
        // the list is compared without regard to case
        check(passport(), PassportTrust(listOf(ca.root), listOf(TestCa.spkiSha256(ca.issuer).uppercase())))
    }

    @Test
    fun `2 - not a device certificate`() {
        rejected(PassportFault.NOT_DEVICE) { check(passport(ca.device(user, device, key, clientAuth = false))) }
        rejected(PassportFault.NOT_DEVICE) { check(passport(ca.device(user, device, key, ca = true))) }
        rejected(PassportFault.NOT_DEVICE) { check(passport(ca.device(user, device, key, names = listOf("urn:wolp:user:$user")))) }
        rejected(PassportFault.NOT_DEVICE) { check(passport(ca.device(user, device, key, names = listOf("urn:wolp:device:$device")))) }
        rejected(PassportFault.NOT_DEVICE) { check(passport(ca.device(user, device, key, names = emptyList()))) }
        rejected(PassportFault.NOT_DEVICE) {
            check(passport(ca.device(user, device, key, names = listOf("urn:wolp:device:$device", "urn:wolp:user:$user", "urn:wolp:user:someone-else"))))
        }
    }

    @Test
    fun `3 - a real certificate of another account`() {
        rejected(PassportFault.USER) { check(passport(), who = "someone-else") }
    }

    @Test
    fun `4 - validity with 7 days of grace`() {
        val cert = ca.device(user, device, key) // valid for a day
        check(passport(cert), at = now.plusSeconds(6 * 86400))
        check(passport(cert), at = now.plusSeconds(8 * 86400 - 60))
        rejected(PassportFault.EXPIRED) { check(passport(cert), at = now.plusSeconds(8 * 86400 + 60)) }
        rejected(PassportFault.EXPIRED) { check(passport(cert), at = now.minusSeconds(3600)) }
    }

    @Test
    fun `5 - the signature does not match`() {
        rejected(PassportFault.SIGNATURE) { check(passport(), id = ByteArray(33) { 1 }) }
        val cert = ca.device(user, device, key)
        val chain = listOf(cert, ca.issuer)
        rejected(PassportFault.SIGNATURE) { check(Passport.sign(TestCa.ecKey().private, user, device, identity, chain)) }
        rejected(PassportFault.SIGNATURE) { check(Passport.sign(key.private, user, "01JCZ8K3W9D5V7H2Q4N6M8P0RX", identity, chain)) }
        rejected(PassportFault.SIGNATURE) { check(Passport.sign(key.private, "someone-else", device, identity, chain)) }
        rejected(PassportFault.SIGNATURE) { check(Passport(ByteArray(0), chain.map { it.encoded })) }
    }

    @Test
    fun `garbage instead of certificates`() {
        rejected(PassportFault.MALFORMED) { check(Passport(ByteArray(70), listOf(ByteArray(40)))) }
        rejected(PassportFault.MALFORMED) { check(Passport(ByteArray(70), emptyList())) }
        rejected(PassportFault.MALFORMED) { check(Passport(ByteArray(70), List(5) { ca.issuer.encoded })) }
    }

    @Test
    fun `the signed structure, byte for byte`() {
        val bytes = Passport.signedBytes("ab", "D1", byteArrayOf(5, 6, 7))
        val expected = "wolp-e2ee-passport-v1".toByteArray() + byteArrayOf(0, 2, 'a'.code.toByte(), 'b'.code.toByte(), 0, 2, 'D'.code.toByte(), '1'.code.toByte(), 0, 3, 5, 6, 7)
        assertArrayEquals(expected, bytes)
    }

    @Test
    fun `encoding round trip and garbage`() {
        val p = passport()
        val back = Passport.decode(p.encode())
        assertArrayEquals(p.signature, back.signature)
        assertEquals(p.certificates.map { it.toList() }, back.certificates.map { it.toList() })
        check(back)
        for (bad in listOf(ByteArray(0), byteArrayOf(0, 1, 9, 0), byteArrayOf(0, 1, 9, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0), p.encode() + 1, p.encode().dropLast(1).toByteArray())) {
            assertThrows(Exception::class.java) { Passport.decode(bad) }
        }
    }
}
