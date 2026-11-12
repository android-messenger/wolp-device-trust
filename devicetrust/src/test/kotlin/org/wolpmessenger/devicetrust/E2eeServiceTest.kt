package org.wolpmessenger.devicetrust

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.wolpmessenger.devicetrust.alert.AlertKind
import org.wolpmessenger.devicetrust.alert.AlertSink
import org.wolpmessenger.devicetrust.api.E2eeException
import org.wolpmessenger.devicetrust.api.E2eeFailure
import org.wolpmessenger.devicetrust.api.E2eePeerTrust
import org.wolpmessenger.devicetrust.api.RaspFinding
import org.wolpmessenger.devicetrust.e2ee.E2eeService
import org.wolpmessenger.devicetrust.e2ee.KeySync
import org.wolpmessenger.devicetrust.e2ee.PassportCheck
import org.wolpmessenger.devicetrust.e2ee.Passport
import org.wolpmessenger.devicetrust.keys.KeystoreKeys
import org.wolpmessenger.devicetrust.store.ActiveCert
import org.wolpmessenger.devicetrust.store.Phase
import org.wolpmessenger.devicetrust.store.StoredState
import org.wolpmessenger.devicetrust.store.TrustStore
import org.wolpmessenger.devicetrust.vault.EnvelopeVault
import org.wolpmessenger.devicetrust.vault.UnlockState
import java.io.File
import java.security.KeyPair
import java.time.Instant

/**
 * specs/002, story 3: the library keeps its own record in the key directory, signs its passport with
 * the device key and reports what does not add up. Whole phones — store, Keystore, Vault, protocol —
 * against a stand-in directory.
 */
class E2eeServiceTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private var clock = 1_800_000_000_000L
    private var uptime = 0L
    private val hour = 60L * 60 * 1000
    private val day = 24 * hour
    private val ca = TestCa()
    private val directory = FakeDirectory()

    private class Reports : AlertSink {
        val findings = ArrayList<RaspFinding>()
        override fun enqueue(kind: AlertKind, checks: List<RaspFinding>) = false
        override fun report(findings: List<RaspFinding>) {
            this.findings += findings
        }
        override fun schedule() = Unit
    }

    /** One enrolled phone: device key in the (fake) Keystore, certificate from the test authority in the store. */
    private inner class Phone(val user: String, val deviceId: String = "01JCZ8K3W9D5V7H2Q4N6M8P0RT", val dir: File = tmp.newFolder()) {
        var unlocked = true
        val backend = FakeBackend()
        val keystore = KeystoreKeys(backend)
        val store = TrustStore(File(dir, "dt"))
        val kek = SoftKek()
        var vault = EnvelopeVault(kek, File(dir, "dek.bin"), UnlockState { unlocked })
        val reports = Reports()
        var serial = 0

        /** A new process over the same files. */
        fun start() = E2eeService(File(dir, "dt/e2ee"), vault, store, keystore, ca.trust, directory.of(user), reports, { Instant.ofEpochMilli(clock) }) { uptime }
        var e2ee = start()

        /** Enrollment or renewal: a new device key and a certificate for it. */
        fun certificate(owner: String = user) {
            val n = ++serial
            val alias = "${KeystoreKeys.DEVICE_PREFIX}$n"
            backend.generateSigningKey(alias, null, false)
            val pair = backend.pairs.getValue(alias)
            val at = Instant.ofEpochMilli(clock)
            val leaf = ca.device(owner, deviceId, KeyPair(pair.public, pair.private), notBefore = at.minusSeconds(300), notAfter = at.plusSeconds(24 * 3600))
            store.writeChain(n, listOf(leaf, ca.issuer))
            store.save(StoredState(Phase.ENROLLED, deviceId, ActiveCert(alias, leaf.serialNumber.toString(16), at, at.plusSeconds(24 * 3600), at.plusSeconds(16 * 3600))))
        }

        suspend fun enroll(): Phone {
            certificate()
            vault.provision()
            assertTrue(e2ee.sync())
            return this
        }

        val record get() = directory.records.getValue(user)
    }

    private suspend fun refused(expected: E2eeFailure, block: suspend () -> Unit) {
        try {
            block()
            fail("expected $expected")
        } catch (e: E2eeException) {
            assertEquals(expected, e.failure)
        }
    }

    @Test
    fun `s3-1 - an enrolled phone publishes its keys with a passport signed by the device key`() = runTest {
        val alice = Phone("alice").enroll()

        val r = alice.record
        assertEquals(KeySync.FULL, r.oneTime.size)
        assertEquals(33, r.keys.identityKey.size)
        assertEquals(1569, r.keys.pqPreKey.publicKey.size)
        assertTrue(r.keys.registrationId in 1..16380)
        // what a peer does with it: the five checks, against the build's root and issuer
        PassportCheck(ca.trust) { Instant.ofEpochMilli(clock) }.verify("alice", r.keys.identityKey, r.passport!!)
        assertEquals("the device certificate and its issuer, no root", 2, r.passport!!.certificates.size)
        assertTrue(alice.reports.findings.isEmpty())
    }

    @Test
    fun `two phones talk through the public operations`() = runTest {
        val alice = Phone("alice", "01ALICE").enroll()
        val bob = Phone("bob", "01BOB").enroll()

        val first = alice.e2ee.encrypt("bob", "привет")
        assertEquals("привет", bob.e2ee.decrypt("alice", first))
        assertEquals("ответ", alice.e2ee.decrypt("bob", bob.e2ee.encrypt("alice", "ответ")))

        assertEquals(E2eePeerTrust.PASSPORT, alice.e2ee.peerState("bob").trust)
        assertFalse(alice.e2ee.peerState("bob").keyChanged)
        assertEquals(60, alice.e2ee.safetyNumber("bob")!!.filter(Char::isDigit).length)
        assertEquals(alice.e2ee.safetyNumber("bob"), bob.e2ee.safetyNumber("alice"))
        alice.e2ee.setVerified("bob", true)
        assertEquals(E2eePeerTrust.VERIFIED, alice.e2ee.peerState("bob").trust)

        alice.e2ee.resetSession("bob")
        assertEquals("again", bob.e2ee.decrypt("alice", alice.e2ee.encrypt("bob", "again")))
        assertEquals("one fetch for the first message, one after the reset", 2, directory.fetches)
        assertEquals(KeySync.FULL - 2, bob.record.oneTime.size)
    }

    @Test
    fun `s3-2 - a renewed certificate puts a new passport into the directory, the identity key stays`() = runTest {
        val alice = Phone("alice").enroll()
        val before = alice.record.passport!!
        val identity = alice.record.keys.identityKey

        uptime += 5 * 60 * 1000
        assertTrue("nothing to do: same certificate, checked a moment ago", alice.e2ee.syncIfDue())
        assertEquals(1, alice.record.publications)

        alice.certificate()
        assertTrue(alice.e2ee.syncIfDue())
        assertEquals(2, alice.record.publications)
        assertFalse(before.certificates.first().contentEquals(alice.record.passport!!.certificates.first()))
        assertArrayEquals(identity, alice.record.keys.identityKey)
        PassportCheck(ca.trust) { Instant.ofEpochMilli(clock) }.verify("alice", identity, alice.record.passport!!)
        assertEquals("the one-time keys already there are not published again", KeySync.FULL, alice.record.oneTime.size)
    }

    @Test
    fun `s3-3 - one-time keys below the threshold are topped up`() = runTest {
        val alice = Phone("alice").enroll()
        repeat(KeySync.FULL - KeySync.LOW) { alice.record.oneTime.removeFirst() }
        uptime += 2 * hour
        assertTrue(alice.e2ee.syncIfDue())
        assertEquals("exactly at the threshold nothing is sent", 0, directory.replenishments)

        alice.record.oneTime.removeFirst()
        uptime += 2 * hour
        assertTrue(alice.e2ee.syncIfDue())
        assertEquals(1, directory.replenishments)
        assertEquals(KeySync.FULL, alice.record.oneTime.size)
        assertEquals("a top-up is not a publication", 1, alice.record.publications)

        // every key handed out is one the phone can still use
        val bob = Phone("bob", "01BOB").enroll()
        repeat(3) { bob.e2ee.resetSession("alice"); assertEquals("m$it", alice.e2ee.decrypt("bob", bob.e2ee.encrypt("alice", "m$it"))) }
    }

    @Test
    fun `s3-4 - another key in the own record is reported and replaced`() = runTest {
        val alice = Phone("alice").enroll()
        val intruder = Phone("alice", "01INTRUDER").enroll() // whoever can write to the directory
        val foreign = alice.record.keys.identityKey
        assertTrue("a first publication over somebody's record is not an incident", intruder.reports.findings.isEmpty())

        uptime += 2 * hour
        assertTrue(alice.e2ee.syncIfDue())
        assertEquals(listOf(E2eeService.FOREIGN_KEY), alice.reports.findings.map { it.id })
        assertFalse("the phone's own key is back", foreign.contentEquals(alice.record.keys.identityKey))
        assertEquals(KeySync.FULL, alice.record.oneTime.size)
    }

    @Test
    fun `s3-5 - without the directory an open session goes on, a new one is no_network`() = runTest {
        val alice = Phone("alice", "01ALICE").enroll()
        val bob = Phone("bob", "01BOB").enroll()
        Phone("carol", "01CAROL").enroll()
        assertEquals("one", bob.e2ee.decrypt("alice", alice.e2ee.encrypt("bob", "one")))

        directory.online = false
        assertEquals("two", bob.e2ee.decrypt("alice", alice.e2ee.encrypt("bob", "two")))
        refused(E2eeFailure.NO_NETWORK) { alice.e2ee.encrypt("carol", "x") }
        uptime += 2 * hour
        assertFalse("a failed pass is repeated later", alice.e2ee.syncIfDue())

        directory.online = true
        assertTrue(alice.e2ee.syncIfDue())
        assertEquals(1, alice.record.publications)
    }

    @Test
    fun `the signed and the post-quantum key are replaced every two days`() = runTest {
        val alice = Phone("alice", "01ALICE").enroll()
        val bob = Phone("bob", "01BOB").enroll()
        val v1 = alice.record.keys
        val early = bob.e2ee.encrypt("alice", "to the first keys")

        clock += day
        uptime += day
        alice.certificate() // certificates live a day
        assertTrue(alice.e2ee.syncIfDue())
        assertEquals("a day old: kept", v1.signedPreKey.id, alice.record.keys.signedPreKey.id)

        clock += day + hour
        uptime += day + hour
        alice.certificate()
        assertTrue(alice.e2ee.syncIfDue())
        assertNotEquals(v1.signedPreKey.id, alice.record.keys.signedPreKey.id)
        assertNotEquals(v1.pqPreKey.id, alice.record.keys.pqPreKey.id)
        assertArrayEquals(v1.identityKey, alice.record.keys.identityKey)

        assertEquals("the replaced keys still decrypt", "to the first keys", alice.e2ee.decrypt("bob", early))
    }

    @Test
    fun `fr-017 - a peer whose passport fails is refused and reported to the gateway`() = runTest {
        val alice = Phone("alice", "01ALICE").enroll()
        val mallory = Phone("bob", "01MALLORY")
        mallory.certificate(owner = "mallory") // a real device certificate, but of another account
        mallory.vault.provision()
        assertTrue(mallory.e2ee.sync()) // publishes under bob's name

        refused(E2eeFailure.BAD_PASSPORT) { alice.e2ee.encrypt("bob", "secret") }
        assertEquals(listOf(RaspFinding(E2eeService.BAD_PASSPORT, org.wolpmessenger.devicetrust.api.RaspReaction.REPORT, "USER bob")), alice.reports.findings)
        assertEquals(E2eePeerTrust.UNVERIFIED, alice.e2ee.peerState("bob").trust)
    }

    @Test
    fun `without a certificate or with a locked screen nothing is published and every operation refuses`() = runTest {
        val alice = Phone("alice")
        refused(E2eeFailure.NOT_ENROLLED) { alice.e2ee.encrypt("bob", "x") }
        refused(E2eeFailure.NOT_ENROLLED) { alice.e2ee.peerState("bob") }
        assertFalse(alice.e2ee.syncIfDue())
        assertFalse(alice.e2ee.sync())

        alice.certificate()
        alice.vault.provision()
        // a new process behind the lock screen: the vault key is not in memory
        alice.unlocked = false
        alice.vault = EnvelopeVault(alice.kek, File(alice.dir, "dek.bin"), UnlockState { alice.unlocked })
        alice.e2ee = alice.start()
        assertFalse(alice.e2ee.sync())
        refused(E2eeFailure.LOCKED) { alice.e2ee.encrypt("bob", "x") }
        assertNull(directory.records["alice"])

        alice.unlocked = true
        assertTrue(alice.e2ee.syncIfDue())
        assertEquals(1, alice.record.publications)
    }

    @Test
    fun `a new process keeps the record, a destroyed vault key publishes a new device`() = runTest {
        val alice = Phone("alice").enroll()
        val first = alice.record
        alice.e2ee = alice.start()
        assertTrue(alice.e2ee.syncIfDue())
        assertEquals("same keys, same passport: nothing to publish", 1, first.publications)

        alice.vault.wipe()
        alice.vault.provision()
        alice.e2ee = alice.start()
        assertTrue(alice.e2ee.syncIfDue())
        val second = alice.record
        assertNotEquals("one-time key ids start over, so the directory must see another device", first.deviceId, second.deviceId)
        assertFalse(first.keys.identityKey.contentEquals(second.keys.identityKey))
        assertEquals(KeySync.FULL, second.oneTime.size)
        assertTrue("its own earlier record is not somebody else's key", alice.reports.findings.isEmpty())
    }

    @Test
    fun `the trust of a build - roots and issuers go together`() {
        assertNull(E2eeService.trust(emptyList(), emptyList()))
        val pem = "-----BEGIN CERTIFICATE-----\n" + java.util.Base64.getMimeEncoder().encodeToString(ca.root.encoded) + "\n-----END CERTIFICATE-----\n"
        val trust = E2eeService.trust(listOf(pem), listOf(TestCa.spkiSha256(ca.issuer).uppercase()))!!
        assertEquals(listOf(ca.root), trust.roots)
        assertEquals(setOf(TestCa.spkiSha256(ca.issuer)), trust.issuers)
        for (bad in listOf<() -> Unit>(
            { E2eeService.trust(listOf(pem), emptyList()) },
            { E2eeService.trust(emptyList(), listOf(TestCa.spkiSha256(ca.issuer))) },
            { E2eeService.trust(listOf(pem), listOf("abc")) },
            { E2eeService.trust(listOf("not a certificate"), listOf(TestCa.spkiSha256(ca.issuer))) },
        )) {
            try {
                bad()
                fail("accepted")
            } catch (e: Exception) {
                assertTrue(e is IllegalArgumentException || e is java.security.cert.CertificateException)
            }
        }
    }
}
