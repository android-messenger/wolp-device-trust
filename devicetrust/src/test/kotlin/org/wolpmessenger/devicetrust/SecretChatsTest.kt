package org.wolpmessenger.devicetrust

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.wolpmessenger.devicetrust.api.E2eeException
import org.wolpmessenger.devicetrust.api.E2eeFailure
import org.wolpmessenger.devicetrust.api.VaultPurpose
import org.wolpmessenger.devicetrust.e2ee.KeyDirectory
import org.wolpmessenger.devicetrust.e2ee.OneTimeKey
import org.wolpmessenger.devicetrust.e2ee.OwnKeys
import org.wolpmessenger.devicetrust.e2ee.PeerKeys
import org.wolpmessenger.devicetrust.e2ee.SecretChats
import org.wolpmessenger.devicetrust.e2ee.SignedKey
import org.wolpmessenger.devicetrust.vault.EnvelopeVault
import org.wolpmessenger.devicetrust.vault.UnlockState
import java.io.File

/** specs/002, story 1: two libraries in one process and a stand-in key directory. */
class SecretChatsTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private var clock = 1_800_000_000_000L
    private val day = 24L * 60 * 60 * 1000

    /** Stand-in key directory: one record per user, a one-time key is handed out once. */
    private inner class Directory : KeyDirectory {
        val records = HashMap<String, OwnKeys>()
        val oneTime = HashMap<String, ArrayDeque<OneTimeKey>>()
        var online = true
        var fetches = 0

        fun publish(user: String, keys: OwnKeys) {
            records[user] = keys
            oneTime.getOrPut(user) { ArrayDeque() }.addAll(keys.oneTimePreKeys)
        }

        override suspend fun fetch(user: String): PeerKeys {
            fetches++
            if (!online) throw E2eeException(E2eeFailure.NO_NETWORK)
            val r = records[user] ?: throw E2eeException(E2eeFailure.NO_DEVICE)
            return PeerKeys(r.identityKey, r.registrationId, r.signedPreKey, r.pqPreKey, oneTime[user]?.removeFirstOrNull())
        }
    }

    /** One phone: its own vault and its own files. */
    private inner class Phone(val user: String, val directory: Directory, val dir: File = tmp.newFolder()) {
        var unlocked = true
        val kek = SoftKek()
        val vault = EnvelopeVault(kek, File(dir, "dek.bin"), UnlockState { unlocked })
        val files = File(dir, "e2ee")

        /** A new process over the same files. */
        fun start() = SecretChats(user, files, vault, directory) { clock }
        var chats = start()

        suspend fun enroll(oneTime: Int = 5): Phone {
            vault.provision()
            directory.publish(user, chats.ownKeys(oneTime))
            return this
        }
    }

    private val directory = Directory()

    private suspend fun pair(): Pair<Phone, Phone> = Phone("alice", directory).enroll() to Phone("bob", directory).enroll()

    private suspend fun refused(expected: E2eeFailure, block: suspend () -> Unit) {
        try {
            block()
            fail("expected $expected")
        } catch (e: E2eeException) {
            assertEquals(expected, e.failure)
        }
    }

    @Test
    fun `1 - first message, the answer and what follows go both ways`() = runTest {
        val (alice, bob) = pair()
        val first = alice.chats.encrypt("bob", "привет")
        assertTrue(first.startsWith("E2EE2:3."))
        assertEquals("привет", bob.chats.decrypt("alice", first))

        val answer = bob.chats.encrypt("alice", "ответ")
        assertTrue(answer.startsWith("E2EE2:2."))
        assertEquals("ответ", alice.chats.decrypt("bob", answer))

        repeat(3) {
            assertEquals("a$it", bob.chats.decrypt("alice", alice.chats.encrypt("bob", "a$it")))
            assertEquals("b$it", alice.chats.decrypt("bob", bob.chats.encrypt("alice", "b$it")))
        }
        assertEquals("only the first message needs the directory", 1, directory.fetches)
    }

    @Test
    fun `2 - messages out of order and with one lost are decrypted`() = runTest {
        val (alice, bob) = pair()
        val m = List(5) { alice.chats.encrypt("bob", "m$it") }
        for (i in listOf(3, 0, 4, 1)) assertEquals("m$i", bob.chats.decrypt("alice", m[i])) // m2 never arrives
        assertEquals("ok", alice.chats.decrypt("bob", bob.chats.encrypt("alice", "ok")))
    }

    @Test
    fun `3 - the same message twice is a duplicate and the session survives`() = runTest {
        val (alice, bob) = pair()
        val first = alice.chats.encrypt("bob", "one")
        val second = alice.chats.encrypt("bob", "two")
        assertEquals("one", bob.chats.decrypt("alice", first))
        refused(E2eeFailure.DUPLICATE) { bob.chats.decrypt("alice", first) }
        assertEquals("two", bob.chats.decrypt("alice", second))
        refused(E2eeFailure.DUPLICATE) { bob.chats.decrypt("alice", second) }
        assertEquals("three", bob.chats.decrypt("alice", alice.chats.encrypt("bob", "three")))
    }

    @Test
    fun `3 - garbage and a damaged message are undecryptable and change nothing`() = runTest {
        val (alice, bob) = pair()
        val good = alice.chats.encrypt("bob", "one")
        for (bad in listOf("", "E2EE1:abc", "E2EE2:", "E2EE2:9.AAAA", "E2EE2:3.***", good.dropLast(4) + "AAAA")) {
            refused(E2eeFailure.UNDECRYPTABLE) { bob.chats.decrypt("alice", bad) }
        }
        assertEquals("one", bob.chats.decrypt("alice", good))
    }

    @Test
    fun `4 - sessions survive a restart of the process`() = runTest {
        val (alice, bob) = pair()
        assertEquals("one", bob.chats.decrypt("alice", alice.chats.encrypt("bob", "one")))
        assertEquals("ack", alice.chats.decrypt("bob", bob.chats.encrypt("alice", "ack")))
        alice.chats = alice.start()
        bob.chats = bob.start()
        val next = alice.chats.encrypt("bob", "two")
        assertTrue("no new session after a restart", next.startsWith("E2EE2:2."))
        assertEquals("two", bob.chats.decrypt("alice", next))
        assertEquals("three", alice.chats.decrypt("bob", bob.chats.encrypt("alice", "three")))
    }

    @Test
    fun `5 - locked device refuses every operation and loses nothing`() = runTest {
        val (alice, bob) = pair()
        assertEquals("one", bob.chats.decrypt("alice", alice.chats.encrypt("bob", "one")))
        val waiting = alice.chats.encrypt("bob", "two")

        // a new process behind the lock screen: the vault key is not in memory
        bob.unlocked = false
        val locked = SecretChats("bob", bob.files, EnvelopeVault(bob.kek, File(bob.dir, "dek.bin"), UnlockState { bob.unlocked }), directory) { clock }
        val before = bob.files.listFiles()!!.associate { it.name to it.readBytes().toList() }
        refused(E2eeFailure.LOCKED) { locked.decrypt("alice", waiting) }
        refused(E2eeFailure.LOCKED) { locked.encrypt("alice", "x") }
        refused(E2eeFailure.LOCKED) { locked.resetSession("alice") }
        refused(E2eeFailure.LOCKED) { locked.ownKeys(1) }
        refused(E2eeFailure.LOCKED) { locked.rotateSignedKeys() }
        assertEquals(before, bob.files.listFiles()!!.associate { it.name to it.readBytes().toList() })

        bob.unlocked = true
        assertEquals("two", locked.decrypt("alice", waiting))
    }

    @Test
    fun `6 - a destroyed vault key deletes the state, a new identity key is made`() = runTest {
        val (alice, bob) = pair()
        assertEquals("one", bob.chats.decrypt("alice", alice.chats.encrypt("bob", "one")))
        val oldIdentity = directory.records.getValue("bob").identityKey
        val late = alice.chats.encrypt("bob", "late")

        bob.vault.wipe() // BLOCK, unenroll, screen lock removed
        refused(E2eeFailure.NOT_ENROLLED) { bob.chats.decrypt("alice", late) }
        assertTrue("the state must not outlive its key", bob.files.listFiles().isNullOrEmpty())

        bob.vault.provision() // VaultReset
        refused(E2eeFailure.UNDECRYPTABLE) { bob.chats.decrypt("alice", late) }
        val fresh = bob.chats.ownKeys(5)
        assertFalse(oldIdentity.contentEquals(fresh.identityKey))
    }

    @Test
    fun `6 - files left from a vault key that was replaced are deleted`() = runTest {
        val (alice, bob) = pair()
        assertEquals("one", bob.chats.decrypt("alice", alice.chats.encrypt("bob", "one")))
        val oldIdentity = directory.records.getValue("bob").identityKey
        val stale = bob.files.listFiles()!!.map { it.name }.filter { it.startsWith("p-") }
        assertEquals(1, stale.size)

        bob.vault.wipe()
        bob.vault.provision() // the app was not running in between
        val fresh = bob.chats.ownKeys(5)
        assertFalse(oldIdentity.contentEquals(fresh.identityKey))
        assertEquals(listOf("account.bin"), bob.files.listFiles()!!.map { it.name })
    }

    @Test
    fun `7 - files show no keys, no sessions and no peer names`() = runTest {
        val (alice, bob) = pair()
        assertEquals("one", bob.chats.decrypt("alice", alice.chats.encrypt("bob", "one")))
        assertEquals("two", alice.chats.decrypt("bob", bob.chats.encrypt("alice", "two")))

        val files = bob.files.listFiles()!!.toList()
        assertEquals(2, files.size)
        val known = listOf(
            "alice".toByteArray(), "bob".toByteArray(),
            directory.records.getValue("alice").identityKey, directory.records.getValue("bob").identityKey,
            directory.records.getValue("bob").signedPreKey.publicKey,
        )
        for (f in files) {
            assertFalse(f.name, f.name.contains("alice"))
            val raw = String(f.readBytes(), Charsets.ISO_8859_1)
            for (k in known) assertFalse(f.name, raw.contains(String(k, Charsets.ISO_8859_1)))
            // each file is a Vault blob for E2EE bound to its own name: it does not open under another name or purpose
            assertTrue(bob.vault.unwrap(f.readBytes(), VaultPurpose.E2EE, f.name.toByteArray()).isNotEmpty())
            assertTrue(runCatching { bob.vault.unwrap(f.readBytes(), VaultPurpose.E2EE, "x".toByteArray()) }.isFailure)
            assertTrue(runCatching { bob.vault.unwrap(f.readBytes(), VaultPurpose.E2EE_PLAINTEXT, f.name.toByteArray()) }.isFailure)
        }
        // and the plain content does hold what we looked for — the search above is not vacuous
        val peerFile = files.single { it.name.startsWith("p-") }
        val plain = String(bob.vault.unwrap(peerFile.readBytes(), VaultPurpose.E2EE, peerFile.name.toByteArray()), Charsets.ISO_8859_1)
        assertTrue(plain.contains(String(directory.records.getValue("alice").identityKey, Charsets.ISO_8859_1)))
    }

    @Test
    fun `8 - a lost session comes back after the sender starts it anew`() = runTest {
        val (alice, bob) = pair()
        assertEquals("one", bob.chats.decrypt("alice", alice.chats.encrypt("bob", "one")))
        assertEquals("two", alice.chats.decrypt("bob", bob.chats.encrypt("alice", "two")))

        // Bob's file for Alice is damaged: her next message does not decrypt
        bob.files.listFiles()!!.single { it.name.startsWith("p-") }.writeBytes(ByteArray(64))
        val lost = alice.chats.encrypt("bob", "three")
        refused(E2eeFailure.UNDECRYPTABLE) { bob.chats.decrypt("alice", lost) }

        // Bob asks, Alice starts the session anew and sends the same text again
        val fetchesBefore = directory.fetches
        alice.chats.resetSession("bob")
        val again = alice.chats.encrypt("bob", "three")
        assertTrue(again.startsWith("E2EE2:3."))
        assertEquals(fetchesBefore + 1, directory.fetches)
        assertEquals("three", bob.chats.decrypt("alice", again))

        assertEquals("four", alice.chats.decrypt("bob", bob.chats.encrypt("alice", "four")))
        val five = alice.chats.encrypt("bob", "five")
        assertTrue("the new session is acknowledged", five.startsWith("E2EE2:2."))
        assertEquals("five", bob.chats.decrypt("alice", five))
    }

    @Test
    fun `8 - the session set aside still decrypts what the peer sent with it`() = runTest {
        val (alice, bob) = pair()
        assertEquals("one", bob.chats.decrypt("alice", alice.chats.encrypt("bob", "one")))
        val sentBefore = bob.chats.encrypt("alice", "from the old session")

        alice.chats.resetSession("bob")
        assertEquals("anew", bob.chats.decrypt("alice", alice.chats.encrypt("bob", "anew")))
        assertEquals("from the old session", alice.chats.decrypt("bob", sentBefore))
        assertEquals("next", alice.chats.decrypt("bob", bob.chats.encrypt("alice", "next")))
    }

    @Test
    fun `8 - reset without a session is a no-op`() = runTest {
        val (alice, _) = pair()
        alice.chats.resetSession("bob")
        alice.chats.resetSession("nobody")
        assertEquals(0, directory.fetches)
    }

    @Test
    fun `9 - the peer changed the phone - the new session is built on the new phone's keys`() = runTest {
        val (alice, bob) = pair()
        assertEquals("one", bob.chats.decrypt("alice", alice.chats.encrypt("bob", "one")))
        val old = alice.chats.encrypt("bob", "sent from the old phone")

        val newAlice = Phone("alice", directory).enroll()
        refused(E2eeFailure.UNDECRYPTABLE) { newAlice.chats.decrypt("bob", bob.chats.encrypt("alice", "to the old phone")) }

        // Bob was offline: he still decrypts what the old phone sent, then asks the new one
        assertEquals("sent from the old phone", bob.chats.decrypt("alice", old))
        newAlice.chats.resetSession("bob")
        assertEquals("hello again", bob.chats.decrypt("alice", newAlice.chats.encrypt("bob", "hello again")))
        assertEquals("answer", newAlice.chats.decrypt("bob", bob.chats.encrypt("alice", "answer")))
    }

    @Test
    fun `both start at the same moment`() = runTest {
        val (alice, bob) = pair()
        val a = alice.chats.encrypt("bob", "from alice")
        val b = bob.chats.encrypt("alice", "from bob")
        assertEquals("from alice", bob.chats.decrypt("alice", a))
        assertEquals("from bob", alice.chats.decrypt("bob", b))
        repeat(2) {
            assertEquals("a$it", bob.chats.decrypt("alice", alice.chats.encrypt("bob", "a$it")))
            assertEquals("b$it", alice.chats.decrypt("bob", bob.chats.encrypt("alice", "b$it")))
        }
    }

    @Test
    fun `no one-time keys left - the session is still built`() = runTest {
        val alice = Phone("alice", directory).enroll()
        val bob = Phone("bob", directory).enroll(oneTime = 0)
        val first = alice.chats.encrypt("bob", "one")
        assertEquals("one", bob.chats.decrypt("alice", first))
        refused(E2eeFailure.DUPLICATE) { bob.chats.decrypt("alice", first) }
        assertEquals("two", alice.chats.decrypt("bob", bob.chats.encrypt("alice", "two")))
    }

    @Test
    fun `a first message replayed after its session is gone is refused`() = runTest {
        val alice = Phone("alice", directory).enroll()
        val bob = Phone("bob", directory).enroll(oneTime = 0)
        val first = alice.chats.encrypt("bob", "one")
        assertEquals("one", bob.chats.decrypt("alice", first))
        bob.files.listFiles()!!.single { it.name.startsWith("p-") }.delete()
        refused(E2eeFailure.UNDECRYPTABLE) { bob.chats.decrypt("alice", first) }
    }

    @Test
    fun `refusals of encryption - oneself, no device, no network, forged prekey`() = runTest {
        val (alice, bob) = pair()
        refused(E2eeFailure.NO_DEVICE) { alice.chats.encrypt("alice", "x") }
        refused(E2eeFailure.NO_DEVICE) { alice.chats.encrypt("carol", "x") }

        directory.online = false
        refused(E2eeFailure.NO_NETWORK) { alice.chats.encrypt("bob", "x") }
        directory.online = true
        assertEquals("one", bob.chats.decrypt("alice", alice.chats.encrypt("bob", "one")))
        directory.online = false
        assertEquals("a ready session needs no directory", "two", bob.chats.decrypt("alice", alice.chats.encrypt("bob", "two")))
        directory.online = true

        // the directory swaps the signed prekey: it is not signed by the identity key it comes with
        val carol = Phone("carol", directory).enroll()
        val real = directory.records.getValue("carol")
        val foreign = directory.records.getValue("bob").signedPreKey
        directory.records["carol"] = OwnKeys(real.identityKey, real.registrationId, SignedKey(foreign.id, foreign.publicKey, real.signedPreKey.signature), real.pqPreKey, emptyList())
        refused(E2eeFailure.BAD_PASSPORT) { alice.chats.encrypt("carol", "x") }
        directory.records["carol"] = real
        assertEquals("ok", carol.chats.decrypt("alice", alice.chats.encrypt("carol", "ok")))
    }

    @Test
    fun `published keys - ids never repeat, replaced signed keys work for 30 days`() = runTest {
        val alice = Phone("alice", directory).enroll()
        val bob = Phone("bob", directory)
        bob.vault.provision()
        val v1 = bob.chats.ownKeys(3)
        val more = bob.chats.ownKeys(2)
        assertEquals(listOf(1, 2, 3, 4, 5), (v1.oneTimePreKeys + more.oneTimePreKeys).map { it.id })
        assertEquals("the signed prekey stays until rotated", v1.signedPreKey.id, more.signedPreKey.id)
        assertEquals(1569, v1.pqPreKey.publicKey.size)
        assertEquals(33, v1.identityKey.size)
        assertTrue(v1.registrationId in 1..16380)

        // Alice builds two sessions' worth of first messages on the keys published first
        directory.publish("bob", v1)
        val early = alice.chats.encrypt("bob", "within 30 days")
        alice.chats.resetSession("bob")
        val late = alice.chats.encrypt("bob", "after 30 days")

        bob.chats.rotateSignedKeys()
        val v2 = bob.chats.ownKeys(0)
        assertNotEquals(v1.signedPreKey.id, v2.signedPreKey.id)
        assertNotEquals(v1.pqPreKey.id, v2.pqPreKey.id)
        assertTrue(v1.identityKey.contentEquals(v2.identityKey))

        clock += 29 * day
        assertEquals("within 30 days", bob.chats.decrypt("alice", early))
        clock += 2 * day
        bob.chats.ownKeys(0) // any publication drops what expired
        refused(E2eeFailure.UNDECRYPTABLE) { bob.chats.decrypt("alice", late) }
    }
}
