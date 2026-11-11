package org.wolpmessenger.devicetrust

import kotlinx.coroutines.async
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.yield
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.wolpmessenger.devicetrust.api.VaultException
import org.wolpmessenger.devicetrust.api.VaultPurpose
import org.wolpmessenger.devicetrust.vault.EnvelopeVault
import org.wolpmessenger.devicetrust.vault.Kek
import org.wolpmessenger.devicetrust.vault.UnlockState
import org.wolpmessenger.devicetrust.vault.VaultKeys
import java.io.File
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Software stand-in for the Keystore KEK. */
internal class SoftKek : Kek {
    var key: SecretKey? = null
    var decrypts = 0
    override fun exists() = key != null
    override fun create() {
        key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
    }

    override fun delete() {
        key = null
    }

    override fun encrypt(plain: ByteArray, aad: ByteArray): ByteArray {
        val iv = ByteArray(12).also(SecureRandom()::nextBytes)
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv)) }
        c.updateAAD(aad)
        return iv + c.doFinal(plain)
    }

    override fun decrypt(ivCiphertextTag: ByteArray, aad: ByteArray): ByteArray {
        decrypts++
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, ivCiphertextTag, 0, 12))
        c.updateAAD(aad)
        return c.doFinal(ivCiphertextTag, 12, ivCiphertextTag.size - 12)
    }
}

/** Returns scripted bytes first (DEK, then IVs), random afterwards. */
private class ScriptedRandom(vararg chunks: ByteArray) : SecureRandom() {
    private val queue = ArrayDeque(chunks.toList())
    override fun nextBytes(bytes: ByteArray) {
        val next = queue.removeFirstOrNull() ?: return super.nextBytes(bytes)
        require(next.size == bytes.size) { "scripted ${next.size} bytes, asked ${bytes.size}" }
        next.copyInto(bytes)
    }
}

class VaultTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private val kek = SoftKek()
    private var unlocked = true
    private val dekFile by lazy { File(tmp.root, "dt/dek.bin") }

    private fun vault(random: SecureRandom = SecureRandom()) = EnvelopeVault(kek, dekFile, UnlockState { unlocked }, random)

    private inline fun <reified T : VaultException> assertVault(block: () -> Unit) {
        try {
            block()
            fail("expected ${T::class.simpleName}")
        } catch (e: VaultException) {
            assertTrue("expected ${T::class.simpleName}, got $e", e is T)
        }
    }

    @Test
    fun `blob format matches an independent implementation (Python cryptography)`() = runTest {
        val dek = ByteArray(32) { it.toByte() }
        val iv = ByteArray(12) { (100 + it).toByte() }
        val v = vault(ScriptedRandom(dek, iv, iv))
        v.provision()

        val blob = v.wrap("signal-identity-key".toByteArray(), VaultPurpose.E2EE, "conv-42".toByteArray())
        assertEquals(
            "026465666768696a6b6c6d6e6f3b72b90818857bf75a07319cb31113d029a77f1873889406e9392cb461b39e008eb81a",
            blob.toHex(),
        )
        assertEquals("026465666768696a6b6c6d6e6f393bdc73546738e1af3a7412d0f1993d", v.wrap(ByteArray(0), VaultPurpose.NAMES).toHex())
    }

    @Test
    fun `round trip for every purpose and size`() = runTest {
        val v = vault().apply { provision() }
        for (purpose in VaultPurpose.entries) for (size in listOf(0, 1, 32, 4096)) {
            val plain = ByteArray(size) { (it * 31).toByte() }
            assertArrayEquals(plain, v.unwrap(v.wrap(plain, purpose), purpose))
            assertArrayEquals(plain, v.unwrap(v.wrap(plain, purpose, byteArrayOf(9)), purpose, byteArrayOf(9)))
        }
    }

    @Test
    fun `wrong purpose, wrong extra AAD, tampered header or body are Corrupt`() = runTest {
        val v = vault().apply { provision() }
        val blob = v.wrap("secret".toByteArray(), VaultPurpose.E2EE, "a".toByteArray())
        assertVault<VaultException.Corrupt> { v.unwrap(blob, VaultPurpose.E2EE_PLAINTEXT, "a".toByteArray()) }
        assertVault<VaultException.Corrupt> { v.unwrap(blob, VaultPurpose.E2EE, "b".toByteArray()) }
        assertVault<VaultException.Corrupt> { v.unwrap(blob, VaultPurpose.E2EE) }
        for (i in listOf(0, 1, 12, 13, blob.size - 1)) {
            val bad = blob.copyOf().also { it[i] = (it[i].toInt() xor 1).toByte() }
            assertVault<VaultException.Corrupt> { v.unwrap(bad, VaultPurpose.E2EE, "a".toByteArray()) }
        }
        assertVault<VaultException.Corrupt> { v.unwrap(blob.copyOf(20), VaultPurpose.E2EE, "a".toByteArray()) }
        assertVault<VaultException.Corrupt> { v.unwrap(ByteArray(0), VaultPurpose.E2EE) }
    }

    @Test
    fun `DEK survives a process restart and is unwrapped with one KEK call`() = runTest {
        val blob = vault().run { provision(); wrap("x".toByteArray(), VaultPurpose.PUSH_KEY) }
        kek.decrypts = 0
        val fresh = vault()
        repeat(5) { assertArrayEquals("x".toByteArray(), fresh.unwrap(blob, VaultPurpose.PUSH_KEY)) }
        assertEquals(1, kek.decrypts)
    }

    @Test
    fun `provision is idempotent and keeps existing data readable`() = runTest {
        val v = vault()
        assertTrue(v.provision())
        val blob = v.wrap("keep".toByteArray(), VaultPurpose.E2EE)
        assertFalse(v.provision())
        assertFalse(vault().provision())
        assertArrayEquals("keep".toByteArray(), vault().unwrap(blob, VaultPurpose.E2EE))
    }

    @Test
    fun `missing keys are KeyGone and wipe destroys everything`() = runTest {
        assertEquals(VaultKeys.MISSING, vault().keys())
        assertVault<VaultException.KeyGone> { vault().wrap(ByteArray(1), VaultPurpose.E2EE) }

        val v = vault().apply { provision() }
        val blob = v.wrap("gone".toByteArray(), VaultPurpose.E2EE)
        v.wipe()
        assertEquals(VaultKeys.MISSING, v.keys())
        assertFalse(dekFile.exists())
        assertVault<VaultException.KeyGone> { v.unwrap(blob, VaultPurpose.E2EE) }
        v.wipe() // idempotent
    }

    @Test
    fun `replaced KEK or damaged DEK file make the DEK unrecoverable (KeyGone, partial keys)`() = runTest {
        vault().provision()
        kek.create() // a new KEK cannot open the old DEK
        assertVault<VaultException.KeyGone> { vault().wrap(ByteArray(1), VaultPurpose.E2EE) }

        kek.delete()
        assertEquals(VaultKeys.PARTIAL, vault().keys())
        assertTrue("provision repairs a partial vault", vault().provision())
        dekFile.writeBytes(byteArrayOf(0x01, 1, 2, 3))
        assertVault<VaultException.KeyGone> { vault().wrap(ByteArray(1), VaultPurpose.E2EE) }
    }

    @Test
    fun `before the first unlock the vault is Locked`() = runTest {
        vault().provision()
        unlocked = false
        assertVault<VaultException.Locked> { vault().wrap(ByteArray(1), VaultPurpose.E2EE) }
        assertVault<VaultException.Locked> { vault().provision() }
    }

    private fun ByteArray.toHex() = joinToString("") { "%02x".format(it) }

    // ---------------------------------------------------------------- specs/001-rasp-hardening, story 3

    @Test
    fun `nothing is wrapped or unwrapped until an integrity pass allowed it`() = runTest {
        val gate = org.wolpmessenger.devicetrust.rasp.IntegrityGate(waitMs = 50)
        val v = EnvelopeVault(kek, dekFile, UnlockState { unlocked }, SecureRandom(), gate = { gate.require() })
        v.provision()
        assertVault<VaultException.Locked> { v.wrap(byteArrayOf(1), VaultPurpose.E2EE) } // no pass yet

        gate.record(open = true)
        val blob = v.wrap(byteArrayOf(1, 2, 3), VaultPurpose.E2EE)
        assertArrayEquals(byteArrayOf(1, 2, 3), v.unwrap(blob, VaultPurpose.E2EE))

        gate.record(open = false) // a later pass found something, or could not run
        assertVault<VaultException.Locked> { v.unwrap(blob, VaultPurpose.E2EE) }
        assertEquals("closed is not a wipe", VaultKeys.PRESENT, v.keys())

        gate.record(open = true)
        assertArrayEquals(byteArrayOf(1, 2, 3), v.unwrap(blob, VaultPurpose.E2EE))
    }

    @Test
    fun `a waiting caller gets through as soon as the first pass ends`() = runTest {
        val gate = org.wolpmessenger.devicetrust.rasp.IntegrityGate(waitMs = 60_000)
        val v = EnvelopeVault(kek, dekFile, UnlockState { unlocked }, SecureRandom(), gate = { gate.require() })
        v.provision()
        val waiting = async { v.wrap(byteArrayOf(7), VaultPurpose.E2EE) }
        yield()
        assertFalse(waiting.isCompleted)
        gate.record(open = true)
        assertTrue(waiting.await().isNotEmpty())
    }
}
