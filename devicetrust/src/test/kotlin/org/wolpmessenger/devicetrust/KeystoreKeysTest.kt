package org.wolpmessenger.devicetrust

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.wolpmessenger.devicetrust.api.SecurityLevel
import org.wolpmessenger.devicetrust.keys.KeyGenResult
import org.wolpmessenger.devicetrust.keys.KeystoreKeys
import java.security.InvalidAlgorithmParameterException
import java.security.KeyStoreException
import java.security.ProviderException

class KeystoreKeysTest {
    private val backend = FakeBackend()
    private val keys = KeystoreKeys(backend)

    private fun ok(r: KeyGenResult) = (r as KeyGenResult.Ok).key

    @Test
    fun `TEE by default`() {
        val key = ok(keys.generate("dt.device.k1", byteArrayOf(1), preferStrongBox = false))
        assertEquals(SecurityLevel.TRUSTED_ENVIRONMENT, key.level)
        assertFalse(key.strongBoxFallback)
        assertEquals(listOf("dt.device.k1" to false), backend.generated)
    }

    @Test
    fun `StrongBox when it works`() {
        val key = ok(keys.generate("dt.device.k1", byteArrayOf(1), preferStrongBox = true))
        assertEquals(SecurityLevel.STRONGBOX, key.level)
        assertFalse(key.strongBoxFallback)
    }

    @Test
    fun `StrongBox failures listed in S2 §3 fall back to TEE`() {
        val triggers = listOf<(Boolean) -> Exception?>(
            { sb -> if (sb) ProviderException("StrongBoxUnavailable") else null },
            { sb -> if (sb) KeyStoreException("keystore") else null },
            { sb -> if (sb) InvalidAlgorithmParameterException("params") else null },
        )
        for (t in triggers) {
            val b = FakeBackend().apply { failGenerate = t }
            val key = ok(KeystoreKeys(b).generate("dt.device.k1", null, preferStrongBox = true))
            assertEquals(SecurityLevel.TRUSTED_ENVIRONMENT, key.level)
            assertTrue(key.strongBoxFallback)
            assertEquals(listOf("dt.device.k1" to true, "dt.device.k1" to false), b.generated)
        }
    }

    @Test
    fun `StrongBox failure while reading the chain also falls back`() {
        backend.failChain = { sb -> if (sb) ProviderException("chain") else null }
        val key = ok(keys.generate("dt.device.k1", null, preferStrongBox = true))
        assertTrue(key.strongBoxFallback)
        assertEquals(SecurityLevel.TRUSTED_ENVIRONMENT, key.level)
    }

    @Test
    fun `unexpected StrongBox failure propagates and leaves no alias`() {
        backend.failGenerate = { sb -> if (sb) IllegalStateException("bug") else null }
        assertThrows(IllegalStateException::class.java) { keys.generate("dt.device.k1", null, preferStrongBox = true) }
        assertTrue(backend.keys.isEmpty())
    }

    @Test
    fun `TEE failure propagates and leaves no alias`() {
        backend.failGenerate = { ProviderException("tee down") }
        assertThrows(ProviderException::class.java) { keys.generate("dt.device.k1", null, preferStrongBox = false) }
        assertTrue(backend.keys.isEmpty())
    }

    @Test
    fun `unconfirmed levels are rejected and deleted`() {
        for (level in listOf(SecurityLevel.SOFTWARE, SecurityLevel.UNKNOWN_SECURE, SecurityLevel.UNKNOWN)) {
            val b = FakeBackend(teeLevel = level)
            val r = KeystoreKeys(b).generate("dt.device.k1", null, preferStrongBox = false)
            assertEquals(KeyGenResult.SoftwareKeystore(level), r)
            assertTrue(b.keys.isEmpty())
        }
    }

    @Test
    fun `device aliases are numbered and never reused`() {
        assertEquals("dt.device.k1", keys.nextDeviceAlias())
        backend.keys["dt.device.k1"] = SecurityLevel.TRUSTED_ENVIRONMENT
        backend.keys["dt.device.k3"] = SecurityLevel.TRUSTED_ENVIRONMENT
        backend.keys["dt.vault"] = SecurityLevel.TRUSTED_ENVIRONMENT
        backend.keys["dt.device.kx"] = SecurityLevel.TRUSTED_ENVIRONMENT
        assertEquals("dt.device.k4", keys.nextDeviceAlias())
        assertEquals(listOf("dt.device.k1", "dt.device.k3"), keys.deviceKeyAliases())
    }

    @Test
    fun `orphan cleanup keeps listed keys, vault and foreign aliases`() {
        listOf("dt.device.k1", "dt.device.k2", "dt.vault", "dt.precheck", "other.app.key")
            .forEach { backend.keys[it] = SecurityLevel.TRUSTED_ENVIRONMENT }
        val removed = keys.deleteOrphans(keep = setOf("dt.device.k2"))
        assertEquals(listOf("dt.device.k1", "dt.precheck"), removed)
        assertEquals(listOf("dt.device.k2", "dt.vault", "other.app.key"), backend.aliases())
    }
}
