package org.wolpmessenger.devicetrust

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.wolpmessenger.devicetrust.api.DeviceTrustConfig
import org.wolpmessenger.devicetrust.api.PrecheckResult
import org.wolpmessenger.devicetrust.api.RaspFinding
import org.wolpmessenger.devicetrust.api.RaspReaction
import org.wolpmessenger.devicetrust.api.RaspReport
import org.wolpmessenger.devicetrust.api.SecurityLevel
import org.wolpmessenger.devicetrust.api.UnsupportedReason
import org.wolpmessenger.devicetrust.attest.CachedKeystoreLevel
import org.wolpmessenger.devicetrust.attest.Precheck
import org.wolpmessenger.devicetrust.attest.RaspScanner
import org.wolpmessenger.devicetrust.keys.KeystoreKeys
import java.time.LocalDate

class PrecheckTest {
    private val backend = FakeBackend()
    private val env = FakeEnv()
    private val cache = MemCache()
    private var rasp = RaspReport.CLEAN

    private fun precheck(config: DeviceTrustConfig = DeviceTrustConfig()) =
        Precheck(KeystoreKeys(backend), env, cache, RaspScanner { rasp }, config)

    @Test
    fun `hardware keystore, fresh patch, screen lock - supported`() = runTest {
        val r = precheck().run() as PrecheckResult.Supported
        assertEquals(SecurityLevel.TRUSTED_ENVIRONMENT, r.info.keystoreLevel)
        assertTrue(r.reports.isEmpty())
        assertTrue("precheck key must be deleted", backend.keys.isEmpty())
    }

    @Test
    fun `RASP BLOCK wins before Keystore is touched`() = runTest {
        rasp = RaspReport(listOf(RaspFinding("ROOT_SU", RaspReaction.BLOCK), RaspFinding("DEV_OPTIONS", RaspReaction.REPORT)))
        val r = precheck().run()
        assertTrue(r is PrecheckResult.Compromised)
        assertTrue(backend.generated.isEmpty())
    }

    @Test
    fun `software keystore is unsupported`() = runTest {
        backend.teeLevel = SecurityLevel.SOFTWARE
        val r = precheck().run() as PrecheckResult.Unsupported
        assertEquals(listOf(UnsupportedReason.SOFTWARE_KEYSTORE), r.reasons)
        assertEquals(SecurityLevel.SOFTWARE, r.info?.keystoreLevel)
    }

    @Test
    fun `all reasons are reported together`() = runTest {
        backend.teeLevel = SecurityLevel.SOFTWARE
        env.securityPatch = "2024-01-05"
        val r = precheck().run() as PrecheckResult.Unsupported
        assertEquals(listOf(UnsupportedReason.SOFTWARE_KEYSTORE, UnsupportedReason.PATCH_TOO_OLD), r.reasons)
    }

    @Test
    fun `patch age boundary is inclusive and unparseable is not fresh`() {
        val p = precheck(DeviceTrustConfig(maxPatchAgeMonths = 12))
        env.now = LocalDate.of(2026, 11, 30)
        assertTrue(p.patchFresh("2025-11-01"))
        assertFalse(p.patchFresh("2025-10-31"))
        assertFalse(p.patchFresh(""))
        assertFalse(p.patchFresh("garbage"))
    }

    @Test
    fun `RASP reports pass through`() = runTest {
        rasp = RaspReport(listOf(RaspFinding("DEV_OPTIONS", RaspReaction.REPORT)))
        val r = precheck().run() as PrecheckResult.Supported
        assertEquals(listOf("DEV_OPTIONS"), r.reports.map { it.id })
    }

    /** specs/001-rasp-hardening FR-009: the E2EE key is bound to the lock screen, so there must be one. */
    @Test
    fun `no screen lock - the device is not supported`() = runTest {
        env.secure = false
        val r = precheck().run() as PrecheckResult.Unsupported
        assertEquals(listOf(org.wolpmessenger.devicetrust.api.UnsupportedReason.NO_SCREEN_LOCK), r.reasons)
        assertFalse(r.info!!.screenLockSecure)
    }

    @Test
    fun `Keystore is probed once per process`() = runTest {
        val p = precheck()
        p.run(); p.run()
        assertEquals(1, backend.generated.size)
    }

    @Test
    fun `cache is reused for the same boot and app version`() = runTest {
        cache.value = CachedKeystoreLevel(bootCount = 7, versionCode = 10300, level = SecurityLevel.STRONGBOX, strongBoxFallback = false)
        val r = precheck().run() as PrecheckResult.Supported
        assertEquals(SecurityLevel.STRONGBOX, r.info.keystoreLevel)
        assertTrue(backend.generated.isEmpty())
    }

    @Test
    fun `cache is ignored after reboot or update`() = runTest {
        cache.value = CachedKeystoreLevel(bootCount = 6, versionCode = 10300, level = SecurityLevel.SOFTWARE, strongBoxFallback = false)
        assertTrue(precheck().run() is PrecheckResult.Supported)
        assertEquals(7, cache.value?.bootCount)

        cache.value = CachedKeystoreLevel(bootCount = 7, versionCode = 10200, level = SecurityLevel.SOFTWARE, strongBoxFallback = false)
        assertTrue(precheck().run() is PrecheckResult.Supported)
    }

    @Test
    fun `unknown boot count disables the persistent cache`() = runTest {
        env.bootCount = -1
        cache.value = CachedKeystoreLevel(bootCount = -1, versionCode = 10300, level = SecurityLevel.SOFTWARE, strongBoxFallback = false)
        assertTrue(precheck().run() is PrecheckResult.Supported)
        assertEquals(0, cache.saves)
    }

    @Test
    fun `StrongBox config probes StrongBox and records the fallback`() = runTest {
        backend.failGenerate = { sb -> if (sb) java.security.ProviderException("no strongbox") else null }
        val r = precheck(DeviceTrustConfig(deviceKeyStrongBox = true)).run() as PrecheckResult.Supported
        assertTrue(r.info.strongBoxFallback)
        assertEquals(SecurityLevel.TRUSTED_ENVIRONMENT, r.info.keystoreLevel)
    }
}
