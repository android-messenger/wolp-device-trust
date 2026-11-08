package org.wolpmessenger.devicetrust

import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.wolpmessenger.devicetrust.api.BlockReason
import org.wolpmessenger.devicetrust.api.DeviceTrustConfig
import org.wolpmessenger.devicetrust.api.RaspReport
import org.wolpmessenger.devicetrust.api.SecurityLevel
import org.wolpmessenger.devicetrust.api.TrustState
import org.wolpmessenger.devicetrust.api.UpdateKind
import org.wolpmessenger.devicetrust.attest.Precheck
import org.wolpmessenger.devicetrust.attest.RaspScanner
import org.wolpmessenger.devicetrust.clock.ClockAnchor
import org.wolpmessenger.devicetrust.clock.ClockSource
import org.wolpmessenger.devicetrust.clock.TrustClock
import org.wolpmessenger.devicetrust.enroll.Enroller
import org.wolpmessenger.devicetrust.keys.KeystoreKeys
import org.wolpmessenger.devicetrust.net.GatewayClient
import org.wolpmessenger.devicetrust.net.HttpClients
import org.wolpmessenger.devicetrust.store.ActiveCert
import org.wolpmessenger.devicetrust.store.Enrolling
import org.wolpmessenger.devicetrust.store.Phase
import org.wolpmessenger.devicetrust.store.StoredState
import org.wolpmessenger.devicetrust.store.TrustStore
import org.wolpmessenger.devicetrust.store.UpdateRequiredInfo
import java.time.Instant
import kotlin.time.Duration.Companion.days

class StoreAndCoreTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private val t0 = Instant.parse("2026-11-08T10:00:00Z")
    private val active = ActiveCert("dt.device.k3", "abc123", t0, t0.plusSeconds(72 * 3600), t0.plusSeconds(48 * 3600))

    @Test
    fun `state json round trip, update and certificate chains`() {
        val store = TrustStore(tmp.root)
        assertEquals(StoredState(), store.load())
        val s = StoredState(
            phase = Phase.ENROLLED, deviceId = "01JD", active = active,
            enrolling = Enrolling("01JE", "dt.device.k4", byteArrayOf(1, 2), listOf(byteArrayOf(3), byteArrayOf(4, 5)), t0),
            credentialsVersion = 7, clock = ClockAnchor(1, 2, 3),
            updateRequired = UpdateRequiredInfo("OS", "PATCH_TOO_OLD", 10300, "2026-01-01"), blockReason = null,
        )
        store.save(s)
        val back = TrustStore(tmp.root).load()
        assertEquals(s.copy(enrolling = null), back.copy(enrolling = null))
        assertArrayEquals(byteArrayOf(4, 5), back.enrolling!!.chain[1])
        assertEquals("01JE", back.enrolling!!.enrollmentId)

        store.update { it.copy(credentialsVersion = it.credentialsVersion + 1) }
        assertEquals(8, store.load().credentialsVersion)

        val c = cert("plain.pem")
        store.writeChain(3, listOf(c, c))
        store.writeChain(9, listOf(c))
        assertEquals(listOf(c, c), store.readChain(3))
        store.deleteChainsExcept(setOf(3))
        assertNull(store.readChain(9))
        assertNotNull(store.readChain(3))
    }

    private class FixedClock(var nowMs: Long) : ClockSource {
        override fun elapsedRealtime() = 0L
        override fun systemEpochMs() = nowMs
        override fun bootCount() = 1
    }

    private fun core(store: TrustStore, backend: FakeBackend, now: Instant = t0): DeviceTrustCore {
        val keys = KeystoreKeys(backend)
        val clock = TrustClock(FixedClock(now.toEpochMilli()))
        val config = DeviceTrustConfig(reattestGrace = 7.days)
        val precheck = Precheck(keys, FakeEnv(), MemCache(), RaspScanner { RaspReport.CLEAN }, config)
        val enroller = Enroller(config, precheck::run, keys, GatewayClient(OkHttpClient(), okhttp3.HttpUrl.Builder().scheme("https").host("enroll.test").build(), {}),
            store, {}, { 1 }, clock::now)
        return DeviceTrustCore(config, store, keys, clock, precheck, enroller)
    }

    @Test
    fun `TrustState is derived from the stored phase and the clock`() {
        val c = core(TrustStore(tmp.root), FakeBackend())
        val enrolled = StoredState(phase = Phase.ENROLLED, active = active)
        assertEquals(TrustState.Active(active.notAfter, active.renewAfter), c.derive(enrolled, t0))
        assertEquals(TrustState.RenewalDue(active.notAfter), c.derive(enrolled, active.renewAfter))
        assertEquals(TrustState.ExpiredGrace(active.notAfter.plusSeconds(7 * 86400)), c.derive(enrolled, active.notAfter))
        assertEquals(TrustState.ReEnrollRequired, c.derive(enrolled, active.notAfter.plusSeconds(7 * 86400)))
        assertEquals(TrustState.NotEnrolled, c.derive(StoredState(), t0))
        assertEquals(TrustState.Blocked(BlockReason.REPLACED), c.derive(StoredState(phase = Phase.BLOCKED, blockReason = "REPLACED"), t0))
        assertEquals(TrustState.Blocked(BlockReason.POLICY), c.derive(StoredState(phase = Phase.BLOCKED, blockReason = "garbage"), t0))
        assertEquals(
            TrustState.UpdateRequired(UpdateKind.OS, "PATCH_TOO_OLD"),
            c.derive(StoredState(phase = Phase.UPDATE_REQUIRED, updateRequired = UpdateRequiredInfo("OS", "PATCH_TOO_OLD", 1, "x")), t0),
        )
    }

    @Test
    fun `initialize cleans orphans, publishes state and credentialsVersion`() {
        val store = TrustStore(tmp.root)
        val backend = FakeBackend()
        listOf("dt.device.k1", "dt.device.k3", "dt.device.k4", "dt.precheck").forEach { backend.keys[it] = SecurityLevel.TRUSTED_ENVIRONMENT }
        store.save(StoredState(phase = Phase.ENROLLED, active = active, credentialsVersion = 5,
            enrolling = Enrolling("e", "dt.device.k4", byteArrayOf(), emptyList(), t0)))
        val c = core(store, backend)
        assertEquals(TrustState.Uninitialized, c.state.value)
        c.initialize()
        assertEquals(listOf("dt.device.k3", "dt.device.k4"), backend.aliases())
        assertTrue(c.state.value is TrustState.Active)
        assertEquals(5, c.credentialsVersion.value)
    }

    @Test
    fun `client credentials only while the certificate is valid`() = runTest {
        val store = TrustStore(tmp.root)
        val backend = FakeBackend()
        backend.generateSigningKey("dt.device.k3", null, false)
        store.writeChain(3, listOf(cert("plain.pem")))
        store.save(StoredState(phase = Phase.ENROLLED, active = active))

        val creds = core(store, backend, now = t0).clientCredentials()
        assertNotNull(creds)
        assertEquals(1, creds!!.chain.size)
        assertNotNull(core(store, backend, now = active.renewAfter).clientCredentials()) // RenewalDue: still valid
        assertNull(core(store, backend, now = active.notAfter).clientCredentials())     // expired
        store.save(StoredState(phase = Phase.BLOCKED, active = active))
        assertNull(core(store, backend).clientCredentials())
    }

    @Test
    fun `network config requires https and two pins, and builds a pinned client`() {
        assertThrows(IllegalArgumentException::class.java) { DeviceTrustConfig().validateForNetwork() }
        assertThrows(IllegalArgumentException::class.java) {
            DeviceTrustConfig("https://enroll.x", "https://app.x", listOf("sha256/AAAA")).validateForNetwork()
        }
        val ok = DeviceTrustConfig("https://enroll.x", "https://app.x", listOf("sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="))
        ok.validateForNetwork()
        val client = HttpClients.pinned(ok)
        assertEquals(4, client.certificatePinner.pins.size) // 2 hosts × 2 pins
    }
}
