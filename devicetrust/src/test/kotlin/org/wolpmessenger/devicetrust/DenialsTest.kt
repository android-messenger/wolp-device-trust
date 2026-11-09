package org.wolpmessenger.devicetrust

import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.test.runTest
import okhttp3.CertificatePinner
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import okhttp3.mockwebserver.SocketPolicy
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.wolpmessenger.devicetrust.alert.AlertQueue
import org.wolpmessenger.devicetrust.alert.Alerts
import org.wolpmessenger.devicetrust.api.BindingFailure
import org.wolpmessenger.devicetrust.api.BlockReason
import org.wolpmessenger.devicetrust.api.DenySource
import org.wolpmessenger.devicetrust.api.DenySource.PINNED_CLIENT
import org.wolpmessenger.devicetrust.api.DenySource.WEBVIEW
import org.wolpmessenger.devicetrust.api.DeviceTrustConfig
import org.wolpmessenger.devicetrust.api.GatewayCode
import org.wolpmessenger.devicetrust.api.RaspReport
import org.wolpmessenger.devicetrust.api.ReportLimit
import org.wolpmessenger.devicetrust.api.SessionBinding
import org.wolpmessenger.devicetrust.api.TrustState
import org.wolpmessenger.devicetrust.api.UpdateKind
import org.wolpmessenger.devicetrust.attest.Precheck
import org.wolpmessenger.devicetrust.attest.RaspScanner
import org.wolpmessenger.devicetrust.cert.CertManager
import org.wolpmessenger.devicetrust.cert.Versions
import org.wolpmessenger.devicetrust.clock.TrustClock
import org.wolpmessenger.devicetrust.enroll.Enroller
import org.wolpmessenger.devicetrust.keys.KeystoreKeys
import org.wolpmessenger.devicetrust.net.GatewayClient
import org.wolpmessenger.devicetrust.store.ActiveCert
import org.wolpmessenger.devicetrust.store.Phase
import org.wolpmessenger.devicetrust.store.StoredState
import org.wolpmessenger.devicetrust.store.TrustStore
import org.wolpmessenger.devicetrust.tls.DeviceHttp
import java.time.Instant
import java.util.Base64
import java.util.concurrent.TimeUnit
import kotlin.time.Duration.Companion.days

/** S2 §5.3: gateway denials by source, the WEBVIEW check via ping, whoami (S3 §5.8a, §5.8c), S2 §15 п. 7. */
class DenialsTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private val server = MockWebServer().apply { start() }
    private val backend = FakeBackend()
    private val keys = KeystoreKeys(backend)
    private val store by lazy { TrustStore(tmp.root) }
    private val t0 = Instant.parse("2026-11-08T10:00:00Z")
    private val clock = MutableClock(t0.toEpochMilli())
    private val trustClock = TrustClock(clock)
    private val vault = FakeVault()
    private var monotonic = 0L
    private val k1 = ActiveCert("dt.device.k1", "8f3a0b1c2d3e4f50", t0, t0.plusSeconds(72 * 3600), t0.plusSeconds(48 * 3600))
    private val config = DeviceTrustConfig(reattestGrace = 7.days)
    private val b64 = Base64.getEncoder()

    private fun core(app: OkHttpClient = OkHttpClient(), base: okhttp3.HttpUrl = server.url("/")): DeviceTrustCore {
        val gateway = GatewayClient(app, base, {}, appBase = base)
        val precheck = Precheck(keys, FakeEnv(), MemCache(), RaspScanner { RaspReport.CLEAN }, config)
        val enroller = Enroller(config, precheck::run, keys, gateway, store, { vault.provision() }, { 10300 }, trustClock::now)
        val alerts = Alerts(AlertQueue(tmp.root, ReportLimit()), store, keys, trustClock::now, { 10300 }, {})
        val certs = CertManager(config, store, keys, trustClock, gateway, app, { app }, vault, enroller,
            { Versions(10300, "2026-10-01") }, {}, { RaspReport.CLEAN }, alerts)
        return DeviceTrustCore(config, store, trustClock, precheck, enroller, certs, MutableSharedFlow(extraBufferCapacity = 16),
            appClient = { app }, gateway = gateway, monotonicMs = { monotonic })
    }

    /** k1 with a certificate that matches the fake Keystore key (TLS-usable). */
    private fun enrolledWithK1() {
        backend.generateSigningKey(k1.alias, null, false)
        val leaf = HeldCertificate.Builder().keyPair(backend.pairs.getValue(k1.alias)).commonName("k1").serialNumber(0x8f3a0b1c2d3e4f50uL.toLong()).build()
        store.writeChain(1, listOf(leaf.certificate))
        store.save(StoredState(phase = Phase.ENROLLED, deviceId = "01JDEVICE", active = k1, credentialsVersion = 3))
    }

    @After
    fun stop() = server.shutdown()

    private fun take(): RecordedRequest = server.takeRequest(1, TimeUnit.SECONDS)!!
    private fun deny(code: String) = MockResponse().setResponseCode(403).setHeader("X-Device-Deny", code)
    private val active get() = TrustState.Active(k1.notAfter, k1.renewAfter)

    @Test
    fun `WEBVIEW destructive code not confirmed by ping changes nothing`() = runTest {
        enrolledWithK1()
        val c = core().apply { initialize() }
        server.enqueue(MockResponse().setResponseCode(204))
        assertEquals(active, c.onGatewayDenied(GatewayCode.DEVICE_REVOKED, WEBVIEW))
        assertEquals("/v1/device/ping", take().path)
        assertEquals(listOf(k1.alias), backend.aliases())
        assertTrue(vault.present)
    }

    @Test
    fun `WEBVIEW destructive code confirmed by ping blocks - the action follows the ping code`() = runTest {
        enrolledWithK1()
        val c = core().apply { initialize() }
        server.enqueue(deny("DEVICE_REPLACED"))
        assertEquals(TrustState.Blocked(BlockReason.REPLACED), c.onGatewayDenied(GatewayCode.DEVICE_REVOKED, WEBVIEW))
        assertTrue(backend.aliases().isEmpty())
        assertFalse(vault.present)
        assertTrue("no message for a gateway-side revocation (S2 §8)", AlertQueue(tmp.root, ReportLimit()).isEmpty())
    }

    @Test
    fun `WEBVIEW checks are rate-limited to one per 30 s`() = runTest {
        enrolledWithK1()
        val c = core().apply { initialize() }
        server.enqueue(MockResponse().setResponseCode(204))
        c.onGatewayDenied(GatewayCode.DEVICE_REVOKED, WEBVIEW)
        monotonic += 29_000
        c.onGatewayDenied(GatewayCode.CERT_INVALID, WEBVIEW)
        assertEquals(1, server.requestCount)
        monotonic += 1_000
        server.enqueue(MockResponse().setResponseCode(204))
        c.onGatewayDenied(GatewayCode.CERT_INVALID, WEBVIEW)
        assertEquals(2, server.requestCount)
    }

    @Test
    fun `WEBVIEW - failed ping (network or pinning) deletes nothing`() = runTest {
        enrolledWithK1()
        val c = core().apply { initialize() }
        server.enqueue(MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AT_START))
        assertEquals(active, c.onGatewayDenied(GatewayCode.IDENTITY_REVOKED, WEBVIEW))
        assertEquals(listOf(k1.alias), backend.aliases())
    }

    @Test
    fun `WEBVIEW NO_SESSION, USER_MISMATCH, RATE_LIMITED, UNKNOWN trigger nothing`() = runTest {
        enrolledWithK1()
        val c = core().apply { initialize() }
        for (code in listOf(GatewayCode.NO_SESSION, GatewayCode.USER_MISMATCH, GatewayCode.RATE_LIMITED, GatewayCode.UNKNOWN)) {
            assertEquals(active, c.onGatewayDenied(code, WEBVIEW))
        }
        assertEquals(0, server.requestCount)
    }

    @Test
    fun `WEBVIEW UPDATE_REQUIRED is only checked - ping 204 leaves the state`() = runTest {
        enrolledWithK1()
        val c = core().apply { initialize() }
        server.enqueue(MockResponse().setResponseCode(204))
        assertEquals(active, c.onGatewayDenied(GatewayCode.UPDATE_REQUIRED, WEBVIEW))
    }

    @Test
    fun `WEBVIEW without a valid certificate brings it up to date instead of pinging`() = runTest {
        enrolledWithK1()
        clock.set(k1.notAfter.plusSeconds(60)) // ExpiredGrace
        val c = core().apply { initialize() }
        server.enqueue(MockResponse().setResponseCode(503))
        c.onGatewayDenied(GatewayCode.CERT_EXPIRED, WEBVIEW)
        assertEquals("/v1/device/reattest/challenge", take().path)
    }

    @Test
    fun `PINNED codes act without a check`() = runTest {
        enrolledWithK1()
        val c = core().apply { initialize() }
        assertEquals(active, c.onGatewayDenied(GatewayCode.USER_MISMATCH, PINNED_CLIENT))
        assertEquals(active, c.onGatewayDenied(GatewayCode.CERT_INVALID, PINNED_CLIENT)) // Active: ensureFresh does nothing
        assertEquals(TrustState.UpdateRequired(UpdateKind.OS, "PATCH_TOO_OLD"), c.onGatewayDenied(GatewayCode.UPDATE_REQUIRED, PINNED_CLIENT, "PATCH_TOO_OLD"))
        assertEquals(listOf(k1.alias), backend.aliases())
        assertEquals(0, server.requestCount)
        assertEquals(TrustState.Blocked(BlockReason.POLICY), c.onGatewayDenied(GatewayCode.DEVICE_POLICY, PINNED_CLIENT))
        assertTrue(backend.aliases().isEmpty())
    }

    @Test
    fun `PINNED CERT_SUPERSEDED recovers with the current key`() = runTest {
        enrolledWithK1()
        val c = core().apply { initialize() }
        server.enqueue(MockResponse().setResponseCode(503))
        c.onGatewayDenied(GatewayCode.CERT_SUPERSEDED, PINNED_CLIENT)
        val r = take()
        assertEquals("/v1/device/reattest/challenge", r.path)
        assertTrue(r.body.readUtf8().contains(k1.serialHex))
    }

    @Test
    fun `PINNED denials do not touch a device that is not enrolled, except destructive ones`() = runTest {
        val c = core().apply { initialize() }
        assertEquals(TrustState.NotEnrolled, c.onGatewayDenied(GatewayCode.UPDATE_REQUIRED, PINNED_CLIENT, "APP_VERSION_TOO_OLD"))
        assertEquals(TrustState.Blocked(BlockReason.IDENTITY_REVOKED), c.onGatewayDenied(GatewayCode.IDENTITY_REVOKED, PINNED_CLIENT))
    }

    @Test
    fun `whoami - match, mismatch, no session, with the cookie`() = runTest {
        enrolledWithK1()
        val c = core().apply { initialize() }
        for ((session, expected) in listOf("match" to SessionBinding.Match, "mismatch" to SessionBinding.Mismatch, "none" to SessionBinding.NoSession)) {
            server.enqueue(MockResponse().setBody("""{"deviceId":"01JDEVICE","session":"$session"}"""))
            assertEquals(expected, c.checkSessionBinding("ory_kratos_session=s"))
            val r = take()
            assertEquals("/v1/device/whoami", r.path)
            assertEquals("ory_kratos_session=s", r.getHeader("Cookie"))
        }
    }

    @Test
    fun `whoami - no credentials, network failure, and a denial handled as pinned`() = runTest {
        assertEquals(SessionBinding.Failed(BindingFailure.NO_CREDENTIALS), core().apply { initialize() }.checkSessionBinding("c"))

        enrolledWithK1()
        val c = core().apply { initialize() }
        server.enqueue(MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AT_START))
        assertEquals(SessionBinding.Failed(BindingFailure.NETWORK), c.checkSessionBinding("c"))
        server.enqueue(deny("DEVICE_REVOKED"))
        assertEquals(SessionBinding.Failed(BindingFailure.DENIED, GatewayCode.DEVICE_REVOKED), c.checkSessionBinding("c"))
        assertEquals(TrustState.Blocked(BlockReason.REVOKED), c.state.value)
    }

    /**
     * S2 §15 п. 7 over real TLS and the real pinned client: a server with a certificate from a
     * CA the device trusts, but a different key, answers `DEVICE_REVOKED` to everything. From the
     * WebView that code only triggers a ping; the ping fails on pinning — keys stay. The same code
     * from the genuine (pinned) server deletes them.
     */
    @Test
    fun `fake server - WEBVIEW DEVICE_REVOKED keeps the keys, the genuine pinned server deletes them`() = runTest {
        enrolledWithK1()
        val ca = HeldCertificate.Builder().certificateAuthority(0).commonName("Public CA").build()
        val genuine = HeldCertificate.Builder().signedBy(ca).addSubjectAlternativeName("localhost").commonName("app").build()
        val fake = HeldCertificate.Builder().signedBy(ca).addSubjectAlternativeName("localhost").commonName("app").build()
        val trust = HandshakeCertificates.Builder().addTrustedCertificate(ca.certificate).build()

        fun tlsServer(held: HeldCertificate) = MockWebServer().apply {
            useHttps(HandshakeCertificates.Builder().heldCertificate(held, ca.certificate).build().sslSocketFactory(), false)
            repeat(3) { enqueue(deny("DEVICE_REVOKED")) }
            start()
        }

        for ((held, expectBlocked) in listOf(fake to false, genuine to true)) {
            val s = tlsServer(held)
            try {
                val base = s.url("/")
                val cfg = DeviceTrustConfig(
                    enrollBaseUrl = base.toString().trimEnd('/'), appBaseUrl = base.toString().trimEnd('/'),
                    serverPins = listOf(CertificatePinner.pin(genuine.certificate), "sha256/" + b64.encodeToString(ByteArray(32))),
                )
                val http = DeviceHttp(cfg, current = { null }, onServerDate = {}, trustManager = trust.trustManager)
                val st = core(http.client, base).apply { initialize() }.onGatewayDenied(GatewayCode.DEVICE_REVOKED, DenySource.WEBVIEW)
                if (expectBlocked) {
                    assertEquals(TrustState.Blocked(BlockReason.REVOKED), st)
                    assertTrue(backend.aliases().isEmpty())
                } else {
                    assertEquals(active, st)
                    assertEquals("pinning failed before any HTTP exchange", 0, s.requestCount)
                    assertEquals(listOf(k1.alias), backend.aliases())
                }
            } finally {
                s.shutdown()
            }
        }
    }
}
