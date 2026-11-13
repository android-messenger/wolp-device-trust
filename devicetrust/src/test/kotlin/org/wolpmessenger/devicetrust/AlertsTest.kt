package org.wolpmessenger.devicetrust

import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import okhttp3.mockwebserver.SocketPolicy
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.wolpmessenger.devicetrust.alert.AlertKind
import org.wolpmessenger.devicetrust.alert.AlertQueue
import org.wolpmessenger.devicetrust.alert.AlertSender
import org.wolpmessenger.devicetrust.alert.Alerts
import org.wolpmessenger.devicetrust.api.BlockReason
import org.wolpmessenger.devicetrust.api.DeviceTrustConfig
import org.wolpmessenger.devicetrust.api.PrecheckResult
import org.wolpmessenger.devicetrust.api.RaspFinding
import org.wolpmessenger.devicetrust.api.RaspReaction
import org.wolpmessenger.devicetrust.api.RaspReport
import org.wolpmessenger.devicetrust.api.ReportLimit
import org.wolpmessenger.devicetrust.api.ServerNotice
import org.wolpmessenger.devicetrust.api.SignedOutNotice
import org.wolpmessenger.devicetrust.api.TrustEvent
import org.wolpmessenger.devicetrust.api.TrustState
import org.wolpmessenger.devicetrust.api.UnenrollResult
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
import java.security.Signature
import java.time.Instant
import java.util.Base64
import java.util.concurrent.TimeUnit
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours

/** BLOCK / REPORT / UNENROLL messages, the queue and the sender (S2 §6.5a, §7.4, §8; S3 §5.7). */
class AlertsTest {
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
    private val events = mutableListOf<TrustEvent>()
    private var cookie: String? = null
    private var scheduled = 0
    private var rasp = RaspReport.CLEAN
    private val k1 = ActiveCert("dt.device.k1", "8f3a0b1c2d3e4f50", t0, t0.plusSeconds(72 * 3600), t0.plusSeconds(48 * 3600))
    private val limit = ReportLimit(perCheckWindow = 24.hours, batch = 20, queue = 100)
    private val config = DeviceTrustConfig(reattestGrace = 7.days, cookieProvider = { cookie }, reportRateLimit = limit)

    private val queue by lazy { AlertQueue(tmp.root, limit) }
    private val alerts by lazy { Alerts(queue, store, keys, trustClock::now, { 10300 }, { scheduled++ }) }
    private val gateway by lazy { GatewayClient(OkHttpClient(), server.url("/"), {}, appBase = server.url("/")) }
    private val sender by lazy { AlertSender(queue, alerts, gateway, { cookie }, trustClock::now) }
    private val precheck by lazy { Precheck(keys, FakeEnv(), MemCache(), RaspScanner { rasp }, config) }
    private val enroller by lazy { Enroller(config, precheck::run, keys, gateway, store, { vault.provision() }, { 10300 }, trustClock::now) }
    private val certs by lazy {
        CertManager(config, store, keys, trustClock, gateway, OkHttpClient(), { OkHttpClient() }, vault, enroller,
            { Versions(10300, "2026-10-01") }, { events += it }, { rasp }, alerts)
    }
    private val core by lazy { DeviceTrustCore(config, store, trustClock, precheck, enroller, certs, MutableSharedFlow(extraBufferCapacity = 16), sender) }

    @After
    fun stop() = server.shutdown()

    private fun enrolledWithK1() {
        backend.generateSigningKey(k1.alias, null, false)
        store.writeChain(1, listOf(cert("plain.pem")))
        store.save(StoredState(phase = Phase.ENROLLED, deviceId = "01JDEVICE", active = k1, credentialsVersion = 3))
    }

    private fun take(): RecordedRequest = server.takeRequest(1, TimeUnit.SECONDS)!!
    private fun accepted() = MockResponse().setResponseCode(202)

    /** Decoded request: body JSON and payload JSON; the signature (if any) is checked against [k1]. */
    private fun decode(r: RecordedRequest, signedBy: String? = k1.alias): Pair<JSONObject, JSONObject> {
        assertEquals("/v1/device/alert", r.path)
        val body = JSONObject(r.body.readUtf8())
        val raw = Base64.getDecoder().decode(body.getString("payload"))
        if (signedBy != null) {
            val ok = Signature.getInstance("SHA256withECDSA").run {
                initVerify(backend.pairs.getValue(signedBy).public); update(raw); verify(Base64.getDecoder().decode(body.getString("sig")))
            }
            assertTrue("signature over the exact payload bytes", ok)
        } else {
            assertTrue(body.isNull("sig"))
            assertTrue(body.isNull("certSerial"))
        }
        return body to JSONObject(String(raw))
    }

    private fun blockFinding(id: String = "HOOK_FRIDA_MAPS") = RaspFinding(id, RaspReaction.BLOCK, "frida-agent")

    @Test
    fun `RASP BLOCK - message signed before the wipe, then intent, wipe, event, sender kicked`() = runTest {
        enrolledWithK1()
        certs.raspBlock(listOf(blockFinding()))

        val s = store.load()
        assertEquals(Phase.BLOCKED, s.phase)
        assertEquals("RASP", s.blockReason)
        assertTrue(backend.aliases().isEmpty())
        assertFalse(vault.present)
        assertEquals(listOf(TrustEvent.Blocked(BlockReason.RASP)), events)
        assertEquals(1, scheduled)

        // delivered after the keys are gone — the signature was made before
        server.enqueue(accepted())
        assertEquals(0, sender.sendAll())
        val (body, p) = decode(take())
        assertEquals("8f3a0b1c2d3e4f50", body.getString("certSerial"))
        assertEquals(1, p.getInt("v"))
        assertEquals("BLOCK", p.getString("kind"))
        assertEquals("01JDEVICE", p.getString("deviceId"))
        assertEquals("8f3a0b1c2d3e4f50", p.getString("certSerial"))
        assertEquals("2026-11-08T10:00:00Z", p.getString("ts"))
        assertEquals(10300, p.getLong("appVersionCode"))
        val c = p.getJSONArray("checks").getJSONObject(0)
        assertEquals("HOOK_FRIDA_MAPS", c.getString("id"))
        assertEquals("frida-agent", c.getString("detail"))
        assertTrue(queue.isEmpty())
    }

    @Test
    fun `a repeated BLOCK does not queue a second (unsigned) message`() = runTest {
        enrolledWithK1()
        certs.raspBlock(listOf(blockFinding()))
        certs.raspBlock(listOf(blockFinding("DEBUGGER")))
        assertEquals(1, queue.list().size)
    }

    @Test
    fun `BLOCK before enrollment is unsigned and waits for a Kratos cookie`() = runTest {
        certs.raspBlock(listOf(blockFinding()))
        assertEquals(Phase.BLOCKED, store.load().phase)

        assertEquals("no cookie: not sent", 1, sender.sendAll())
        assertEquals(0, server.requestCount)

        cookie = "ory_kratos_session=abc"
        server.enqueue(accepted())
        assertEquals(0, sender.sendAll())
        val r = take()
        assertEquals("ory_kratos_session=abc", r.getHeader("Cookie"))
        val (_, p) = decode(r, signedBy = null)
        assertTrue(p.isNull("deviceId"))
        assertTrue(p.isNull("certSerial"))
    }

    @Test
    fun `signed messages are sent without the cookie`() = runTest {
        enrolledWithK1()
        cookie = "ory_kratos_session=abc"
        certs.raspBlock(listOf(blockFinding()))
        server.enqueue(accepted())
        sender.sendAll()
        assertNull(take().getHeader("Cookie"))
    }

    @Test
    fun `sender - network error and 5xx keep the queue, 400 drops, older than 7 days dropped`() = runTest {
        enrolledWithK1()
        alerts.enqueue(AlertKind.REPORT, listOf(RaspFinding("DEV_OPTIONS", RaspReaction.REPORT)))
        alerts.enqueue(AlertKind.REPORT, listOf(RaspFinding("ADB_ENABLED", RaspReaction.REPORT)))

        server.enqueue(MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AT_START))
        assertEquals(2, sender.sendAll())
        server.enqueue(MockResponse().setResponseCode(503))
        assertEquals("stops at the first failure", 2, sender.sendAll())
        server.enqueue(MockResponse().setResponseCode(429).setHeader("Retry-After", "5"))
        assertEquals(2, sender.sendAll())

        server.enqueue(MockResponse().setResponseCode(400).setBody("""{"error":"BAD_REQUEST"}"""))
        server.enqueue(accepted())
        assertEquals(0, sender.sendAll())

        alerts.enqueue(AlertKind.REPORT, listOf(RaspFinding("DEV_OPTIONS", RaspReaction.REPORT)))
        clock.set(t0.plusSeconds(7 * 86400 + 1))
        val before = server.requestCount
        assertEquals(0, sender.sendAll())
        assertEquals("expired message is not sent", before, server.requestCount)
    }

    @Test
    fun `REPORT - one per (id, detail) per 24 h, batched by 20, queue capped at 100`() = runTest {
        enrolledWithK1()
        val f = RaspFinding("DEV_OPTIONS", RaspReaction.REPORT, "on")
        alerts.report(listOf(f, f))
        alerts.report(listOf(f))
        assertEquals("scheduled once: the rest was rate-limited", 1, scheduled)
        alerts.report(listOf(f.copy(detail = "other")))
        assertEquals(2, scheduled)

        clock.set(t0.plusSeconds(24 * 3600 + 1))
        alerts.report(listOf(f))
        assertEquals("allowed again after the window", 3, scheduled)

        // 3 pending so far + 130 distinct → capped at 100, sent as 5 messages of ≤ 20
        alerts.report((1..130).map { RaspFinding("ROOT_MANAGER_PKG", RaspReaction.REPORT, "pkg$it") })
        repeat(5) { server.enqueue(accepted()) }
        assertEquals(0, sender.sendAll())
        assertEquals(5, server.requestCount)
        val sent = (1..5).flatMap { _ ->
            val (_, p) = decode(take())
            assertEquals("REPORT", p.getString("kind"))
            val a = p.getJSONArray("checks")
            assertTrue(a.length() <= 20)
            List(a.length()) { a.getJSONObject(it).getString("detail") }
        }
        assertEquals(100, sent.size)
        assertEquals("the oldest were dropped", "pkg130", sent.last())
    }

    @Test
    fun `unenroll with a key - signed UNENROLL queued first, everything wiped, NotEnrolled`() = runTest {
        enrolledWithK1()
        assertEquals(UnenrollResult.Ok(ServerNotice.PENDING), core.unenroll())

        val s = store.load()
        assertEquals(Phase.NOT_ENROLLED, s.phase)
        assertNull(s.deviceId)
        assertNull(s.active)
        assertEquals(4, s.credentialsVersion)
        assertTrue(backend.aliases().isEmpty())
        assertFalse(vault.present)
        assertEquals(TrustState.NotEnrolled, core.state.value)

        server.enqueue(accepted())
        assertEquals(0, core.sendAlerts())
        val (_, p) = decode(take())
        assertEquals("UNENROLL", p.getString("kind"))
        assertEquals(0, p.getJSONArray("checks").length())
    }

    @Test
    fun `unenroll without a key or when blocked - nothing to notify, local part still done`() = runTest {
        store.save(StoredState(phase = Phase.RE_ENROLL_REQUIRED, deviceId = "01JDEVICE"))
        assertEquals(UnenrollResult.Ok(ServerNotice.NOT_NEEDED), core.unenroll())
        assertEquals(Phase.NOT_ENROLLED, store.load().phase)
        assertFalse("Vault wiped", vault.present)
        assertTrue(queue.isEmpty())

        store.save(StoredState(phase = Phase.BLOCKED, blockReason = "RASP"))
        assertEquals(UnenrollResult.Ok(ServerNotice.NOT_NEEDED), core.unenroll())
        assertEquals("Blocked is final", Phase.BLOCKED, store.load().phase)
    }

    @Test
    fun `interrupted unenroll is finished at start, the queued UNENROLL survives`() = runTest {
        enrolledWithK1()
        alerts.enqueue(AlertKind.UNENROLL)
        store.update { it.copy(phase = Phase.UNENROLLING) } // crash before the wipe
        core.initialize()
        assertEquals(TrustState.NotEnrolled, core.state.value)
        assertTrue(backend.aliases().isEmpty())
        assertEquals(1, queue.list().size)
    }

    @Test
    fun `UNENROLL is never queued unsigned`() {
        assertFalse(alerts.enqueue(AlertKind.UNENROLL))
        assertTrue(queue.isEmpty())
    }

    // --- sign-out the server did not hear about (docs specs F5, part 2) ---

    @Test
    fun `signed-out - a fresh message signed by the device key, no cookie, the device stays enrolled`() = runTest {
        enrolledWithK1()
        cookie = "ory_kratos_session=s"
        server.enqueue(accepted())
        assertEquals(SignedOutNotice.DELIVERED, core.reportSignedOut())

        val r = take()
        assertEquals("/v1/device/signed-out", r.path)
        assertNull("the signature is the only credential", r.getHeader("Cookie"))
        val body = JSONObject(r.body.readUtf8())
        val raw = Base64.getDecoder().decode(body.getString("payload"))
        val ok = Signature.getInstance("SHA256withECDSA").run {
            initVerify(backend.pairs.getValue(k1.alias).public); update(raw); verify(Base64.getDecoder().decode(body.getString("sig")))
        }
        assertTrue("signature over the exact payload bytes", ok)
        assertEquals(k1.serialHex, body.getString("certSerial"))
        val p = JSONObject(String(raw))
        assertEquals(setOf("v", "kind", "deviceId", "certSerial", "ts"), p.keys().asSequence().toSet())
        assertEquals(1, p.getInt("v"))
        assertEquals("SIGNED_OUT", p.getString("kind"))
        assertEquals("01JDEVICE", p.getString("deviceId"))
        assertEquals(k1.serialHex, p.getString("certSerial"))
        assertEquals(t0, Instant.parse(p.getString("ts")))

        assertEquals(Phase.ENROLLED, store.load().phase)
        assertEquals(setOf(k1.alias), backend.aliases().toSet())
        assertTrue("nothing is queued: the message is good for minutes only", queue.isEmpty())

        // every attempt is signed anew, with the time of that attempt
        clock.set(t0.plusSeconds(3600))
        server.enqueue(accepted())
        assertEquals(SignedOutNotice.DELIVERED, core.reportSignedOut())
        val again = JSONObject(String(Base64.getDecoder().decode(JSONObject(take().body.readUtf8()).getString("payload"))))
        assertEquals(t0.plusSeconds(3600), Instant.parse(again.getString("ts")))
    }

    @Test
    fun `signed-out - 404 and 400 end the cleanup, anything else asks for another try`() = runTest {
        enrolledWithK1()
        server.enqueue(MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AT_START)) // first: it acts on a new connection only
        assertEquals("no network", SignedOutNotice.RETRY, core.reportSignedOut())
        server.enqueue(MockResponse().setResponseCode(404))
        assertEquals(SignedOutNotice.UNSUPPORTED, core.reportSignedOut())
        server.enqueue(MockResponse().setResponseCode(400).setBody("""{"error":"BAD_REQUEST"}"""))
        assertEquals(SignedOutNotice.UNSUPPORTED, core.reportSignedOut())
        for (code in listOf(429, 500, 503)) {
            server.enqueue(MockResponse().setResponseCode(code))
            assertEquals("HTTP $code", SignedOutNotice.RETRY, core.reportSignedOut())
        }
        assertTrue(SignedOutNotice.DELIVERED.done && SignedOutNotice.UNSUPPORTED.done && SignedOutNotice.NOT_NEEDED.done)
        assertFalse(SignedOutNotice.RETRY.done)
    }

    @Test
    fun `signed-out - without a device key nothing is sent`() = runTest {
        assertEquals("not enrolled", SignedOutNotice.NOT_NEEDED, core.reportSignedOut())
        store.save(StoredState(phase = Phase.ENROLLED, deviceId = "01JDEVICE", active = k1)) // the key is not in the keystore
        assertEquals("key lost", SignedOutNotice.NOT_NEEDED, core.reportSignedOut())
        assertEquals(0, server.requestCount)
    }

    @Test
    fun `precheck BLOCK finding runs the BLOCK reaction`() = runTest {
        enrolledWithK1()
        rasp = RaspReport(listOf(blockFinding("ROOT_SU")))
        assertTrue(core.precheck() is PrecheckResult.Compromised)
        assertEquals(TrustState.Blocked(BlockReason.RASP), core.state.value)
        assertEquals(1, queue.list().size)
    }

    @Test
    fun `renewal runs RASP first and blocks with a signed message`() = runTest {
        enrolledWithK1()
        clock.set(k1.renewAfter.plusSeconds(1))
        rasp = RaspReport(listOf(blockFinding("DEBUGGER")))
        assertEquals(TrustState.Blocked(BlockReason.RASP), certs.ensureFresh())
        assertEquals(0, server.requestCount)
        server.enqueue(accepted())
        sender.sendAll()
        val (_, p) = decode(take())
        assertEquals("DEBUGGER", p.getJSONArray("checks").getJSONObject(0).getString("id"))
    }

    // ---------------------------------------------------------------- specs/001-rasp-hardening, story 1

    @Test
    fun `sender - a message refused for itself does not hold back the BLOCK behind it`() = runTest {
        // an unsigned REPORT from before enrollment, then enrollment and a signed BLOCK
        alerts.enqueue(AlertKind.REPORT, listOf(RaspFinding("DEV_OPTIONS", RaspReaction.REPORT)))
        clock.set(t0.plusSeconds(1))
        enrolledWithK1()
        certs.raspBlock(listOf(blockFinding()))
        cookie = "ory_kratos_session=expired"

        server.enqueue(MockResponse().setResponseCode(401).setHeader("X-Device-Deny", "NO_SESSION"))
        server.enqueue(accepted())
        assertEquals("the refused one stays for a later pass", 1, sender.sendAll())
        decode(take(), signedBy = null)
        val (_, p) = decode(take())
        assertEquals("BLOCK", p.getString("kind"))
        assertEquals(AlertKind.REPORT, queue.list().single().kind)
    }

    @Test
    fun `BLOCK still wipes when the message cannot be queued`() = runTest {
        enrolledWithK1()
        val broken = object : org.wolpmessenger.devicetrust.alert.AlertSink {
            override fun enqueue(kind: AlertKind, checks: List<RaspFinding>): Boolean = throw java.io.IOException("disk full")
            override fun report(findings: List<RaspFinding>) = Unit
            override fun schedule(): Unit = throw IllegalStateException("no WorkManager")
        }
        val c = CertManager(config, store, keys, trustClock, gateway, OkHttpClient(), { OkHttpClient() }, vault, enroller,
            { Versions(10300, "2026-10-01") }, { events += it }, { rasp }, broken)
        c.raspBlock(listOf(blockFinding()))
        assertEquals(Phase.BLOCKED, store.load().phase)
        assertNull(store.load().active)
        assertTrue("device keys are gone", keys.deviceKeyAliases().isEmpty())
        assertEquals(listOf<TrustEvent>(TrustEvent.Blocked(BlockReason.RASP)), events)
    }

    @Test
    fun `overlapping RASP passes run the BLOCK reaction once`() = runTest {
        enrolledWithK1()
        val blocking = RaspReport(listOf(blockFinding()))
        val c = DeviceTrustCore(config, store, trustClock, precheck, enroller, certs, MutableSharedFlow(extraBufferCapacity = 16), sender, rasp = { blocking })
        c.checkIntegrity()
        c.checkIntegrity()
        assertEquals(1, events.size)
        assertEquals(1, queue.list().size)
    }

    @Test
    fun `a damaged state file does not throw - it is set aside and the device starts over`() {
        enrolledWithK1()
        val file = java.io.File(tmp.root, "state.json")
        file.writeText("{\"v\":1,\"phase\":\"ENROL")
        assertEquals(Phase.NOT_ENROLLED, store.load().phase)
        assertFalse(file.exists())
        assertTrue(java.io.File(tmp.root, "state.json.corrupt").exists())

        file.writeText("{\"v\":1,\"phase\":\"NO_SUCH_PHASE\"}")
        assertEquals(Phase.NOT_ENROLLED, store.load().phase)
        store.update { it.copy(deviceId = "x") } // usable again
        assertEquals("x", store.load().deviceId)
    }
}
