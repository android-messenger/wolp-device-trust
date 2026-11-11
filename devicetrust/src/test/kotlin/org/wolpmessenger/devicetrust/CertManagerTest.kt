package org.wolpmessenger.devicetrust

import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import okhttp3.mockwebserver.SocketPolicy
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.wolpmessenger.devicetrust.api.BlockReason
import org.wolpmessenger.devicetrust.api.DeviceTrustConfig
import org.wolpmessenger.devicetrust.api.RaspReport
import org.wolpmessenger.devicetrust.api.TrustEvent
import org.wolpmessenger.devicetrust.api.TrustState
import org.wolpmessenger.devicetrust.api.UpdateKind
import org.wolpmessenger.devicetrust.attest.Precheck
import org.wolpmessenger.devicetrust.attest.RaspScanner
import org.wolpmessenger.devicetrust.cert.CertManager
import org.wolpmessenger.devicetrust.cert.ContinuitySig
import org.wolpmessenger.devicetrust.cert.Versions
import org.wolpmessenger.devicetrust.clock.TrustClock
import org.wolpmessenger.devicetrust.enroll.Enroller
import org.wolpmessenger.devicetrust.keys.KeystoreKeys
import org.wolpmessenger.devicetrust.net.GatewayClient
import org.wolpmessenger.devicetrust.rasp.RaspSummarySource
import org.wolpmessenger.devicetrust.rasp.RaspSummaryStore
import org.wolpmessenger.devicetrust.api.RaspFinding
import org.wolpmessenger.devicetrust.api.RaspReaction
import java.security.MessageDigest
import org.wolpmessenger.devicetrust.store.ActiveCert
import org.wolpmessenger.devicetrust.store.Enrolling
import org.wolpmessenger.devicetrust.store.Phase
import org.wolpmessenger.devicetrust.store.StoredState
import org.wolpmessenger.devicetrust.store.TrustStore
import org.wolpmessenger.devicetrust.store.UpdateRequiredInfo
import java.math.BigInteger
import java.security.Signature
import java.time.Instant
import java.util.Base64
import java.util.concurrent.TimeUnit
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes

class CertManagerTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private val server = MockWebServer().apply { start() }
    private val backend = FakeBackend()
    private val keys = KeystoreKeys(backend)
    private val store by lazy { TrustStore(tmp.root) }
    private val t0 = Instant.parse("2026-11-08T10:00:00Z")
    private val clock = MutableClock(t0.toEpochMilli())
    private val vault = FakeVault()
    private val events = mutableListOf<TrustEvent>()
    private var versions = Versions(10300, "2026-10-01")
    private var cookie: String? = null
    private val issuedCert = cert("plain.pem")
    private val nonce = ByteArray(32) { 3 }
    private val b64 = Base64.getEncoder()

    // k1 issued at t0: renewAfter +48h, notAfter +72h
    private val k1 = ActiveCert("dt.device.k1", "8f3a0b1c2d3e4f50", t0, t0.plusSeconds(72 * 3600), t0.plusSeconds(48 * 3600))

    private val config = DeviceTrustConfig(reattestGrace = 7.days, enrollReplayTtl = 15.minutes, cookieProvider = { cookie })

    /** mTLS client stand-in: tags every request with the alias of the presented key. */
    private fun mtlsFor(creds: org.wolpmessenger.devicetrust.api.ClientCredentials): OkHttpClient {
        val alias = backend.pairs.entries.first { it.value.private == creds.privateKey }.key
        return OkHttpClient.Builder().addInterceptor { it.proceed(it.request().newBuilder().header("X-Test-Key", alias).build()) }.build()
    }

    private fun manager(summary: RaspSummarySource = RaspSummarySource.None): CertManager {
        val trustClock = TrustClock(clock)
        val gateway = GatewayClient(OkHttpClient(), server.url("/"), {}, appBase = server.url("/"))
        val precheck = Precheck(keys, FakeEnv(), MemCache(), RaspScanner { RaspReport.CLEAN }, config)
        val enroller = Enroller(config, precheck::run, keys, gateway, store, { vault.provision() }, { 10300 }, trustClock::now)
        return CertManager(config, store, keys, trustClock, gateway, OkHttpClient(), ::mtlsFor, vault, enroller, { versions }, { events += it }, summary = summary)
    }

    private fun enrolledWithK1(): StoredState {
        backend.generateSigningKey(k1.alias, null, false)
        store.writeChain(1, listOf(issuedCert))
        val s = StoredState(phase = Phase.ENROLLED, deviceId = "01JDEVICE", active = k1, credentialsVersion = 3)
        store.save(s)
        return s
    }

    @After
    fun stop() = server.shutdown()

    private fun challenge() = MockResponse().setBody("""{"nonce":"${b64.encodeToString(nonce)}","expiresAt":"2026-11-10T10:05:00Z"}""")
    private fun issued(notBefore: Instant) = MockResponse().setBody(
        """{"certChain":["${b64.encodeToString(issuedCert.encoded)}"],"notBefore":"$notBefore",
           "notAfter":"${notBefore.plusSeconds(72 * 3600)}","renewAfter":"${notBefore.plusSeconds(48 * 3600)}"}""",
    )
    private fun refused(code: Int, body: String) = MockResponse().setResponseCode(code).setBody(body)
    private fun take(): RecordedRequest = server.takeRequest(1, TimeUnit.SECONDS)!!

    @Test
    fun `renewal follows S2 §6_3 - old key for challenge and renew, new key for confirm`() = runTest {
        enrolledWithK1()
        clock.set(k1.renewAfter.plusSeconds(1))
        server.enqueue(challenge())
        server.enqueue(issued(clock.nowMs.let(Instant::ofEpochMilli)))
        server.enqueue(MockResponse().setResponseCode(204))

        val st = manager().ensureFresh()

        assertTrue(st is TrustState.Active)
        val ch = take()
        assertEquals("/v1/device/renew/challenge", ch.path)
        assertEquals("dt.device.k1", ch.getHeader("X-Test-Key"))
        val renew = take()
        assertEquals("/v1/device/renew", renew.path)
        assertEquals("dt.device.k1", renew.getHeader("X-Test-Key"))
        val confirm = take()
        assertEquals("/v1/device/renew/confirm", confirm.path)
        assertEquals("dt.device.k2", confirm.getHeader("X-Test-Key"))

        // continuitySig: signed by k1 over the S3 §5.4 payload for k2 and its chain
        val body = JSONObject(renew.body.readUtf8())
        val chain = body.getJSONArray("attestationChain").let { a -> List(a.length()) { Base64.getDecoder().decode(a.getString(it)) } }
        val payload = ContinuitySig.payload(ContinuitySig.RENEW, "01JDEVICE", BigInteger(k1.serialHex, 16), nonce,
            backend.pairs.getValue("dt.device.k2").public.encoded, chain)
        val sigOk = Signature.getInstance("SHA256withECDSA").run {
            initVerify(backend.pairs.getValue("dt.device.k1").public); update(payload); verify(Base64.getDecoder().decode(body.getString("continuitySig")))
        }
        assertTrue(sigOk)
        assertTrue("new key is bound to the nonce", backend.challenges.getValue("dt.device.k2").contentEquals(nonce))

        val s = store.load()
        assertEquals("dt.device.k2", s.active?.alias)
        assertNull(s.pending)
        assertEquals(4, s.credentialsVersion)
        assertEquals(listOf("dt.device.k2"), backend.aliases())
        assertNull(store.readChain(1))
        assertNotNull(store.readChain(2))
    }

    @Test
    fun `nothing happens while Active`() = runTest {
        enrolledWithK1()
        assertTrue(manager().ensureFresh() is TrustState.Active)
        assertEquals(0, server.requestCount)
    }

    @Test
    fun `lost renew response deletes the new key and keeps the old certificate`() = runTest {
        enrolledWithK1()
        clock.set(k1.renewAfter.plusSeconds(1))
        server.enqueue(challenge())
        server.enqueue(MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AFTER_REQUEST))
        assertTrue(manager().ensureFresh() is TrustState.RenewalDue)
        assertEquals(listOf("dt.device.k1"), backend.aliases())
        assertEquals("dt.device.k1", store.load().active?.alias)
        assertNull(store.load().pending)
    }

    @Test
    fun `NONCE_INVALID is retried once`() = runTest {
        enrolledWithK1()
        clock.set(k1.renewAfter.plusSeconds(1))
        server.enqueue(challenge())
        server.enqueue(refused(403, """{"error":"NONCE_INVALID"}"""))
        server.enqueue(challenge())
        server.enqueue(issued(Instant.ofEpochMilli(clock.nowMs)))
        server.enqueue(MockResponse().setResponseCode(204))
        assertTrue(manager().ensureFresh() is TrustState.Active)
        assertEquals(5, server.requestCount)
    }

    @Test
    fun `UPDATE_REQUIRED keeps the keys and is lifted after an update`() = runTest {
        enrolledWithK1()
        clock.set(k1.renewAfter.plusSeconds(1))
        server.enqueue(challenge())
        server.enqueue(refused(403, """{"error":"UPDATE_REQUIRED","reason":"PATCH_TOO_OLD"}"""))
        val m = manager()
        assertEquals(TrustState.UpdateRequired(UpdateKind.OS, "PATCH_TOO_OLD"), m.ensureFresh())
        assertEquals(listOf("dt.device.k1"), backend.aliases())
        assertEquals(UpdateRequiredInfo("OS", "PATCH_TOO_OLD", 10300, "2026-10-01"), store.load().updateRequired)

        assertTrue("same versions: stays", m.ensureFresh() is TrustState.UpdateRequired)
        versions = Versions(10300, "2026-11-01") // OS patched
        server.enqueue(challenge())
        server.enqueue(issued(Instant.ofEpochMilli(clock.nowMs)))
        server.enqueue(MockResponse().setResponseCode(204))
        assertTrue(m.ensureFresh() is TrustState.Active)
    }

    @Test
    fun `destructive codes block - everything wiped, intent first, event emitted`() = runTest {
        for ((code, reason) in listOf("DEVICE_POLICY" to BlockReason.POLICY, "DEVICE_REPLACED" to BlockReason.REPLACED,
            "DEVICE_REVOKED" to BlockReason.REVOKED, "IDENTITY_REVOKED" to BlockReason.IDENTITY_REVOKED)) {
            backend.keys.clear(); events.clear(); vault.present = true
            enrolledWithK1()
            clock.set(k1.renewAfter.plusSeconds(1))
            server.enqueue(refused(403, """{"error":"$code","reason":"BOOT_KEY_CHANGED"}"""))
            assertEquals(TrustState.Blocked(reason), manager().ensureFresh())
            assertTrue(backend.aliases().isEmpty())
            assertTrue(!vault.present)
            assertNull(store.readChain(1))
            assertEquals(listOf(TrustEvent.Blocked(reason)), events)
            assertNull(store.load().active)
        }
    }

    @Test
    fun `CERT_SUPERSEDED recovers with the superseded key - reattest without confirm`() = runTest {
        enrolledWithK1()
        clock.set(k1.renewAfter.plusSeconds(1))
        server.enqueue(refused(403, """{"error":"CERT_SUPERSEDED"}"""))
        server.enqueue(challenge())
        server.enqueue(issued(Instant.ofEpochMilli(clock.nowMs)))
        assertTrue(manager().ensureFresh() is TrustState.Active)

        take() // renew/challenge
        val rc = take()
        assertEquals("/v1/device/reattest/challenge", rc.path)
        assertNull("recovery is not mTLS", rc.getHeader("X-Test-Key"))
        assertEquals(k1.serialHex, JSONObject(rc.body.readUtf8()).getString("certSerial"))
        val rf = JSONObject(take().body.readUtf8())
        val chain = rf.getJSONArray("attestationChain").let { a -> List(a.length()) { Base64.getDecoder().decode(a.getString(it)) } }
        val payload = ContinuitySig.payload(ContinuitySig.REATTEST, "01JDEVICE", BigInteger(k1.serialHex, 16), nonce,
            backend.pairs.getValue("dt.device.k2").public.encoded, chain)
        assertTrue(Signature.getInstance("SHA256withECDSA").run {
            initVerify(backend.pairs.getValue("dt.device.k1").public); update(payload); verify(Base64.getDecoder().decode(rf.getString("continuitySig")))
        })
        assertEquals(3, server.requestCount) // no confirm
        assertEquals(listOf("dt.device.k2"), backend.aliases())
    }

    @Test
    fun `expired within grace recovers, REATTEST_NOT_ALLOWED leads to re-enrollment with the Vault kept`() = runTest {
        enrolledWithK1()
        clock.set(k1.notAfter.plusSeconds(3600))
        server.enqueue(challenge())
        server.enqueue(issued(Instant.ofEpochMilli(clock.nowMs)))
        assertTrue(manager().ensureFresh() is TrustState.Active)

        backend.keys.clear()
        enrolledWithK1()
        server.enqueue(refused(403, """{"error":"REATTEST_NOT_ALLOWED"}"""))
        assertEquals(TrustState.ReEnrollRequired, manager().ensureFresh())
        assertTrue(backend.deviceAliases().isEmpty())
        assertTrue("Vault survives", vault.present)
        assertEquals(0, vault.wipes)
    }

    @Test
    fun `past the grace period the gateway decides - REATTEST_NOT_ALLOWED opens re-enrollment, the Vault is kept`() = runTest {
        enrolledWithK1()
        clock.set(k1.notAfter.plusSeconds(8 * 24 * 3600L)) // grace is 7 days
        assertEquals(TrustState.ReEnrollRequired, manager().state())
        assertEquals("only computed so far", Phase.ENROLLED, store.load().phase)

        server.enqueue(refused(403, """{"error":"REATTEST_NOT_ALLOWED"}"""))
        assertEquals(TrustState.ReEnrollRequired, manager().ensureFresh())
        assertEquals("/v1/device/reattest/challenge", take().path)
        assertEquals("the phase Enroller accepts", Phase.RE_ENROLL_REQUIRED, store.load().phase)
        assertTrue(backend.deviceAliases().isEmpty())
        assertTrue("Vault survives", vault.present)
        assertEquals(0, vault.wipes)

        manager().ensureFresh() // settled: the gateway is not asked again
        assertEquals(1, server.requestCount)
    }

    @Test
    fun `past the grace period by a wrong phone clock - the gateway still recovers the certificate`() = runTest {
        enrolledWithK1()
        clock.set(k1.notAfter.plusSeconds(30 * 24 * 3600L))
        server.enqueue(challenge())
        server.enqueue(issued(Instant.ofEpochMilli(clock.nowMs)))
        assertTrue(manager().ensureFresh() is TrustState.Active)
        assertEquals(listOf("dt.device.k2"), backend.aliases())
    }

    @Test
    fun `past the grace period without network nothing is deleted`() = runTest {
        enrolledWithK1()
        clock.set(k1.notAfter.plusSeconds(8 * 24 * 3600L))
        server.enqueue(MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AT_START))
        assertEquals(TrustState.ReEnrollRequired, manager().ensureFresh())
        assertEquals(Phase.ENROLLED, store.load().phase)
        assertEquals(listOf(k1.alias), backend.aliases())
    }

    @Test
    fun `reconcile switches to a recorded pending certificate and confirms it`() = runTest {
        enrolledWithK1()
        backend.generateSigningKey("dt.device.k2", null, false)
        store.writeChain(2, listOf(issuedCert))
        val k2 = k1.copy(alias = "dt.device.k2", serialHex = "aa")
        store.update { it.copy(pending = k2) }
        server.enqueue(MockResponse().setResponseCode(204))

        manager().reconcile()

        assertEquals("dt.device.k2", store.load().active?.alias)
        assertEquals(4, store.load().credentialsVersion)
        assertEquals("dt.device.k2", take().getHeader("X-Test-Key"))
        assertEquals(listOf("dt.device.k2"), backend.aliases())
    }

    @Test
    fun `reconcile drops a pending certificate whose key is gone, and orphans`() = runTest {
        enrolledWithK1()
        backend.generateSigningKey("dt.device.k7", null, false)
        store.update { it.copy(pending = k1.copy(alias = "dt.device.k5")) }
        manager().reconcile()
        assertNull(store.load().pending)
        assertEquals(listOf("dt.device.k1"), backend.aliases())
    }

    @Test
    fun `reconcile replays a lost enroll finish within the window, drops it after`() = runTest {
        backend.generateSigningKey("dt.device.k1", byteArrayOf(1), false)
        store.save(StoredState(enrolling = Enrolling("01JE", "dt.device.k1", byteArrayOf(1), listOf(byteArrayOf(2)), t0.minusSeconds(60))))
        cookie = "ory_kratos_session=abc"
        server.enqueue(MockResponse().setBody(
            """{"deviceId":"01JDEVICE","certChain":["${b64.encodeToString(issuedCert.encoded)}"],
               "notBefore":"$t0","notAfter":"${t0.plusSeconds(72 * 3600)}","renewAfter":"${t0.plusSeconds(48 * 3600)}"}""",
        ))
        manager().reconcile()
        val r = take()
        assertEquals("/v1/enroll/finish", r.path)
        assertEquals("ory_kratos_session=abc", r.getHeader("Cookie"))
        assertEquals(Phase.ENROLLED, store.load().phase)
        assertEquals(1, vault.provisions)

        // stale intent: dropped with its key
        backend.keys.clear(); store.save(StoredState())
        backend.generateSigningKey("dt.device.k1", byteArrayOf(1), false)
        store.save(StoredState(enrolling = Enrolling("01JE", "dt.device.k1", byteArrayOf(1), listOf(byteArrayOf(2)), t0.minusSeconds(3600))))
        manager().reconcile()
        assertNull(store.load().enrolling)
        assertTrue(backend.aliases().isEmpty())
    }

    @Test
    fun `reconcile recreates a lost Vault and announces VaultReset`() = runTest {
        enrolledWithK1()
        vault.present = false
        manager().reconcile()
        assertTrue(vault.present)
        assertEquals(listOf(TrustEvent.VaultReset), events)
    }

    @Test
    fun `reconcile finishes a sticky BLOCK and repeats the event every start`() = runTest {
        enrolledWithK1()
        store.update { it.copy(phase = Phase.BLOCKED, blockReason = "REPLACED") } // crashed after the intent
        manager().reconcile()
        assertTrue(backend.aliases().isEmpty())
        assertNull(store.load().active)
        manager().reconcile()
        assertEquals(listOf<TrustEvent>(TrustEvent.Blocked(BlockReason.REPLACED), TrustEvent.Blocked(BlockReason.REPLACED)), events)
    }

    @Test
    fun `missing active key means re-enrollment`() = runTest {
        enrolledWithK1()
        backend.keys.remove(k1.alias)
        manager().reconcile()
        assertEquals(Phase.RE_ENROLL_REQUIRED, store.load().phase)
    }

    // ---------------------------------------------------------------- RASP summary (specs/001-rasp-hardening FR-035)

    private val summaryStore by lazy { RaspSummaryStore(java.io.File(tmp.root, "rasp-summary.json")) { t0 } }
    private fun challengeWith(features: String) =
        MockResponse().setBody("""{"nonce":"${b64.encodeToString(nonce)}","expiresAt":"2026-11-10T10:05:00Z","features":$features}""")

    private fun twoPasses() {
        summaryStore.record(RaspReport(listOf(RaspFinding("DEV_OPTIONS", RaspReaction.REPORT, "on"))), nativeOk = true)
        summaryStore.record(RaspReport.CLEAN, nativeOk = true)
    }

    /** Verifies continuitySig of [body] as v1 (no summary) or v2 (over the summary bytes in the body). */
    private fun sigVerifies(body: JSONObject, prefix: String): Boolean {
        val dec = Base64.getDecoder()
        val chain = body.getJSONArray("attestationChain").let { a -> List(a.length()) { dec.decode(a.getString(it)) } }
        val spki = backend.pairs.getValue("dt.device.k2").public.encoded
        val serial = BigInteger(k1.serialHex, 16)
        val payload =
            if (body.has("raspSummary")) ContinuitySig.payloadV2(prefix, "01JDEVICE", serial, nonce, spki, chain, dec.decode(body.getString("raspSummary")))
            else ContinuitySig.payload(prefix, "01JDEVICE", serial, nonce, spki, chain)
        return Signature.getInstance("SHA256withECDSA").run {
            initVerify(backend.pairs.getValue("dt.device.k1").public); update(payload); verify(dec.decode(body.getString("continuitySig")))
        }
    }

    @Test
    fun `new client, old gateway - no features announced means v1 and no summary, the counters stay`() = runTest {
        enrolledWithK1()
        twoPasses()
        clock.set(k1.renewAfter.plusSeconds(1))
        server.enqueue(challenge())
        server.enqueue(issued(Instant.ofEpochMilli(clock.nowMs)))
        server.enqueue(MockResponse().setResponseCode(204))
        assertTrue(manager(summaryStore).ensureFresh() is TrustState.Active)

        take()
        val body = JSONObject(take().body.readUtf8())
        assertTrue("an older gateway revokes on a signature it cannot verify", !body.has("raspSummary"))
        assertTrue(sigVerifies(body, ContinuitySig.RENEW))
        assertEquals(2, summaryStore.snapshot().passes)
    }

    @Test
    fun `features that are not a list of strings announce nothing`() = runTest {
        for (features in listOf("\"raspSummary\"", "{\"raspSummary\":true}", "[1,null,[\"raspSummary\"]]", "[\"other\"]", "null")) {
            backend.keys.clear()
            enrolledWithK1()
            clock.set(k1.renewAfter.plusSeconds(1))
            server.enqueue(challengeWith(features))
            server.enqueue(issued(Instant.ofEpochMilli(clock.nowMs)))
            server.enqueue(MockResponse().setResponseCode(204))
            assertTrue(features, manager(summaryStore).ensureFresh() is TrustState.Active)
            take()
            val body = JSONObject(take().body.readUtf8())
            take()
            assertTrue(features, !body.has("raspSummary"))
            assertTrue(features, sigVerifies(body, ContinuitySig.RENEW))
        }
    }

    @Test
    fun `gateway announces raspSummary - renewal carries the summary under continuitySig v2 and the counters restart`() = runTest {
        enrolledWithK1()
        twoPasses()
        clock.set(k1.renewAfter.plusSeconds(1))
        server.enqueue(challengeWith("[\"somethingElse\",\"raspSummary\"]"))
        server.enqueue(issued(Instant.ofEpochMilli(clock.nowMs)))
        server.enqueue(MockResponse().setResponseCode(204))
        assertTrue(manager(summaryStore).ensureFresh() is TrustState.Active)

        take()
        val body = JSONObject(take().body.readUtf8())
        assertEquals(
            """{"v":1,"native":true,"passes":2,"nativeFail":0,"since":"2026-11-08T10:00:00Z","findings":["DEV_OPTIONS"]}""",
            String(Base64.getDecoder().decode(body.getString("raspSummary"))),
        )
        assertTrue(sigVerifies(body, ContinuitySig.RENEW_V2))
        assertTrue("v2 is not v1 with an extra field", !sigVerifies(JSONObject(body.toString()).apply { remove("raspSummary") }, ContinuitySig.RENEW))
        val after = summaryStore.snapshot()
        assertEquals(0, after.passes)
        assertTrue(String(after.bytes).endsWith("\"findings\":[]}"))
    }

    @Test
    fun `gateway announces raspSummary - recovery uses the reattest v2 prefix`() = runTest {
        enrolledWithK1()
        twoPasses()
        clock.set(k1.notAfter.plusSeconds(3600))
        server.enqueue(challengeWith("[\"raspSummary\"]"))
        server.enqueue(issued(Instant.ofEpochMilli(clock.nowMs)))
        assertTrue(manager(summaryStore).ensureFresh() is TrustState.Active)

        take()
        val body = JSONObject(take().body.readUtf8())
        assertTrue(body.has("raspSummary"))
        assertTrue(sigVerifies(body, ContinuitySig.REATTEST_V2))
        assertTrue(!sigVerifies(body, ContinuitySig.RENEW_V2))
        assertEquals(0, summaryStore.snapshot().passes)
    }

    @Test
    fun `a refused or lost renewal keeps the counters for the next one`() = runTest {
        enrolledWithK1()
        twoPasses()
        clock.set(k1.renewAfter.plusSeconds(1))
        server.enqueue(challengeWith("[\"raspSummary\"]"))
        server.enqueue(refused(429, """{"error":"RATE_LIMITED"}"""))
        manager(summaryStore).ensureFresh()
        assertEquals(2, summaryStore.snapshot().passes)

        server.enqueue(challengeWith("[\"raspSummary\"]"))
        server.enqueue(MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AFTER_REQUEST))
        manager(summaryStore).ensureFresh()
        assertEquals(2, summaryStore.snapshot().passes)
    }

    @Test
    fun `a summary that cannot be read does not stop the renewal - it goes as v1`() = runTest {
        enrolledWithK1()
        clock.set(k1.renewAfter.plusSeconds(1))
        server.enqueue(challengeWith("[\"raspSummary\"]"))
        server.enqueue(issued(Instant.ofEpochMilli(clock.nowMs)))
        server.enqueue(MockResponse().setResponseCode(204))
        val broken = object : RaspSummarySource {
            override fun snapshot() = throw java.io.IOException("disk")
            override fun sent(summary: org.wolpmessenger.devicetrust.rasp.RaspSummary) = Unit
            override fun reset() = Unit
        }
        assertTrue(manager(broken).ensureFresh() is TrustState.Active)
        take()
        val body = JSONObject(take().body.readUtf8())
        assertTrue(!body.has("raspSummary"))
        assertTrue(sigVerifies(body, ContinuitySig.RENEW))
    }

    private fun FakeBackend.deviceAliases() = aliases().filter { it.startsWith(KeystoreKeys.DEVICE_PREFIX) }
}

class ContinuitySigTest {
    @Test
    fun `payload and signature match the independent vectors (Python cryptography)`() {
        val file = generateSequence(java.io.File("").absoluteFile) { it.parentFile }
            .map { java.io.File(it, "testvectors/continuity/continuity-v1.json") }.first { it.exists() }
        val vectors = JSONObject(file.readText()).getJSONArray("vectors")
        val dec = Base64.getDecoder()
        for (i in 0 until vectors.length()) {
            val v = vectors.getJSONObject(i)
            val chain = v.getJSONArray("attestationChainB64").let { a -> List(a.length()) { dec.decode(a.getString(it)) } }
            val payload = ContinuitySig.payload(v.getString("prefix"), v.getString("deviceId"), BigInteger(v.getString("certSerialHex"), 16),
                dec.decode(v.getString("nonceB64")), dec.decode(v.getString("newKeySpkiB64")), chain)
            assertEquals(v.getString("prefix"), v.getString("payloadHex"), payload.joinToString("") { "%02x".format(it) })
            val oldKey = java.security.KeyFactory.getInstance("EC").generatePublic(java.security.spec.X509EncodedKeySpec(dec.decode(v.getString("oldKeySpkiB64"))))
            assertTrue(Signature.getInstance("SHA256withECDSA").run { initVerify(oldKey); update(payload); verify(dec.decode(v.getString("continuitySigB64"))) })
        }
    }

    @Test
    fun `v2 payload and signature match the independent vectors (Python cryptography)`() {
        val file = generateSequence(java.io.File("").absoluteFile) { it.parentFile }
            .map { java.io.File(it, "testvectors/continuity/continuity-v2.json") }.first { it.exists() }
        val vectors = JSONObject(file.readText()).getJSONArray("vectors")
        val dec = Base64.getDecoder()
        assertEquals(2, vectors.length())
        for (i in 0 until vectors.length()) {
            val v = vectors.getJSONObject(i)
            val chain = v.getJSONArray("attestationChainB64").let { a -> List(a.length()) { dec.decode(a.getString(it)) } }
            val payload = ContinuitySig.payloadV2(v.getString("prefix"), v.getString("deviceId"), BigInteger(v.getString("certSerialHex"), 16),
                dec.decode(v.getString("nonceB64")), dec.decode(v.getString("newKeySpkiB64")), chain, dec.decode(v.getString("raspSummaryB64")))
            assertEquals(v.getString("prefix"), v.getString("payloadHex"), payload.joinToString("") { "%02x".format(it) })
            val oldKey = java.security.KeyFactory.getInstance("EC").generatePublic(java.security.spec.X509EncodedKeySpec(dec.decode(v.getString("oldKeySpkiB64"))))
            assertTrue(Signature.getInstance("SHA256withECDSA").run { initVerify(oldKey); update(payload); verify(dec.decode(v.getString("continuitySigB64"))) })
        }
        assertEquals(ContinuitySig.RENEW_V2, ContinuitySig.v2(ContinuitySig.RENEW))
        assertEquals(ContinuitySig.REATTEST_V2, ContinuitySig.v2(ContinuitySig.REATTEST))
    }

    @Test
    fun `serial is big-endian without the sign byte`() {
        assertEquals("8f", ContinuitySig.unsignedBigEndian(BigInteger("8f", 16)).joinToString("") { "%02x".format(it) })
        assertEquals("7f", ContinuitySig.unsignedBigEndian(BigInteger("7f", 16)).joinToString("") { "%02x".format(it) })
        assertEquals("00", ContinuitySig.unsignedBigEndian(BigInteger.ZERO).joinToString("") { "%02x".format(it) })
    }
}
