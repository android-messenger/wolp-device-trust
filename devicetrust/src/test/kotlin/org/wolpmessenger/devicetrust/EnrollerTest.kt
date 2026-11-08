package org.wolpmessenger.devicetrust

import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.SocketPolicy
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.wolpmessenger.devicetrust.api.BlockReason
import org.wolpmessenger.devicetrust.api.DeviceSecurityInfo
import org.wolpmessenger.devicetrust.api.DeviceTrustConfig
import org.wolpmessenger.devicetrust.api.EnrollResult
import org.wolpmessenger.devicetrust.api.PrecheckResult
import org.wolpmessenger.devicetrust.api.SecurityLevel
import org.wolpmessenger.devicetrust.api.UnsupportedReason
import org.wolpmessenger.devicetrust.api.UpdateKind
import org.wolpmessenger.devicetrust.enroll.Enroller
import org.wolpmessenger.devicetrust.keys.KeystoreKeys
import org.wolpmessenger.devicetrust.net.GatewayClient
import org.wolpmessenger.devicetrust.store.Phase
import org.wolpmessenger.devicetrust.store.StoredState
import org.wolpmessenger.devicetrust.store.TrustStore
import java.security.Signature
import java.time.Instant
import java.util.Base64
import java.util.concurrent.TimeUnit

class EnrollerTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private val server = MockWebServer().apply { start() }
    private val backend = FakeBackend()
    private val keys = KeystoreKeys(backend)
    private val store by lazy { TrustStore(tmp.root) }
    private val dates = mutableListOf<String?>()
    private var vaultProvisions = 0
    private var vaultFails = false
    private var precheck: PrecheckResult = PrecheckResult.Supported(
        DeviceSecurityInfo(SecurityLevel.TRUSTED_ENVIRONMENT, false, false, 34, "2026-10-05", true), emptyList(),
    )

    private val deviceCert = cert("plain.pem")
    private val nonce = ByteArray(32) { 7 }
    private val b64 = Base64.getEncoder()

    private fun enroller() = Enroller(
        config = DeviceTrustConfig(),
        precheck = { precheck },
        keys = keys,
        gateway = GatewayClient(OkHttpClient(), server.url("/"), onServerDate = { dates += it }),
        store = store,
        provisionVault = { if (vaultFails) error("vault locked") else vaultProvisions++ },
        versionCode = { 10300 },
        now = { Instant.parse("2026-11-08T10:00:00Z") },
    )

    @After
    fun stop() = server.shutdown()

    private fun startOk(id: String = "01JENROLL") = MockResponse().setBody(
        """{"enrollmentId":"$id","nonce":"${b64.encodeToString(nonce)}","expiresAt":"2026-11-08T10:05:00Z"}""",
    ).addHeader("Date", "Sun, 08 Nov 2026 10:00:00 GMT")

    private fun finishOk() = MockResponse().setBody(
        """{"deviceId":"01JDEVICE","certChain":["${b64.encodeToString(deviceCert.encoded)}"],
           "notBefore":"2026-11-08T09:55:00Z","notAfter":"2026-11-11T10:00:00Z","renewAfter":"2026-11-10T10:00:00Z"}""",
    ).addHeader("Date", "Sun, 08 Nov 2026 10:00:01 GMT")

    private fun refused(code: Int, body: String) = MockResponse().setResponseCode(code).setBody(body)

    private suspend fun enroll(pw: CharArray = "K7M2-QX9P-4T".toCharArray()) = enroller().enroll("ory_kratos_session=abc", pw)

    @Test
    fun `happy path follows S2 §6_2 and S3 §5_1-5_2`() = runTest {
        server.enqueue(startOk())
        server.enqueue(finishOk())
        val pw = "K7M2-QX9P-4T".toCharArray()

        assertEquals(EnrollResult.Ok("01JDEVICE"), enroll(pw))

        // start: cookie + schema; password zeroed afterwards
        val start = server.takeRequest(1, TimeUnit.SECONDS)!!
        assertEquals("/v1/enroll/start", start.path)
        assertEquals("ory_kratos_session=abc", start.getHeader("Cookie"))
        val sj = JSONObject(start.body.readUtf8())
        assertEquals("K7M2-QX9P-4T", sj.getString("onboardingPassword"))
        assertEquals(10300, sj.getInt("appVersionCode"))
        assertEquals("TEE", sj.getJSONObject("precheck").getString("securityLevel"))
        assertTrue(pw.all { it == '\u0000' })

        // key bound to the nonce; finish carries CSR signed by that key and the attestation chain
        val alias = "dt.device.k1"
        assertArrayEquals(nonce, backend.challenges[alias])
        val fj = JSONObject(server.takeRequest(1, TimeUnit.SECONDS)!!.body.readUtf8())
        assertEquals("01JENROLL", fj.getString("enrollmentId"))
        assertEquals(1, fj.getJSONArray("attestationChain").length())
        val csr = Base64.getDecoder().decode(fj.getString("csr"))
        assertTrue("CSR embeds the device public key", csr.containsSlice(backend.pairs.getValue(alias).public.encoded))

        // state: ENROLLED, active cert, credentialsVersion bumped, Vault provisioned, intent cleared
        val s = store.load()
        assertEquals(Phase.ENROLLED, s.phase)
        assertEquals("01JDEVICE", s.deviceId)
        assertEquals(alias, s.active?.alias)
        assertEquals(deviceCert.serialNumber.toString(16), s.active?.serialHex)
        assertEquals(Instant.parse("2026-11-10T10:00:00Z"), s.active?.renewAfter)
        assertEquals(1, s.credentialsVersion)
        assertNull(s.enrolling)
        assertEquals(1, vaultProvisions)
        assertEquals(deviceCert, store.readChain(1)?.single())
        assertEquals(listOf(alias), backend.aliases())
        assertEquals(listOf("Sun, 08 Nov 2026 10:00:00 GMT", "Sun, 08 Nov 2026 10:00:01 GMT"), dates)
    }

    @Test
    fun `enroll start refusals map to results and create no key`() = runTest {
        val cases = listOf(
            refused(403, """{"error":"WRONG_PASSWORD","attemptsLeft":2}""") to EnrollResult.WrongPassword(2),
            refused(403, """{"error":"PASSWORD_BURNED"}""") to EnrollResult.PasswordBurned,
            refused(403, """{"error":"PASSWORD_EXPIRED"}""") to EnrollResult.PasswordExpired,
            refused(403, """{"error":"NO_PASSWORD"}""") to EnrollResult.NoPassword,
            refused(401, """{"error":"NO_SESSION"}""") to EnrollResult.NoSession,
            refused(403, """{"error":"IDENTITY_REVOKED"}""") to EnrollResult.Blocked(BlockReason.IDENTITY_REVOKED),
        )
        for ((response, expected) in cases) {
            server.enqueue(response)
            assertEquals(expected, enroll())
        }
        server.enqueue(refused(429, """{"error":"RATE_LIMITED"}""").addHeader("Retry-After", "60"))
        val rl = enroll() as EnrollResult.Transient
        assertEquals(java.time.Duration.ofSeconds(60), rl.retryAfter)
        assertTrue(backend.generated.isEmpty())
    }

    @Test
    fun `failed precheck never reaches the gateway`() = runTest {
        precheck = PrecheckResult.Unsupported(listOf(UnsupportedReason.SOFTWARE_KEYSTORE), null)
        assertEquals(EnrollResult.Unsupported(listOf("SOFTWARE_KEYSTORE")), enroll())
        assertEquals(0, server.requestCount)
    }

    @Test
    fun `policy rejection deletes the key and clears the intent`() = runTest {
        server.enqueue(startOk())
        server.enqueue(refused(403, """{"error":"POLICY_REJECTED","reason":"BOOTLOADER_UNLOCKED"}"""))
        assertEquals(EnrollResult.PolicyRejected("BOOTLOADER_UNLOCKED"), enroll())
        assertTrue(backend.keys.isEmpty())
        assertNull(store.load().enrolling)
        assertEquals(Phase.NOT_ENROLLED, store.load().phase)
    }

    @Test
    fun `soft reasons become UpdateRequired`() = runTest {
        server.enqueue(startOk())
        server.enqueue(refused(403, """{"error":"POLICY_REJECTED","reason":"PATCH_TOO_OLD"}"""))
        assertEquals(EnrollResult.UpdateRequired(UpdateKind.OS), enroll())
        server.enqueue(startOk())
        server.enqueue(refused(403, """{"error":"UPDATE_REQUIRED","reason":"APP_VERSION_TOO_OLD"}"""))
        assertEquals(EnrollResult.UpdateRequired(UpdateKind.APP), enroll())
        assertTrue(backend.keys.isEmpty())
    }

    @Test
    fun `NONCE_INVALID restarts once, then gives up`() = runTest {
        server.enqueue(startOk("01JA"))
        server.enqueue(refused(403, """{"error":"NONCE_INVALID"}"""))
        server.enqueue(startOk("01JB"))
        server.enqueue(finishOk())
        assertEquals(EnrollResult.Ok("01JDEVICE"), enroll())
        assertEquals("the rejected key is gone, one key left", 1, backend.aliases().size)
        assertEquals(4, server.requestCount)

        val fresh = TemporaryFolder().apply { create() }
        val e2 = Enroller(DeviceTrustConfig(), { precheck }, KeystoreKeys(FakeBackend()),
            GatewayClient(OkHttpClient(), server.url("/"), {}), TrustStore(fresh.root), {}, { 1 }, { Instant.EPOCH })
        repeat(2) {
            server.enqueue(startOk())
            server.enqueue(refused(403, """{"error":"NONCE_INVALID"}"""))
        }
        assertTrue(e2.enroll("c", "p".toCharArray()) is EnrollResult.Transient)
    }

    @Test
    fun `lost finish response keeps the intent and the key for replay`() = runTest {
        server.enqueue(startOk())
        server.enqueue(MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AFTER_REQUEST))
        assertTrue(enroll() is EnrollResult.Transient)
        val s = store.load()
        assertNotNull(s.enrolling)
        assertEquals("01JENROLL", s.enrolling?.enrollmentId)
        assertEquals(listOf(s.enrolling!!.alias), backend.aliases())
        assertEquals(Phase.NOT_ENROLLED, s.phase)

        server.enqueue(startOk())
        server.enqueue(refused(503, """{"error":"UNAVAILABLE"}"""))
        assertTrue(enroll() is EnrollResult.Transient)
        assertNotNull(store.load().enrolling)
    }

    @Test
    fun `Vault failure after server success does not mark the device enrolled`() = runTest {
        vaultFails = true
        server.enqueue(startOk())
        server.enqueue(finishOk())
        assertTrue(enroll() is EnrollResult.Transient)
        assertEquals(Phase.NOT_ENROLLED, store.load().phase)
        assertNotNull("replay can still collect the certificate", store.load().enrolling)
    }

    @Test
    fun `enroll is refused when enrolled or blocked`() = runTest {
        store.save(StoredState(phase = Phase.ENROLLED))
        assertTrue(enroll() is EnrollResult.Transient)
        store.save(StoredState(phase = Phase.BLOCKED, blockReason = "REPLACED"))
        assertEquals(EnrollResult.Blocked(BlockReason.REPLACED), enroll())
        assertEquals(0, server.requestCount)
    }

    @Test
    fun `CSR in finish verifies with the device key`() = runTest {
        server.enqueue(startOk())
        server.enqueue(finishOk())
        enroll()
        server.takeRequest()
        val csr = Base64.getDecoder().decode(JSONObject(server.takeRequest().body.readUtf8()).getString("csr"))
        // outer SEQUENCE → info TLV → signature BIT STRING (last TLV)
        val infoStart = if ((csr[1].toInt() and 0x80) != 0) 2 + (csr[1].toInt() and 0x7F) else 2
        val infoLen = tlvLen(csr, infoStart)
        val sigBits = csr.copyOfRange(csr.size - tlvContentLen(csr), csr.size)
        val ok = Signature.getInstance("SHA256withECDSA").run {
            initVerify(backend.pairs.getValue("dt.device.k1").public)
            update(csr, infoStart, infoLen)
            verify(sigBits.copyOfRange(1, sigBits.size))
        }
        assertTrue(ok)
    }

    private fun tlvLen(b: ByteArray, off: Int): Int {
        val f = b[off + 1].toInt() and 0xFF
        if (f < 0x80) return 2 + f
        var n = 0
        repeat(f and 0x7F) { n = (n shl 8) or (b[off + 2 + it].toInt() and 0xFF) }
        return 2 + (f and 0x7F) + n
    }

    /** Content length of the trailing BIT STRING (ECDSA signatures are < 128 bytes). */
    private fun tlvContentLen(csr: ByteArray): Int {
        for (i in csr.size - 2 downTo 0) {
            if (csr[i] == 0x03.toByte() && (csr[i + 1].toInt() and 0xFF) == csr.size - i - 2) return csr.size - i - 2
        }
        error("no trailing BIT STRING")
    }

    private fun ByteArray.containsSlice(n: ByteArray) = (0..size - n.size).any { i -> n.indices.all { this[i + it] == n[it] } }
}
