package org.wolpmessenger.devicetrust

import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.wolpmessenger.devicetrust.api.ClientCredentials
import org.wolpmessenger.devicetrust.api.DeviceTrustConfig
import org.wolpmessenger.devicetrust.tls.DeviceHttp
import java.io.IOException
import java.security.cert.X509Certificate

/** S2 §10: the mTLS client follows the active certificate, evicts on change, and applies R7. */
class DeviceHttpTest {
    private val deviceCa = HeldCertificate.Builder().certificateAuthority(0).commonName("Wolp Device CA").build()
    private val serverCert = HeldCertificate.Builder().addSubjectAlternativeName("localhost").commonName("app").build()
    // distinct serials, as the signer issues them (128-bit random, S3 §4); R7 compares serials
    private fun device(cn: String, serial: Long) = HeldCertificate.Builder().signedBy(deviceCa).commonName(cn).serialNumber(serial).ecdsa256().build()
    private fun creds(h: HeldCertificate) = ClientCredentials(h.keyPair.private, arrayOf(h.certificate, deviceCa.certificate))
    private val k1 = device("k1", 0x1001)
    private val k2 = device("k2", 0x1002)

    private val serverCerts = HandshakeCertificates.Builder().heldCertificate(serverCert).addTrustedCertificate(deviceCa.certificate).build()
    private val trust = HandshakeCertificates.Builder().addTrustedCertificate(serverCert.certificate).build().trustManager
    private val servers = mutableListOf<MockWebServer>()

    /** TLS server; [deny] = CNs whose requests get `403 X-Device-Deny: CERT_SUPERSEDED`. */
    private fun server(requireClientCert: Boolean = true, deny: Set<String> = emptySet()) = MockWebServer().apply {
        useHttps(serverCerts.sslSocketFactory(), false)
        if (requireClientCert) requireClientAuth()
        dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                val cn = (request.handshake?.peerCertificates?.firstOrNull() as? X509Certificate)?.subjectX500Principal?.name?.removePrefix("CN=")
                return if (cn in deny) MockResponse().setResponseCode(403).addHeader("X-Device-Deny", "CERT_SUPERSEDED")
                else MockResponse().setResponseCode(200).addHeader("Date", "Sun, 08 Nov 2026 10:00:00 GMT").setBody(cn ?: "anonymous")
            }
        }
        start()
        servers += this
    }

    private var active: ClientCredentials? = creds(k1)
    private val dates = mutableListOf<String?>()
    private val http = DeviceHttp(DeviceTrustConfig(), current = { active }, onServerDate = { dates += it }, trustManager = trust, pinned = OkHttpClient())

    private fun get(client: OkHttpClient, s: MockWebServer) =
        client.newCall(Request.Builder().url(s.url("/v1/device/ping")).build()).execute().use { it.code to it.body!!.string() }

    @After
    fun stop() = servers.forEach { it.shutdown() }

    @Test
    fun presentsActiveCertificateAndKeySwitchNeedsEviction() {
        val s = server()
        assertEquals(200 to "k1", get(http.client, s))
        active = creds(k2)
        assertEquals("without eviction the pooled k1 connection is reused", 200 to "k1", get(http.client, s))
        http.onCredentialsChanged()
        assertEquals(200 to "k2", get(http.client, s))
        assertEquals(3, dates.size)
    }

    @Test
    fun r7DenialForSupersededCertificateIsRetriedWithCurrent() {
        val s = server(deny = setOf("k1"))
        assertEquals(403, get(http.client, s).first) // k1 is active: the denial is real and passed through
        assertEquals(1, s.requestCount)

        active = creds(k2) // switched, but the pooled connection is still k1
        assertEquals(200 to "k2", get(http.client, s))
        assertEquals("the stale answer was retried", 3, s.requestCount)
        assertTrue("only successful answers feed the clock", dates.size == 1)
    }

    @Test
    fun noActiveCertificateMeansNoClientCertificate() {
        active = null
        val failed = runCatching { get(http.client, server()) }.exceptionOrNull()
        assertTrue("handshake must fail against a client-auth server, got $failed", failed is IOException)
        assertEquals(200 to "anonymous", get(http.client, server(requireClientCert = false)))
    }

    @Test
    fun updateClientNeverPresentsCertificateAndIsNotPinned() {
        val update = http.update.newBuilder().sslSocketFactory(
            HandshakeCertificates.Builder().addTrustedCertificate(serverCert.certificate).build().sslSocketFactory(), trust,
        ).build()
        assertEquals(200 to "anonymous", get(update, server(requireClientCert = false)))
        assertTrue(runCatching { get(update, server()) }.exceptionOrNull() is IOException)
        assertTrue(http.update.certificatePinner.pins.isEmpty())
        assertTrue("separate pool from the pinned client", http.update.connectionPool !== http.client.connectionPool)
    }
}
