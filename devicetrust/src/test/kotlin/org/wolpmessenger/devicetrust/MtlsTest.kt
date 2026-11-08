package org.wolpmessenger.devicetrust

import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.wolpmessenger.devicetrust.api.ClientCredentials
import org.wolpmessenger.devicetrust.net.HttpClients
import java.security.cert.X509Certificate
import javax.net.ssl.SSLHandshakeException

/** HttpClients.mtls really presents the device certificate (S2 §10) and keeps connections per certificate apart. */
class MtlsTest {
    private val deviceCa = HeldCertificate.Builder().certificateAuthority(0).commonName("Wolp Device CA").build()
    private val serverCert = HeldCertificate.Builder().addSubjectAlternativeName("localhost").commonName("app").build()
    private fun device(cn: String) = HeldCertificate.Builder().signedBy(deviceCa).commonName(cn).ecdsa256().build()

    private val server = MockWebServer().apply {
        val certs = HandshakeCertificates.Builder().heldCertificate(serverCert).addTrustedCertificate(deviceCa.certificate).build()
        useHttps(certs.sslSocketFactory(), false)
        requireClientAuth()
        start()
    }
    private val clientTrust = HandshakeCertificates.Builder().addTrustedCertificate(serverCert.certificate).build().trustManager

    private fun creds(h: HeldCertificate) = ClientCredentials(h.keyPair.private, arrayOf(h.certificate, deviceCa.certificate))
    private fun get(client: OkHttpClient) = client.newCall(Request.Builder().url(server.url("/v1/device/ping")).build()).execute().use { it.code }

    @Test
    fun `the gateway sees the device certificate, and a new certificate never rides an old pooled connection`() {
        val base = OkHttpClient()
        val k1 = device("01JDEVICE-k1")
        val k2 = device("01JDEVICE-k2")
        repeat(3) { server.enqueue(MockResponse().setResponseCode(204)) }

        assertEquals(204, get(HttpClients.mtls(base, creds(k1), clientTrust)))
        assertEquals(204, get(HttpClients.mtls(base, creds(k2), clientTrust)))
        assertEquals(204, get(HttpClients.mtls(base, creds(k1), clientTrust)))

        val peers = List(3) { (server.takeRequest().handshake!!.peerCertificates.first() as X509Certificate).subjectX500Principal.name }
        assertEquals(listOf("CN=01JDEVICE-k1", "CN=01JDEVICE-k2", "CN=01JDEVICE-k1"), peers)
        server.shutdown()
    }

    @Test
    fun `without a client certificate the TLS handshake fails`() {
        val plain = OkHttpClient.Builder().sslSocketFactory(
            HandshakeCertificates.Builder().addTrustedCertificate(serverCert.certificate).build().sslSocketFactory(), clientTrust,
        ).build()
        val failed = runCatching { get(plain) }.exceptionOrNull()
        assertTrue("expected a handshake failure, got $failed", failed is SSLHandshakeException || failed is java.io.IOException)
        server.shutdown()
    }
}
