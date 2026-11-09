package org.wolpmessenger.devicetrust

import androidx.test.ext.junit.runners.AndroidJUnit4
import okhttp3.Request
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.wolpmessenger.devicetrust.api.ClientCredentials
import org.wolpmessenger.devicetrust.api.DeviceTrustConfig
import org.wolpmessenger.devicetrust.keys.KeyGenResult
import org.wolpmessenger.devicetrust.keys.KeystoreKeys
import org.wolpmessenger.devicetrust.tls.DeviceHttp
import java.security.KeyPair
import java.security.cert.X509Certificate

/**
 * The full mTLS handshake with a **Keystore** device key through the library's own client
 * (`DeviceHttp`, Conscrypt on the device) against a server that requires a client certificate,
 * for TLS 1.3 and 1.2. Stage 5 ran the TLS tests with software keys only and so missed that a
 * key without `DIGEST_NONE` cannot sign `CertificateVerify` (found on the stand, session 6).
 */
@RunWith(AndroidJUnit4::class)
class KeystoreMtlsDeviceTest {
    private val keys = KeystoreKeys.android()
    private val servers = mutableListOf<MockWebServer>()

    @After
    fun cleanup() {
        servers.forEach { it.shutdown() }
        keys.deleteOrphans(keep = emptySet())
    }

    @Test
    fun keystoreKeyCompletesMtlsHandshakeTls13AndTls12() {
        val alias = keys.nextDeviceAlias()
        val gen = keys.generate(alias, ByteArray(32) { 1 }, preferStrongBox = false)
        assumeTrue("needs a hardware Keystore (emulator: software, not enrollable)", gen is KeyGenResult.Ok)

        // a device certificate for the Keystore public key, issued by a test device CA (as device-signer would)
        val deviceCa = HeldCertificate.Builder().certificateAuthority(0).commonName("Test Device CA").ecdsa256().build()
        val leaf = HeldCertificate.Builder()
            .keyPair(KeyPair(keys.publicKey(alias)!!, keys.privateKey(alias)!!))
            .signedBy(deviceCa).commonName("keystore-device").serialNumber(0x7a11).build()
        val creds = ClientCredentials(keys.privateKey(alias)!!, arrayOf(leaf.certificate, deviceCa.certificate))

        val serverCert = HeldCertificate.Builder().addSubjectAlternativeName("localhost").commonName("app").build()
        val trust = HandshakeCertificates.Builder().addTrustedCertificate(serverCert.certificate).build().trustManager
        val http = DeviceHttp(DeviceTrustConfig(), current = { creds }, onServerDate = {}, trustManager = trust, pinned = okhttp3.OkHttpClient())

        for (tls in listOf("TLSv1.3", "TLSv1.2")) {
            val serverTls = HandshakeCertificates.Builder().heldCertificate(serverCert).addTrustedCertificate(deviceCa.certificate).build()
            val s = MockWebServer().apply {
                val factory = serverTls.sslContext().apply { }.socketFactory
                useHttps(OnlyProtocol(factory, tls), false)
                requireClientAuth()
                dispatcher = object : Dispatcher() {
                    override fun dispatch(request: RecordedRequest): MockResponse {
                        val peer = request.handshake?.peerCertificates?.firstOrNull() as? X509Certificate
                        return MockResponse().setResponseCode(204).setHeader("X-Peer-Serial", peer?.serialNumber?.toString(16) ?: "none")
                            .setHeader("X-Tls", request.handshake?.tlsVersion?.javaName ?: "?")
                    }
                }
                start()
                servers += this
            }
            http.onCredentialsChanged()
            http.client.newCall(Request.Builder().url(s.url("/v1/device/ping").newBuilder().host("localhost").build()).build()).execute().use {
                assertEquals("$tls handshake with the Keystore key", 204, it.code)
                assertEquals("7a11", it.header("X-Peer-Serial"))
                assertEquals(tls, it.header("X-Tls"))
            }
        }
    }

    /** Server socket factory limited to one TLS version. */
    private class OnlyProtocol(private val d: javax.net.ssl.SSLSocketFactory, private val p: String) : javax.net.ssl.SSLSocketFactory() {
        private fun on(s: java.net.Socket) = s.also { (it as javax.net.ssl.SSLSocket).enabledProtocols = arrayOf(p) }
        override fun getDefaultCipherSuites(): Array<String> = d.defaultCipherSuites
        override fun getSupportedCipherSuites(): Array<String> = d.supportedCipherSuites
        override fun createSocket(s: java.net.Socket?, h: String?, port: Int, a: Boolean) = on(d.createSocket(s, h, port, a))
        override fun createSocket(h: String?, port: Int) = on(d.createSocket(h, port))
        override fun createSocket(h: String?, port: Int, l: java.net.InetAddress?, lp: Int) = on(d.createSocket(h, port, l, lp))
        override fun createSocket(h: java.net.InetAddress?, port: Int) = on(d.createSocket(h, port))
        override fun createSocket(a: java.net.InetAddress?, port: Int, l: java.net.InetAddress?, lp: Int) = on(d.createSocket(a, port, l, lp))
    }
}
