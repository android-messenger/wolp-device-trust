package org.wolpmessenger.devicetrust.net

import okhttp3.CertificatePinner
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient
import org.wolpmessenger.devicetrust.api.ClientCredentials
import org.wolpmessenger.devicetrust.api.DeviceTrustConfig
import org.wolpmessenger.devicetrust.tls.FixedKeyManager
import java.security.KeyStore
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/**
 * The pinned client (S2 §10): system CAs plus `CertificatePinner` for the enroll and app hosts;
 * [mtls] derives a client presenting one specific device certificate.
 */
internal object HttpClients {
    fun pinned(config: DeviceTrustConfig): OkHttpClient {
        val pinner = CertificatePinner.Builder().apply {
            for (host in listOf(config.enrollBaseUrl.toHttpUrl().host, config.appBaseUrl.toHttpUrl().host).distinct()) {
                config.serverPins.forEach { add(host, it) }
            }
        }.build()
        return OkHttpClient.Builder()
            .certificatePinner(pinner)
            .connectTimeout(config.httpTimeouts.connect.inWholeMilliseconds, TimeUnit.MILLISECONDS)
            .readTimeout(config.httpTimeouts.read.inWholeMilliseconds, TimeUnit.MILLISECONDS)
            .followRedirects(false)
            .build()
    }

    /**
     * [base] (pins, timeouts, shared connection pool) presenting [credentials]. OkHttp keys pooled
     * connections by address including the SSLSocketFactory, so connections authenticated with
     * different certificates are never reused for each other.
     */
    fun mtls(base: OkHttpClient, credentials: ClientCredentials, trustManager: X509TrustManager = systemTrustManager()): OkHttpClient {
        val ssl = SSLContext.getInstance("TLS").apply { init(arrayOf(FixedKeyManager(credentials)), arrayOf(trustManager), null) }
        return base.newBuilder().sslSocketFactory(ssl.socketFactory, trustManager).build()
    }

    fun systemTrustManager(): X509TrustManager =
        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            .apply { init(null as KeyStore?) }
            .trustManagers.filterIsInstance<X509TrustManager>().first()
}
