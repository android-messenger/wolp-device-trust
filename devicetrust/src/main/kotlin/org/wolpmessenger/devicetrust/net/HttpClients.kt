package org.wolpmessenger.devicetrust.net

import okhttp3.CertificatePinner
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient
import org.wolpmessenger.devicetrust.api.DeviceTrustConfig
import java.util.concurrent.TimeUnit

/**
 * The pinned client (S2 §10): system CAs plus `CertificatePinner` for the enroll and app hosts.
 * The client certificate (X509KeyManager, `evictAll` on `credentialsVersion`) is added in stage 5.
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
}
