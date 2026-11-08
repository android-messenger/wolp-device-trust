package org.wolpmessenger.devicetrust.tls

import okhttp3.ConnectionPool
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.Response
import org.wolpmessenger.devicetrust.api.ClientCredentials
import org.wolpmessenger.devicetrust.api.DeviceTrustConfig
import org.wolpmessenger.devicetrust.api.GatewayCode
import org.wolpmessenger.devicetrust.net.HttpClients
import java.net.InetAddress
import java.net.Socket
import java.security.Principal
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.X509ExtendedKeyManager
import javax.net.ssl.X509TrustManager

/**
 * The two HTTP clients of S2 §10.
 *
 * - [client] (`okHttpClient()`): mTLS + pinning. The certificate is resolved **at handshake time**
 *   from [current]; on every `credentialsVersion` change [onCredentialsChanged] evicts the shared
 *   pool and switches to a fresh SSLContext (no cached TLS sessions) — both would otherwise keep
 *   the old certificate.
 *   **R7**: a `CERT_*` or destructive `X-Device-Deny` received over a connection whose client
 *   certificate is no longer the active one is not acted upon — the request is repeated once with
 *   the current certificate. Successful responses feed the TrustClock ([onServerDate]).
 * - [update] (`updateHttpClient()`): system CAs only, no pinning, no client certificate — for the
 *   signed update manifest and the APK, so a broken server-key rotation never cuts the app off
 *   from the update that fixes it.
 */
internal class DeviceHttp(
    config: DeviceTrustConfig,
    private val current: () -> ClientCredentials?,
    private val onServerDate: (String?) -> Unit,
    trustManager: X509TrustManager = HttpClients.systemTrustManager(),
    /** Pinned base (pins, timeouts, the connection pool shared with the library's own calls). */
    val pinned: OkHttpClient = HttpClients.pinned(config),
) {
    private val sockets = FreshSessionSocketFactory { SSLContext.getInstance("TLS").apply { init(arrayOf(CurrentKeyManager(current)), arrayOf(trustManager), null) } }

    val client: OkHttpClient = pinned.newBuilder()
        .sslSocketFactory(sockets, trustManager)
        .addInterceptor(SerialGuard())
        .addNetworkInterceptor { chain -> chain.proceed(chain.request()).also { if (it.isSuccessful) onServerDate(it.header("Date")) } }
        .build()

    val update: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(config.httpTimeouts.connect.inWholeMilliseconds, TimeUnit.MILLISECONDS)
        .readTimeout(config.httpTimeouts.read.inWholeMilliseconds, TimeUnit.MILLISECONDS)
        .build()

    /**
     * Call on every `credentialsVersion` change (S2 §10). Evicting the pool is not enough: a new
     * connection would **resume** a cached TLS session and carry the old client identity. Sessions
     * cannot be invalidated portably (Conscrypt throws UnsupportedOperationException), so new
     * connections switch to a fresh SSLContext whose session cache is empty.
     */
    fun onCredentialsChanged() {
        sockets.renew()
        pinned.connectionPool.evictAll()
    }

    /** R7 (S2 §1): act only on answers to requests sent with the active certificate. */
    private inner class SerialGuard : Interceptor {
        override fun intercept(chain: Interceptor.Chain): Response {
            val request = chain.request()
            val response = chain.proceed(request)
            if (request.tag(R7Retry::class.java) != null) return response
            val code = GatewayCode.parse(response.header("X-Device-Deny")?.trim())
            if (code !in GUARDED) return response
            val used = (response.handshake?.localCertificates?.firstOrNull() as? X509Certificate)?.serialNumber
            val active = current()?.chain?.firstOrNull()?.serialNumber
            if (used == null || active == null || used == active) return response
            // Sent with a superseded certificate over a connection from before the key switch.
            // Repeat once on a FRESH pool: an HTTP/2 connection still carrying this very call is not
            // idle, so evictAll() leaves it open and a new call on the shared pool would multiplex
            // onto it — with the old certificate again.
            response.close()
            onCredentialsChanged()
            val fresh = client.newBuilder().connectionPool(ConnectionPool()).build()
            return fresh.newCall(request.newBuilder().tag(R7Retry::class.java, R7Retry).build()).execute()
        }
    }

    private object R7Retry

    private companion object {
        val GUARDED = setOf(
            GatewayCode.CERT_INVALID, GatewayCode.CERT_UNKNOWN, GatewayCode.CERT_SUPERSEDED, GatewayCode.CERT_EXPIRED,
            GatewayCode.DEVICE_REVOKED, GatewayCode.DEVICE_REPLACED, GatewayCode.IDENTITY_REVOKED, GatewayCode.DEVICE_POLICY,
        )
    }
}

/** Presents whatever certificate is active when the TLS handshake asks for one (none → no certificate). */
private class CurrentKeyManager(private val current: () -> ClientCredentials?) : X509ExtendedKeyManager() {
    // The alias carries the leaf serial so a handshake never mixes the key of one certificate with the chain of another.
    private fun alias(): String? = current()?.chain?.firstOrNull()?.serialNumber?.toString(16)
    private fun forAlias(alias: String?): ClientCredentials? = current()?.takeIf { alias != null && it.chain.firstOrNull()?.serialNumber?.toString(16) == alias }

    override fun chooseClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, socket: Socket?): String? = alias()
    override fun chooseEngineClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, engine: SSLEngine?): String? = alias()
    override fun getClientAliases(keyType: String?, issuers: Array<out Principal>?): Array<String>? = alias()?.let { arrayOf(it) }
    override fun getCertificateChain(alias: String?): Array<X509Certificate>? = forAlias(alias)?.chain
    override fun getPrivateKey(alias: String?): PrivateKey? = forAlias(alias)?.privateKey
    override fun getServerAliases(keyType: String?, issuers: Array<out Principal>?): Array<String>? = null
    override fun chooseServerAlias(keyType: String?, issuers: Array<out Principal>?, socket: Socket?): String? = null
}

/**
 * Socket factory that can switch to a fresh SSLContext. OkHttp sees one stable factory (a
 * client's factory cannot change), while every renewal starts with an empty TLS session cache.
 */
private class FreshSessionSocketFactory(private val newContext: () -> SSLContext) : SSLSocketFactory() {
    @Volatile
    private var delegate: SSLSocketFactory = newContext().socketFactory

    fun renew() {
        delegate = newContext().socketFactory
    }

    override fun getDefaultCipherSuites(): Array<String> = delegate.defaultCipherSuites
    override fun getSupportedCipherSuites(): Array<String> = delegate.supportedCipherSuites
    override fun createSocket(s: Socket?, host: String?, port: Int, autoClose: Boolean): Socket = delegate.createSocket(s, host, port, autoClose)
    override fun createSocket(): Socket = delegate.createSocket()
    override fun createSocket(host: String?, port: Int): Socket = delegate.createSocket(host, port)
    override fun createSocket(host: String?, port: Int, localHost: InetAddress?, localPort: Int): Socket = delegate.createSocket(host, port, localHost, localPort)
    override fun createSocket(host: InetAddress?, port: Int): Socket = delegate.createSocket(host, port)
    override fun createSocket(address: InetAddress?, port: Int, localAddress: InetAddress?, localPort: Int): Socket =
        delegate.createSocket(address, port, localAddress, localPort)
}
