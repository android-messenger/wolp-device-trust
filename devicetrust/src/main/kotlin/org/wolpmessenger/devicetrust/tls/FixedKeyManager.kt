package org.wolpmessenger.devicetrust.tls

import org.wolpmessenger.devicetrust.api.ClientCredentials
import java.net.Socket
import java.security.Principal
import java.security.PrivateKey
import java.security.cert.X509Certificate
import javax.net.ssl.SSLEngine
import javax.net.ssl.X509ExtendedKeyManager

/**
 * Presents exactly one client certificate (S2 §10). The private key is an AndroidKeyStore
 * handle — Conscrypt signs inside Keystore, the bytes never leave it.
 */
internal class FixedKeyManager(private val credentials: ClientCredentials) : X509ExtendedKeyManager() {
    override fun chooseClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, socket: Socket?): String = ALIAS
    override fun chooseEngineClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, engine: SSLEngine?): String = ALIAS
    override fun getClientAliases(keyType: String?, issuers: Array<out Principal>?): Array<String> = arrayOf(ALIAS)
    override fun getCertificateChain(alias: String?): Array<X509Certificate>? = credentials.chain.takeIf { alias == ALIAS }
    override fun getPrivateKey(alias: String?): PrivateKey? = credentials.privateKey.takeIf { alias == ALIAS }

    // client side only
    override fun getServerAliases(keyType: String?, issuers: Array<out Principal>?): Array<String>? = null
    override fun chooseServerAlias(keyType: String?, issuers: Array<out Principal>?, socket: Socket?): String? = null

    private companion object {
        const val ALIAS = "dt-client"
    }
}
