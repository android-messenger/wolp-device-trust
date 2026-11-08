package org.wolpmessenger.devicetrust.keys

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import org.wolpmessenger.devicetrust.api.SecurityLevel
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec

/**
 * The few Android Keystore operations the library needs. Kept behind an interface so
 * that generation/fallback/cleanup logic ([KeystoreKeys]) is unit-tested on the JVM.
 */
internal interface KeyStoreBackend {
    /** Generates an EC P-256 SHA-256 signing key under [alias] (S2 §3, `dt.device.k<N>`). Throws on failure. */
    fun generateSigningKey(alias: String, challenge: ByteArray?, strongBox: Boolean)

    /** Attestation chain, leaf first; null if the alias has no certificate. */
    fun certificateChain(alias: String): List<X509Certificate>?

    fun securityLevel(alias: String): SecurityLevel
    fun delete(alias: String)
    fun aliases(): List<String>

    /** Handle of the private key (AndroidKeyStore: non-extractable, `encoded == null`). */
    fun privateKey(alias: String): PrivateKey?
    fun publicKey(alias: String): PublicKey?
}

internal class AndroidKeyStoreBackend : KeyStoreBackend {
    private fun keyStore(): KeyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

    override fun generateSigningKey(alias: String, challenge: ByteArray?, strongBox: Boolean) {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(false)
            .setUnlockedDeviceRequired(false)
            .setIsStrongBoxBacked(strongBox)
            .apply { if (challenge != null) setAttestationChallenge(challenge) }
            .build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER).apply {
            initialize(spec)
            generateKeyPair()
        }
    }

    override fun certificateChain(alias: String): List<X509Certificate>? =
        keyStore().getCertificateChain(alias)?.map { it as X509Certificate }

    override fun securityLevel(alias: String): SecurityLevel {
        val key = keyStore().getKey(alias, null) as? PrivateKey ?: return SecurityLevel.UNKNOWN
        val info = KeyFactory.getInstance(key.algorithm, PROVIDER).getKeySpec(key, KeyInfo::class.java)
        return when (info.securityLevel) {
            KeyProperties.SECURITY_LEVEL_SOFTWARE -> SecurityLevel.SOFTWARE
            KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> SecurityLevel.TRUSTED_ENVIRONMENT
            KeyProperties.SECURITY_LEVEL_STRONGBOX -> SecurityLevel.STRONGBOX
            KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE -> SecurityLevel.UNKNOWN_SECURE
            else -> SecurityLevel.UNKNOWN
        }
    }

    override fun delete(alias: String) {
        val ks = keyStore()
        if (ks.containsAlias(alias)) ks.deleteEntry(alias)
    }

    override fun aliases(): List<String> = keyStore().aliases().toList()

    override fun privateKey(alias: String): PrivateKey? = keyStore().getKey(alias, null) as? PrivateKey

    override fun publicKey(alias: String): PublicKey? = keyStore().getCertificate(alias)?.publicKey

    private companion object {
        const val PROVIDER = "AndroidKeyStore"
    }
}
