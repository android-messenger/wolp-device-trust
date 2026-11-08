package org.wolpmessenger.devicetrust

import org.wolpmessenger.devicetrust.api.SecurityLevel
import org.wolpmessenger.devicetrust.attest.CachedKeystoreLevel
import org.wolpmessenger.devicetrust.attest.DeviceEnvironment
import org.wolpmessenger.devicetrust.attest.PrecheckCache
import org.wolpmessenger.devicetrust.keys.KeyStoreBackend
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.LocalDate

fun cert(resource: String): X509Certificate =
    object {}.javaClass.classLoader!!.getResourceAsStream(resource)!!.use {
        CertificateFactory.getInstance("X.509").generateCertificate(it) as X509Certificate
    }

/** In-memory Keystore with scriptable failures per StrongBox/TEE attempt. */
internal class FakeBackend(
    var teeLevel: SecurityLevel = SecurityLevel.TRUSTED_ENVIRONMENT,
    var strongBoxLevel: SecurityLevel = SecurityLevel.STRONGBOX,
) : KeyStoreBackend {
    val keys = linkedMapOf<String, SecurityLevel>()
    val generated = mutableListOf<Pair<String, Boolean>>() // alias to strongBox
    var failGenerate: ((strongBox: Boolean) -> Exception?) = { null }
    var failChain: ((strongBox: Boolean) -> Exception?) = { null }
    private val strongBoxOf = mutableMapOf<String, Boolean>()
    val pairs = mutableMapOf<String, java.security.KeyPair>()
    val challenges = mutableMapOf<String, ByteArray?>()

    override fun generateSigningKey(alias: String, challenge: ByteArray?, strongBox: Boolean) {
        generated += alias to strongBox
        keys[alias] = if (strongBox) strongBoxLevel else teeLevel // half-made key exists even if we then fail
        strongBoxOf[alias] = strongBox
        challenges[alias] = challenge
        pairs[alias] = java.security.KeyPairGenerator.getInstance("EC")
            .apply { initialize(java.security.spec.ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        failGenerate(strongBox)?.let { throw it }
    }

    override fun certificateChain(alias: String): List<X509Certificate>? {
        if (alias !in keys) return null
        failChain(strongBoxOf.getValue(alias))?.let { throw it }
        return listOf(cert("plain.pem"))
    }

    override fun securityLevel(alias: String): SecurityLevel = keys[alias] ?: SecurityLevel.UNKNOWN
    override fun delete(alias: String) {
        keys.remove(alias)
    }

    override fun aliases(): List<String> = keys.keys.toList()
    override fun privateKey(alias: String) = pairs[alias]?.takeIf { alias in keys }?.private
    override fun publicKey(alias: String) = pairs[alias]?.takeIf { alias in keys }?.public
}

internal class FakeEnv(
    override var sdkInt: Int = 34,
    override var securityPatch: String = "2026-10-01",
    override var bootCount: Int = 7,
    override var versionCode: Long = 10300,
    override var hasStrongBox: Boolean = false,
    var secure: Boolean = true,
    var now: LocalDate = LocalDate.of(2026, 11, 8),
) : DeviceEnvironment {
    override fun isDeviceSecure(): Boolean = secure
    override fun today(): LocalDate = now
}

internal class MemCache(var value: CachedKeystoreLevel? = null) : PrecheckCache {
    var saves = 0
    override fun load(): CachedKeystoreLevel? = value
    override fun save(value: CachedKeystoreLevel) {
        this.value = value
        saves++
    }
}
