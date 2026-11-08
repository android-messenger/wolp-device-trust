package org.wolpmessenger.devicetrust.keys

import org.wolpmessenger.devicetrust.InternalDeviceTrustApi
import org.wolpmessenger.devicetrust.api.SecurityLevel
import java.security.InvalidAlgorithmParameterException
import java.security.KeyStoreException
import java.security.ProviderException
import java.security.cert.X509Certificate

/** A freshly generated, hardware-confirmed signing key. Private key bytes never leave Keystore. */
@InternalDeviceTrustApi
public class GeneratedKey(
    public val alias: String,
    /** Attestation chain, leaf first. */
    public val chain: List<X509Certificate>,
    public val level: SecurityLevel,
    /** StrongBox was requested but the key ended up in TEE. */
    public val strongBoxFallback: Boolean,
)

@InternalDeviceTrustApi
public sealed interface KeyGenResult {
    public class Ok(public val key: GeneratedKey) : KeyGenResult

    /** The key was not hardware-confirmed and has already been deleted (S2 §3 → `PolicyFailure(SOFTWARE_KEYSTORE)`). */
    public data class SoftwareKeystore(val level: SecurityLevel) : KeyGenResult
}

/**
 * Keystore keys of the library (S2 §3): generation with StrongBox → TEE fallback, level
 * verification, deletion and cleanup of orphaned device keys.
 */
@InternalDeviceTrustApi
public class KeystoreKeys internal constructor(private val backend: KeyStoreBackend) {

    /**
     * Generates an EC P-256 signing key. With [preferStrongBox] a StrongBox failure of any
     * kind listed in S2 §3 (StrongBoxUnavailableException ⊂ ProviderException, KeyStoreException,
     * InvalidAlgorithmParameterException — during generation or while reading the chain)
     * deletes the half-made alias and retries in TEE.
     *
     * A key whose level is not hardware-confirmed is deleted and reported as
     * [KeyGenResult.SoftwareKeystore]. Other failures propagate after the alias is removed.
     */
    public fun generate(alias: String, challenge: ByteArray?, preferStrongBox: Boolean): KeyGenResult {
        if (preferStrongBox) {
            try {
                return finish(alias, generateWithChain(alias, challenge, strongBox = true), fallback = false)
            } catch (e: Exception) {
                backend.delete(alias)
                if (!isStrongBoxFallbackTrigger(e)) throw e
            }
        }
        val chain = try {
            generateWithChain(alias, challenge, strongBox = false)
        } catch (e: Exception) {
            backend.delete(alias)
            throw e
        }
        return finish(alias, chain, fallback = preferStrongBox)
    }

    private fun isStrongBoxFallbackTrigger(e: Exception): Boolean =
        e is ProviderException || e is KeyStoreException || e is InvalidAlgorithmParameterException

    private fun generateWithChain(alias: String, challenge: ByteArray?, strongBox: Boolean): List<X509Certificate> {
        backend.generateSigningKey(alias, challenge, strongBox)
        val chain = backend.certificateChain(alias)
        if (chain.isNullOrEmpty()) throw KeyStoreException("no certificate chain for $alias")
        return chain
    }

    private fun finish(alias: String, chain: List<X509Certificate>, fallback: Boolean): KeyGenResult {
        val level = backend.securityLevel(alias)
        if (!level.isHardwareConfirmed) {
            backend.delete(alias)
            return KeyGenResult.SoftwareKeystore(level)
        }
        return KeyGenResult.Ok(GeneratedKey(alias, chain, level, fallback))
    }

    /**
     * Test-vector export only (`testvectors-export`): generates in exactly the requested
     * environment, without fallback and **without** rejecting a software key, so negative
     * vectors (emulator, software Keystore) can be exported for S3 §6.5. The caller deletes the key.
     * Never use this on an enrollment path.
     */
    public fun generateUnchecked(alias: String, challenge: ByteArray?, strongBox: Boolean): GeneratedKey {
        val chain = try {
            generateWithChain(alias, challenge, strongBox)
        } catch (e: Exception) {
            backend.delete(alias)
            throw e
        }
        return GeneratedKey(alias, chain, backend.securityLevel(alias), strongBoxFallback = false)
    }

    /** Private key handle for signing and TLS; bytes are never exposed (S2 §4). */
    public fun privateKey(alias: String): java.security.PrivateKey? = backend.privateKey(alias)

    public fun publicKey(alias: String): java.security.PublicKey? = backend.publicKey(alias)

    public fun delete(alias: String) {
        backend.delete(alias)
    }

    /** Device-key aliases present in Keystore, ordered by generation number. */
    public fun deviceKeyAliases(): List<String> =
        backend.aliases().filter { deviceKeyNumber(it) != null }.sortedBy { deviceKeyNumber(it) }

    /**
     * Next device alias: `dt.device.k<max+1>` over the aliases present, starting at `k1` (S2 §3).
     * While a key exists its number is never handed out again; after deletion it may be.
     */
    public fun nextDeviceAlias(): String {
        val max = backend.aliases().mapNotNull(::deviceKeyNumber).maxOrNull() ?: 0
        return "$DEVICE_PREFIX${max + 1}"
    }

    /**
     * Deletes every device key not in [keep] (orphans left by an interrupted generation or
     * renewal, S2 §6.6) and the precheck key. Returns the deleted aliases.
     */
    public fun deleteOrphans(keep: Set<String>): List<String> {
        val orphans = backend.aliases().filter { (deviceKeyNumber(it) != null && it !in keep) || it == PRECHECK_ALIAS }
        orphans.forEach(backend::delete)
        return orphans
    }

    public companion object {
        public const val DEVICE_PREFIX: String = "dt.device.k"
        public const val PRECHECK_ALIAS: String = "dt.precheck"
        public const val VAULT_ALIAS: String = "dt.vault"

        /** Keystore keys backed by the platform `AndroidKeyStore`. */
        public fun android(): KeystoreKeys = KeystoreKeys(AndroidKeyStoreBackend())

        internal fun deviceKeyNumber(alias: String): Int? =
            alias.removePrefix(DEVICE_PREFIX).takeIf { alias.startsWith(DEVICE_PREFIX) }?.toIntOrNull()?.takeIf { it > 0 }
    }
}
