package org.wolpmessenger.devicetrust.api

/**
 * What a Vault blob protects. The tag is bound into the AEAD associated data, so a blob
 * wrapped for one purpose never unwraps for another (S2 §9). From JS (S1) only [E2EE] and
 * [E2EE_PLAINTEXT] are reachable — the plugin enforces that.
 */
public enum class VaultPurpose(public val tag: String) {
    E2EE("e2ee"),
    E2EE_PLAINTEXT("e2ee-plaintext"),
    NAMES("names"),
    PUSH_KEY("push-key"),
}

/** Vault failures (S2 §9). */
public sealed class VaultException(message: String, cause: Throwable? = null) : Exception(message, cause) {
    /** The vault keys were destroyed (BLOCK, unenroll) or never created. Data wrapped before is unrecoverable. */
    public class KeyGone(message: String = "vault key is gone", cause: Throwable? = null) : VaultException(message, cause)

    /**
     * Temporarily unavailable, nothing is lost: before the first unlock after boot (credential-encrypted
     * storage), or while the integrity check of this process has not passed (see `DeviceTrust.checkIntegrity`).
     */
    public class Locked(message: String = "device not unlocked since boot") : VaultException(message)

    /** Damaged blob, unknown format, or wrong purpose / extra AAD. */
    public class Corrupt(message: String = "vault blob rejected", cause: Throwable? = null) : VaultException(message, cause)
}

/** Envelope-encrypted storage for E2EE secrets (S2 §9). */
public interface Vault {
    /** Encrypts [plain]; the result is `0x02 ‖ iv(12) ‖ ciphertext ‖ tag(16)`. */
    public suspend fun wrap(plain: ByteArray, purpose: VaultPurpose, extraAad: ByteArray? = null): ByteArray

    /** Decrypts a blob made by [wrap] with the same [purpose] and [extraAad]. Throws [VaultException]. */
    public suspend fun unwrap(blob: ByteArray, purpose: VaultPurpose, extraAad: ByteArray? = null): ByteArray
}
