package org.wolpmessenger.devicetrust.api

/**
 * Where a Keystore key lives, as reported by `KeyInfo.getSecurityLevel()`.
 * Only [TRUSTED_ENVIRONMENT] and [STRONGBOX] are acceptable (S2 §3, R4).
 */
public enum class SecurityLevel {
    SOFTWARE,
    TRUSTED_ENVIRONMENT,
    STRONGBOX,

    /** Secure hardware of an unknown kind: cannot be confirmed, rejected like [SOFTWARE]. */
    UNKNOWN_SECURE,

    /** The platform could not tell: rejected like [SOFTWARE]. */
    UNKNOWN;

    /** True only for levels the policy accepts (TEE, StrongBox). */
    public val isHardwareConfirmed: Boolean
        get() = this == TRUSTED_ENVIRONMENT || this == STRONGBOX
}
