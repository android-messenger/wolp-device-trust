package org.wolpmessenger.devicetrust.api

/** Gateway error codes (S3 §5.9, S2 §4). Unknown strings map to [UNKNOWN]. */
public enum class GatewayCode {
    NO_SESSION, USER_MISMATCH, CERT_INVALID, CERT_UNKNOWN, CERT_SUPERSEDED, CERT_EXPIRED,
    DEVICE_REVOKED, DEVICE_REPLACED, IDENTITY_REVOKED, DEVICE_POLICY, UPDATE_REQUIRED, NONCE_INVALID, RATE_LIMITED,
    REATTEST_NOT_ALLOWED,

    // enroll-only codes (S3 §5.1–5.2)
    NO_PASSWORD, PASSWORD_EXPIRED, PASSWORD_BURNED, WRONG_PASSWORD, CSR_INVALID, POLICY_REJECTED,
    UNKNOWN;

    public companion object {
        public fun parse(s: String?): GatewayCode = entries.firstOrNull { it.name == s && it != UNKNOWN } ?: UNKNOWN
    }
}
