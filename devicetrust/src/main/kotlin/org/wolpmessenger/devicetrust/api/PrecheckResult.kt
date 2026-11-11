package org.wolpmessenger.devicetrust.api

/** Why the device cannot be enrolled at all (S1 shows UnsupportedScreen with the reason). */
public enum class UnsupportedReason {
    /** Keystore keys are not confirmed hardware-backed (S2 §3). */
    SOFTWARE_KEYSTORE,

    /** `SECURITY_PATCH` is older than `maxPatchAgeMonths`, or unparseable (S2 §6.1 п. 3). */
    PATCH_TOO_OLD,

    /** No PIN, pattern or password: the E2EE key is bound to the lock screen, so there must be one. */
    NO_SCREEN_LOCK,
}

/** Outcome of [org.wolpmessenger.devicetrust.attest.Precheck] (S2 §6.1). */
public sealed interface PrecheckResult {
    /** Enrollment may proceed. [reports] are REPORT-level findings (e.g. `NO_SCREEN_LOCK`). */
    public data class Supported(val info: DeviceSecurityInfo, val reports: List<RaspFinding>) : PrecheckResult

    /** The device does not meet the policy; nothing is sent to the gateway. */
    public data class Unsupported(val reasons: List<UnsupportedReason>, val info: DeviceSecurityInfo?) : PrecheckResult

    /** RASP found a BLOCK-level issue; the caller runs the BLOCK reaction (S2 §8). */
    public data class Compromised(val report: RaspReport) : PrecheckResult
}
