package org.wolpmessenger.devicetrust.api

import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

/** HTTP timeouts of the gateway client (S2 §12). */
public data class Timeouts(val connect: Duration = 10.seconds, val read: Duration = 20.seconds)

/**
 * Library configuration (S2 §12). Fields of later stages (RASP policy, work interval,
 * build kind, report limits…) are added with those stages.
 */
public data class DeviceTrustConfig(
    /** `https://enroll.<host>` — enrollment and recovery (S3 §5.1–5.2, §5.6). */
    val enrollBaseUrl: String = "",
    /** `https://app.<host>` — mTLS endpoints (S3 §5.3–5.8). */
    val appBaseUrl: String = "",
    /** Server key pins `sha256/<base64 SPKI hash>` for both hosts: primary and backup (S2 §10). */
    val serverPins: List<String> = emptyList(),
    /** Device key in StrongBox (with TEE fallback); default TEE until stage-1 measurements decide (S2 §3, R4). */
    val deviceKeyStrongBox: Boolean = false,
    /** Oldest acceptable `SECURITY_PATCH`, in months (S2 §6.1 п. 3). */
    val maxPatchAgeMonths: Int = 12,
    /** = `DEVICES_ENROLL_REPLAY_TTL` (S3): window to replay a lost `enroll/finish` (S2 §6.6 п. 2a). */
    val enrollReplayTtl: Duration = 15.minutes,
    /** = `DEVICES_REATTEST_GRACE` (S3): how long after `notAfter` recovery is still possible (`ExpiredGrace`). */
    val reattestGrace: Duration = 7.days,
    val httpTimeouts: Timeouts = Timeouts(),
    /** Period of the background `RenewWorker` (S2 §6.5). */
    val workInterval: Duration = 12.hours,
    /** Kratos cookie for replaying a lost `enroll/finish` at start-up (S2 §6.6 п. 2a); S1 reads it from CookieManager. */
    val cookieProvider: () -> String? = { null },
) {
    /** Checks what the network side needs; called by `DeviceTrust.init`. */
    public fun validateForNetwork() {
        require(enrollBaseUrl.startsWith("https://")) { "enrollBaseUrl must be https" }
        require(appBaseUrl.startsWith("https://")) { "appBaseUrl must be https" }
        require(serverPins.size >= 2) { "serverPins needs a primary and a backup pin (S2 §10)" }
        require(serverPins.all { it.startsWith("sha256/") }) { "pins must be sha256/<base64>" }
    }
}
