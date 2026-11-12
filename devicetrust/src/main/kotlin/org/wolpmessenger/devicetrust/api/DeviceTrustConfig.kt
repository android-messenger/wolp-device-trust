package org.wolpmessenger.devicetrust.api

import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

/** REPORT rate limits (S2 §7.4). */
public data class ReportLimit(
    /** One message per (check id, detail) per window. */
    val perCheckWindow: Duration = 24.hours,
    /** Findings per REPORT message. */
    val batch: Int = 20,
    /** Pending findings kept; the oldest are dropped beyond it. */
    val queue: Int = 100,
)

/** HTTP timeouts of the gateway client (S2 §12). */
public data class Timeouts(val connect: Duration = 10.seconds, val read: Duration = 20.seconds)

/**
 * Library configuration (S2 §12). The RASP fields (policy, build kind, dry run…) arrive with
 * the RASP checks.
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
    /** REPORT rate limits (S2 §7.4). */
    val reportRateLimit: ReportLimit = ReportLimit(),
    /** SHA-256 (hex) of the app signing certificates (`APK_SIGNATURE`, S2 §7.1); required unless the app is debuggable. */
    val expectedSigningDigests: List<String> = emptyList(),
    /** Reactions by check id; lowering below the default is ignored in release (S2 §7.3). */
    val raspPolicy: RaspPolicy = RaspPolicy.default(),
    /** RASP period while the app is in the foreground (S2 §7.2). */
    val raspIntervalForeground: Duration = 5.minutes,
    /** Declared build kind; checked in CI and at runtime (S2 §7.3). */
    val buildKind: BuildKind = BuildKind.RELEASE,
    /** The pilot range of `versionCode`: last two digits 90–99 (pilot 10290..10299 → release 10300). */
    val pilotVersionCode: (Long) -> Boolean = { it % 100 >= 90 },
    /** Pilot / debug only: every BLOCK becomes a REPORT marked `dryRun` (S2 §7.3); ignored in a release build. */
    val raspDryRun: Boolean = false,
    /**
     * Secret chats (specs/002): the root certificates of the device authority of this contour, PEM
     * text. A peer's key is accepted only with a device certificate that chains to one of them. A
     * production build carries the production root only. Empty (with [e2eeIssuers]) — `DeviceTrust.e2ee`
     * is off.
     */
    val e2eeRoots: List<String> = emptyList(),
    /** SHA-256 of the public key (SPKI, hex) of every authority allowed to issue device certificates. */
    val e2eeIssuers: List<String> = emptyList(),
) {
    /** Checks what the network side needs; called by `DeviceTrust.init`. */
    public fun validateForNetwork() {
        require(enrollBaseUrl.startsWith("https://")) { "enrollBaseUrl must be https" }
        require(appBaseUrl.startsWith("https://")) { "appBaseUrl must be https" }
        require(serverPins.size >= 2) { "serverPins needs a primary and a backup pin (S2 §10)" }
        require(serverPins.all { it.startsWith("sha256/") }) { "pins must be sha256/<base64>" }
    }
}
