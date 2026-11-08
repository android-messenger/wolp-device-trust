package org.wolpmessenger.devicetrust.api

import java.time.Duration

/** Outcome of enrollment (S2 §4, §6.2). */
public sealed interface EnrollResult {
    public data class Ok(val deviceId: String) : EnrollResult

    /** Always ≥ 1; the attempt that exhausts the limit is [PasswordBurned]. */
    public data class WrongPassword(val attemptsLeft: Int) : EnrollResult
    public data object PasswordBurned : EnrollResult
    public data object PasswordExpired : EnrollResult
    public data object NoPassword : EnrollResult
    public data object NoSession : EnrollResult
    public data class PolicyRejected(val reason: String) : EnrollResult

    /** `APP_VERSION_TOO_OLD` → APP; `PATCH_TOO_OLD` / `OS_TOO_OLD` → OS. */
    public data class UpdateRequired(val kind: UpdateKind) : EnrollResult
    public data class Unsupported(val reasons: List<String>) : EnrollResult
    public data class Blocked(val reason: BlockReason) : EnrollResult
    public data class Transient(val cause: Throwable, val retryAfter: Duration?) : EnrollResult
}
