package org.wolpmessenger.devicetrust.api

import java.time.Instant

public enum class UpdateKind { APP, OS }

/** Why the device is blocked (S1 picks the text by it). */
public enum class BlockReason { RASP, REVOKED, REPLACED, IDENTITY_REVOKED, POLICY }

/** Device trust state (S2 §4, transitions §5.1). */
public sealed interface TrustState {
    public data object Uninitialized : TrustState
    public data object NotEnrolled : TrustState
    public data class Active(val notAfter: Instant, val renewAfter: Instant) : TrustState
    public data class RenewalDue(val notAfter: Instant) : TrustState
    public data class ExpiredGrace(val graceUntil: Instant) : TrustState

    /** Holds until a successful enroll (does not fall back to NotEnrolled by itself). */
    public data object ReEnrollRequired : TrustState

    /** Keys are kept; cleared after the app or OS is updated (S2 §6.6 п. 5). */
    public data class UpdateRequired(val kind: UpdateKind, val reason: String) : TrustState
    public data class Blocked(val reason: BlockReason) : TrustState
}
