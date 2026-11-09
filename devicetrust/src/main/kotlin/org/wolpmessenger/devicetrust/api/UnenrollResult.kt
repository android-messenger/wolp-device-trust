package org.wolpmessenger.devicetrust.api

/** Whether the gateway still has to learn about an unenroll (S2 §6.5a). */
public enum class ServerNotice {
    /** A signed `UNENROLL` is queued; the gateway revokes the device when it arrives. */
    PENDING,

    /** No device key: the registry entry is unused already and a new enrollment replaces it. */
    NOT_NEEDED,
}

/** Outcome of `DeviceTrust.unenroll()`; the local part always completes (R5). */
public sealed interface UnenrollResult {
    public data class Ok(val serverNotified: ServerNotice) : UnenrollResult
}
