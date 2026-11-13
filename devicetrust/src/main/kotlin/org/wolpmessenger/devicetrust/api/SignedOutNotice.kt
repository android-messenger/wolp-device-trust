package org.wolpmessenger.devicetrust.api

/**
 * Outcome of `DeviceTrust.reportSignedOut()`: whether the gateway now knows that the user of this
 * device signed out while the server could not be told (docs specs F5, part 2).
 */
public enum class SignedOutNotice {
    /** The gateway took the message (`202`); it removes the push token and the key-directory record. */
    DELIVERED,

    /** No device key (not enrolled, blocked, key lost): there is nothing this device could sign. */
    NOT_NEEDED,

    /** The gateway has no such route (`404`: older gateway or the flag is off) or will never take this message (`400`). */
    UNSUPPORTED,

    /** No network, the gateway is busy or down: call again later. */
    RETRY,
    ;

    /** False only for [RETRY]: nothing more to do. */
    public val done: Boolean get() = this != RETRY
}
