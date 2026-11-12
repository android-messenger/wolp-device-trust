package org.wolpmessenger.devicetrust.api

/**
 * Why a secret-chat operation was refused (specs/002, FR-032). The list is closed: [code] goes to
 * the web app through the bridge as is, the text for the user is the web app's.
 */
public enum class E2eeFailure(public val code: String) {
    /** The device is locked or the integrity check has not passed; nothing is lost, repeat after unlock. */
    LOCKED("locked"),

    /** The peer's key came without a passport: the peer is not in the app. */
    NO_PASSPORT("no_passport"),

    /** The peer's keys did not pass verification. */
    BAD_PASSPORT("bad_passport"),

    /** A peer verified by safety number changed the key: verify again or drop the mark. */
    REVERIFY("reverify"),

    /** The key directory returned more than one device for the peer. */
    MULTI_DEVICE("multi_device"),

    /** The peer has no device to encrypt to (also: encrypting to oneself). */
    NO_DEVICE("no_device"),

    /** The key directory cannot be reached and there is no session with the peer yet. */
    NO_NETWORK("no_network"),

    /** This message was already decrypted. */
    DUPLICATE("duplicate"),

    /** The message cannot be decrypted; the web app asks the sender to send it again. */
    UNDECRYPTABLE("undecryptable"),

    /** No vault key: the device is not enrolled (or the keys were destroyed and not recreated yet). */
    NOT_ENROLLED("not_enrolled"),
}

/** A refused secret-chat operation. The message never carries keys or message text. */
public class E2eeException(public val failure: E2eeFailure, cause: Throwable? = null) : Exception(failure.code, cause)
