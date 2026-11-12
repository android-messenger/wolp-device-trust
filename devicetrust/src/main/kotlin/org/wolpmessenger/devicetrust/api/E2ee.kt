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

/** How far the peer's key is trusted; [code] goes to the web app as is. */
public enum class E2eePeerTrust(public val code: String) {
    /** No key of the peer is accepted yet. */
    UNVERIFIED("unverified"),

    /** The key came with a passport that passed the checks. */
    PASSPORT("passport"),

    /** The user compared the safety number. */
    VERIFIED("verified"),

    /** Was [VERIFIED], then the key changed: encryption is refused until the user verifies again or drops the mark. */
    REVERIFY("reverify"),
}

/** [keyChanged] is true once after the peer's key was replaced: reading the state takes the mark off. */
public class E2eePeerState(public val trust: E2eePeerTrust, public val keyChanged: Boolean)

/**
 * Secret chats (specs/002): the six operations the app's bridge hands to the web app. [peer] is the
 * peer's account id. No operation returns a key or signs the caller's data; every refusal is an
 * [E2eeException] with a reason from the closed list [E2eeFailure]. All of them are main-safe.
 *
 * The keys live in the library's files under the Vault; the library itself publishes them to the
 * key directory, takes the peer's keys there and checks their passport.
 */
public interface E2ee {
    /** The envelope (`E2EE2:…`) to put into the message body. */
    public suspend fun encrypt(peer: String, text: String): String

    /** The text of an envelope made by the peer's [encrypt]. */
    public suspend fun decrypt(peer: String, envelope: String): String

    public suspend fun peerState(peer: String): E2eePeerState

    /** 60 digits to compare with the peer, or null while no key of the peer is accepted. */
    public suspend fun safetyNumber(peer: String): String?

    /** The user compared the safety number ([verified]) or drops the mark. */
    public suspend fun setVerified(peer: String, verified: Boolean)

    /**
     * Message recovery: the next [encrypt] takes the peer's keys from the directory and builds a new
     * session; the current one still decrypts. Call on a recovery request, at most once in 10 s per peer.
     */
    public suspend fun resetSession(peer: String)
}
