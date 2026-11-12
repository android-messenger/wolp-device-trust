package org.wolpmessenger.devicetrust.e2ee

import org.wolpmessenger.devicetrust.api.E2eeException

/** A prekey signed by the identity key: the signed EC prekey or the post-quantum (Kyber-1024) one. */
internal class SignedKey(val id: Int, val publicKey: ByteArray, val signature: ByteArray)

internal class OneTimeKey(val id: Int, val publicKey: ByteArray)

/** The peer's device record as the key directory returns it; keys are serialized the libsignal way. */
internal class PeerKeys(
    val identityKey: ByteArray,
    val registrationId: Int,
    val signedPreKey: SignedKey,
    val pqPreKey: SignedKey,
    /** null when the peer ran out of one-time keys and has no last-resort one: the session is still built. */
    val oneTimePreKey: OneTimeKey?,
    /** null when the record was published without one (a browser, an older app). */
    val passport: Passport? = null,
)

/** What this device publishes: public halves only. */
internal class OwnKeys(
    val identityKey: ByteArray,
    val registrationId: Int,
    val signedPreKey: SignedKey,
    val pqPreKey: SignedKey,
    /** Only the one-time keys made by this call; the earlier ones are already in the directory. */
    val oneTimePreKeys: List<OneTimeKey>,
)

/** The only thing the protocol code needs from the key directory; the HTTP client is story 3 of specs/002. */
internal fun interface KeyDirectory {
    /**
     * Keys of the peer's single device. Throws [E2eeException] with `NO_NETWORK`, `NO_DEVICE` or
     * `MULTI_DEVICE`.
     */
    suspend fun fetch(user: String): PeerKeys
}
