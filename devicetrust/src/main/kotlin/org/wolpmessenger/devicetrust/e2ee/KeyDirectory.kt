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

/** The only thing the protocol code needs from the key directory; over HTTP it is [KeyDirectoryClient]. */
internal fun interface KeyDirectory {
    /**
     * Keys of the peer's single device. Throws [E2eeException] with `NO_NETWORK`, `NO_DEVICE`,
     * `MULTI_DEVICE` or `NO_PASSPORT` (a record that was not published by the app).
     */
    suspend fun fetch(user: String): PeerKeys
}

/** What the directory holds for an account: enough to see whether it is this device's record. */
internal class DirectoryRecord(
    val deviceId: String,
    val identityKey: ByteArray,
    /** The device certificate of the record's passport (DER), or null when it was published without one. */
    val passportCertificate: ByteArray?,
)

/** This device's own record in the key directory ([KeySync]). Every call throws [E2eeException] `NO_NETWORK` when the directory gave no answer. */
internal interface OwnRecord {
    /** The account's current record, or null when there is none. */
    suspend fun record(user: String): DirectoryRecord?

    /** One-time keys left for [deviceId], or null when the directory has no such device. */
    suspend fun count(deviceId: String): Int?

    /** Publishes or replaces the record. The passport goes with every publication: without it the directory erases the earlier one (FR-022). */
    suspend fun publish(deviceId: String, keys: OwnKeys, passport: Passport)

    /** Removes the record of [deviceId]; a record that is not there is not an error. */
    suspend fun remove(deviceId: String)

    /** Adds one-time keys; false when the directory has no such device (publish instead). */
    suspend fun replenish(deviceId: String, keys: List<OneTimeKey>): Boolean
}
