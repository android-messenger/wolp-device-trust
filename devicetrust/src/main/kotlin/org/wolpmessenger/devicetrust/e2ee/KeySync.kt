package org.wolpmessenger.devicetrust.e2ee

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.File

/**
 * Keeps this device's record in the key directory right (specs/002, story 3): publishes the keys
 * with the passport, republishes after a certificate renewal or a prekey replacement, tops up the
 * one-time keys and notices a record that is not this device's.
 *
 * One pass at a time (the "race of publications" edge case); a pass that fails changes nothing in
 * the directory it did not finish and is simply run again.
 */
internal class KeySync(
    private val me: String,
    private val chats: SecretChats,
    private val directory: OwnRecord,
    private val ownPassport: suspend (identityKey: ByteArray) -> Passport,
    /** The directory holds another key for this account although this device published its own (FR-025). */
    private val onForeignKey: () -> Unit,
    /** Exists once this installation's identity key was published; lives and dies with the secret-chat files. */
    private val published: File,
) {
    private val mutex = Mutex()

    /** One pass. Throws `E2eeException`: `LOCKED`, `NOT_ENROLLED`, `NO_NETWORK` — the caller repeats later. */
    suspend fun sync(): Unit = mutex.withLock {
        val identity = chats.identityKey()
        val passport = ownPassport(identity)
        val id = chats.directoryId()
        val rotated = chats.rotateSignedKeys(ROTATE_AFTER_MS)

        val record = directory.record(me)
        val ours = record != null && record.deviceId == id && record.identityKey.contentEquals(identity)
        // before the first publication the record is the previous phone's or a browser's: expected
        if (record != null && !record.identityKey.contentEquals(identity) && published.exists()) onForeignKey()

        val left = if (ours) directory.count(id) else null
        val upToDate = ours && left != null && !rotated && record?.passportCertificate?.contentEquals(passport.certificates.first()) == true
        if (upToDate) {
            if (left!! >= LOW) return@withLock
            if (directory.replenish(id, chats.ownKeys(FULL - left).oneTimePreKeys)) return@withLock
            // the record vanished between the two calls (revoked, replaced): publish it whole
        }
        directory.publish(id, chats.ownKeys((FULL - (left ?: 0)).coerceAtLeast(0)), passport)
        published.createNewFile()
    }

    internal companion object {
        /** FR-024: fewer than [LOW] one-time keys left → top up to [FULL]. */
        const val LOW = 20
        const val FULL = 100

        /** The signed and the post-quantum prekey are replaced every two days; the replaced ones decrypt for 30 more. */
        const val ROTATE_AFTER_MS = 2L * 24 * 60 * 60 * 1000
    }
}
