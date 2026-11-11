package org.wolpmessenger.devicetrust.vault

import android.content.Context
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.wolpmessenger.devicetrust.InternalDeviceTrustApi
import org.wolpmessenger.devicetrust.api.Vault
import org.wolpmessenger.devicetrust.api.VaultException
import org.wolpmessenger.devicetrust.api.VaultPurpose
import org.wolpmessenger.devicetrust.io.AtomicFiles
import java.io.File
import java.security.GeneralSecurityException
import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Whether the vault keys are in place (used by the init reconciliation, S2 §6.6 п. 4). */
@InternalDeviceTrustApi
public enum class VaultKeys { PRESENT, MISSING, PARTIAL }

/**
 * Envelope vault (S2 §9):
 * - KEK `dt.vault` in Keystore encrypts only the DEK; `dt/dek.bin` = `0x01 ‖ iv ‖ KEK-GCM(DEK)`
 *   with AAD `"wolp-dek-v1"`. Unwrapping the DEK is the only Keystore operation, done once per process;
 * - `wrap`/`unwrap` run software AES-256-GCM on the in-memory DEK:
 *   blob `0x02 ‖ iv(12) ‖ ciphertext ‖ tag(16)`,
 *   AAD `0x02 ‖ iv ‖ "wolp-vault-v1|" ‖ purpose.tag ‖ ("|" ‖ extraAad)?` — the header is authenticated.
 */
@InternalDeviceTrustApi
public class EnvelopeVault internal constructor(
    private val kek: Kek,
    private val dekFile: File,
    private val unlock: UnlockState,
    private val random: SecureRandom = SecureRandom(),
    /** Throws [VaultException.Locked] while secrets must not be used (rasp/IntegrityGate); checked on every wrap / unwrap. */
    private val gate: suspend () -> Unit = {},
) : Vault {
    private val loadMutex = Mutex()

    @Volatile
    private var dek: ByteArray? = null

    /** Creates KEK and DEK if absent (called after a successful `enroll/finish`, S2 §6.2). Returns true if anything was created. */
    public suspend fun provision(): Boolean = loadMutex.withLock {
        if (!unlock.isUserUnlocked()) throw VaultException.Locked()
        when (keys()) {
            VaultKeys.PRESENT -> false
            VaultKeys.MISSING, VaultKeys.PARTIAL -> {
                wipeLocked()
                kek.create()
                val fresh = ByteArray(DEK_LEN).also(random::nextBytes)
                AtomicFiles.write(dekFile, byteArrayOf(DEK_VERSION) + kek.encrypt(fresh, DEK_AAD))
                dek = fresh
                true
            }
        }
    }

    /** Current state of the persistent keys (no Keystore crypto). */
    public fun keys(): VaultKeys {
        val hasKek = kek.exists()
        val hasDek = dekFile.exists()
        return when {
            hasKek && hasDek -> VaultKeys.PRESENT
            !hasKek && !hasDek -> VaultKeys.MISSING
            else -> VaultKeys.PARTIAL
        }
    }

    /** Destroys KEK, DEK file and the in-memory DEK (BLOCK, unenroll — S2 §8 п. 5, §6.5a). Idempotent. */
    public suspend fun wipe(): Unit = loadMutex.withLock { wipeLocked() }

    private fun wipeLocked() {
        dek?.fill(0)
        dek = null
        dekFile.delete()
        kek.delete()
    }

    override suspend fun wrap(plain: ByteArray, purpose: VaultPurpose, extraAad: ByteArray?): ByteArray {
        val key = loadedDek()
        val iv = ByteArray(IV_LEN).also(random::nextBytes)
        val c = Cipher.getInstance(GCM)
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, iv))
        c.updateAAD(aad(iv, purpose, extraAad))
        return byteArrayOf(BLOB_VERSION) + iv + c.doFinal(plain)
    }

    override suspend fun unwrap(blob: ByteArray, purpose: VaultPurpose, extraAad: ByteArray?): ByteArray {
        if (blob.size < 1 + IV_LEN + TAG_BITS / 8 || blob[0] != BLOB_VERSION) throw VaultException.Corrupt("unknown blob format")
        val key = loadedDek()
        val iv = blob.copyOfRange(1, 1 + IV_LEN)
        return try {
            val c = Cipher.getInstance(GCM)
            c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, iv))
            c.updateAAD(aad(iv, purpose, extraAad))
            c.doFinal(blob, 1 + IV_LEN, blob.size - 1 - IV_LEN)
        } catch (e: AEADBadTagException) {
            throw VaultException.Corrupt("authentication failed (damaged blob or wrong purpose)", e)
        }
    }

    private suspend fun loadedDek(): ByteArray {
        gate()
        dek?.let { return it }
        return loadMutex.withLock {
            dek ?: loadDek().also { dek = it }
        }
    }

    private fun loadDek(): ByteArray {
        if (!unlock.isUserUnlocked()) throw VaultException.Locked()
        if (!kek.exists() || !dekFile.exists()) throw VaultException.KeyGone()
        val stored = dekFile.readBytes()
        if (stored.size != DEK_FILE_LEN || stored[0] != DEK_VERSION) throw VaultException.KeyGone("unknown DEK file format")
        return try {
            kek.decrypt(stored.copyOfRange(1, stored.size), DEK_AAD).also {
                if (it.size != DEK_LEN) throw VaultException.KeyGone("DEK has wrong length")
            }
        } catch (e: GeneralSecurityException) {
            // KEK replaced or DEK file damaged: the DEK is unrecoverable (S2 §6.6 п. 4 → VaultReset).
            throw VaultException.KeyGone("DEK cannot be decrypted", e)
        }
    }

    private fun aad(iv: ByteArray, purpose: VaultPurpose, extra: ByteArray?): ByteArray {
        val label = (AAD_LABEL + purpose.tag).toByteArray(Charsets.US_ASCII)
        val tail = if (extra != null) byteArrayOf('|'.code.toByte()) + extra else ByteArray(0)
        return byteArrayOf(BLOB_VERSION) + iv + label + tail
    }

    public companion object {
        internal const val BLOB_VERSION: Byte = 0x02
        internal const val DEK_VERSION: Byte = 0x01
        internal const val IV_LEN = 12
        internal const val TAG_BITS = 128
        internal const val DEK_LEN = 32
        private const val DEK_FILE_LEN = 1 + IV_LEN + DEK_LEN + TAG_BITS / 8
        internal const val AAD_LABEL = "wolp-vault-v1|"
        internal val DEK_AAD = "wolp-dek-v1".toByteArray(Charsets.US_ASCII)
        private const val GCM = "AES/GCM/NoPadding"

        /** Vault over the platform Keystore; DEK file in `noBackupFilesDir/dt/dek.bin` (S2 §11). */
        public fun android(context: Context): EnvelopeVault = android(context) {}

        internal fun android(context: Context, gate: suspend () -> Unit): EnvelopeVault = EnvelopeVault(
            kek = AndroidKek(),
            dekFile = File(context.noBackupFilesDir, "dt/dek.bin"),
            unlock = UnlockState.android(context),
            gate = gate,
        )
    }
}
