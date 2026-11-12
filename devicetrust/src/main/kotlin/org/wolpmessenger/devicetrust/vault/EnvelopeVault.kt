package org.wolpmessenger.devicetrust.vault

import android.content.Context
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.wolpmessenger.devicetrust.InternalDeviceTrustApi
import org.wolpmessenger.devicetrust.Journal
import org.wolpmessenger.devicetrust.api.Vault
import org.wolpmessenger.devicetrust.api.VaultException
import org.wolpmessenger.devicetrust.api.VaultPurpose
import org.wolpmessenger.devicetrust.io.AtomicFiles
import org.wolpmessenger.devicetrust.keys.KeystoreKeys
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
 * Envelope vault (S2 §9; two keys since specs/001-rasp-hardening, story 2).
 *
 * Each half has a KEK in Keystore that encrypts only its DEK; `wrap`/`unwrap` run software
 * AES-256-GCM on the in-memory DEK: blob `0x02 ‖ iv(12) ‖ ciphertext ‖ tag(16)`,
 * AAD `0x02 ‖ iv ‖ "wolp-vault-v1|" ‖ purpose.tag ‖ ("|" ‖ extraAad)?`.
 *
 * | half       | purposes               | KEK          | DEK file    | available                         |
 * |------------|------------------------|--------------|-------------|-----------------------------------|
 * | background | `NAMES`, `PUSH_KEY`    | `dt.vault`   | `dek.bin`   | after the first unlock since boot |
 * | E2EE       | `E2EE`, `E2EE_PLAINTEXT` | `dt.vault.u` | `dek-u.bin` | only while the device is unlocked |
 *
 * The E2EE KEK is refused by the system Keystore while the device is locked, the E2EE DEK leaves
 * memory at screen-off, and a device whose screen lock was removed loses the E2EE half for good.
 * Push keeps working behind the lock screen with the background half.
 *
 * DEK file: `version ‖ iv ‖ KEK-GCM(DEK)`. Version `0x01` in `dek.bin` is the older single-key
 * vault whose one DEK covered every purpose; [migrate] turns it into the two-key layout without
 * touching E2EE blobs. Until then it keeps working as before. Without [boundKek] the vault is
 * single-key (tests, tools).
 */
@InternalDeviceTrustApi
public class EnvelopeVault internal constructor(
    private val kek: Kek,
    private val dekFile: File,
    private val unlock: UnlockState,
    private val random: SecureRandom = SecureRandom(),
    /** Throws [VaultException.Locked] while secrets must not be used (rasp/IntegrityGate); checked on every wrap / unwrap. */
    private val gate: suspend () -> Unit = {},
    private val boundKek: Kek? = null,
    private val boundDekFile: File? = null,
    private val screen: ScreenLock = ScreenLock.Unknown,
) : Vault {
    private val loadMutex = Mutex()
    private val twoKeys = boundKek != null && boundDekFile != null

    @Volatile
    private var dek: ByteArray? = null

    @Volatile
    private var boundDek: ByteArray? = null

    private fun fileVersion(f: File): Byte? = runCatching { f.inputStream().use { it.read() } }.getOrNull()?.takeIf { it >= 0 }?.toByte()

    /** Cached answer of [legacy]; reset whenever this class rewrites or deletes `dek.bin`. */
    @Volatile
    private var legacyMemo: Boolean? = null

    /** `dek.bin` still holds the single DEK of the older layout. */
    private fun legacy(): Boolean {
        if (!twoKeys) return false
        legacyMemo?.let { return it }
        return (dekFile.exists() && fileVersion(dekFile) == LEGACY_VERSION).also { legacyMemo = it }
    }

    private val openVersion: Byte get() = if (twoKeys) SLOT_VERSION else LEGACY_VERSION

    /** Creates the keys if absent (called after a successful `enroll/finish`, S2 §6.2). Returns true if anything was created. */
    public suspend fun provision(): Boolean = loadMutex.withLock {
        if (!unlock.isUserUnlocked()) throw VaultException.Locked()
        when (keys()) {
            VaultKeys.PRESENT -> false
            VaultKeys.MISSING, VaultKeys.PARTIAL -> {
                if (twoKeys) requireUsableScreenLock()
                wipeLocked()
                legacyMemo = false
                kek.create()
                val fresh = ByteArray(DEK_LEN).also(random::nextBytes)
                AtomicFiles.write(dekFile, byteArrayOf(openVersion) + kek.encrypt(fresh, DEK_AAD))
                dek = fresh
                if (twoKeys) {
                    boundKek!!.create()
                    val e2ee = ByteArray(DEK_LEN).also(random::nextBytes)
                    AtomicFiles.write(boundDekFile!!, byteArrayOf(SLOT_VERSION) + boundKek.encrypt(e2ee, BOUND_DEK_AAD))
                    boundDek = e2ee
                }
                true
            }
        }
    }

    private fun requireUsableScreenLock() {
        if (!screen.isSecure()) throw VaultException.Locked("a screen lock is required")
        if (!screen.isUnlockedNow()) throw VaultException.Locked("device is locked")
    }

    /**
     * Older single-key vault → two keys, when the device is unlocked and has a screen lock:
     * the existing DEK (which every E2EE blob was made with) moves under the unlocked-device KEK,
     * and the background half gets a fresh DEK — the old one must not stay reachable behind the
     * lock screen. Blobs of `NAMES` / `PUSH_KEY` made before stop unwrapping (the caller tells S1).
     * Idempotent and crash-safe: `dek.bin` stays the old one until the E2EE half is on disk.
     * Returns true if the move happened now.
     */
    public suspend fun migrate(): Boolean = loadMutex.withLock {
        if (!legacy() || !kek.exists()) return@withLock false
        if (!unlock.isUserUnlocked() || !screen.isSecure() || !screen.isUnlockedNow()) return@withLock false
        val old = try {
            kek.decrypt(dekFile.readBytes().let { it.copyOfRange(1, it.size) }, DEK_AAD)
        } catch (e: GeneralSecurityException) {
            return@withLock false // unreadable: the reconciliation treats it like a lost vault
        }
        if (old.size != DEK_LEN) return@withLock false
        if (!boundKek!!.exists()) boundKek.create()
        AtomicFiles.write(boundDekFile!!, byteArrayOf(SLOT_VERSION) + boundKek.encrypt(old, BOUND_DEK_AAD))
        val fresh = ByteArray(DEK_LEN).also(random::nextBytes)
        AtomicFiles.write(dekFile, byteArrayOf(SLOT_VERSION) + kek.encrypt(fresh, DEK_AAD))
        legacyMemo = false
        dek = fresh
        boundDek = old
        Journal.event("vault_migrated")
        true
    }

    /** Current state of the persistent keys (no Keystore crypto). */
    public fun keys(): VaultKeys {
        val open = kek.exists() to dekFile.exists()
        if (!twoKeys) return state(listOf(open))
        if (open.first && open.second && legacy()) return VaultKeys.PRESENT // works as before until migrate()
        return state(listOf(open, boundKek!!.exists() to boundDekFile!!.exists()))
    }

    private fun state(parts: List<Pair<Boolean, Boolean>>): VaultKeys = when {
        parts.all { it.first && it.second } -> VaultKeys.PRESENT
        parts.none { it.first || it.second } -> VaultKeys.MISSING
        else -> VaultKeys.PARTIAL
    }

    /** Destroys every KEK, DEK file and in-memory DEK (BLOCK, unenroll — S2 §8 п. 5, §6.5a). Idempotent. */
    public suspend fun wipe(): Unit = loadMutex.withLock { wipeLocked() }

    private fun wipeLocked() {
        // the reference is dropped, not zeroed (as in evictUnlockedKey): a wrap that already holds the
        // array would otherwise encrypt with a key of zeroes and leave that blob on disk
        dek = null
        dekFile.delete()
        kek.delete()
        legacyMemo = null
        wipeBound()
    }

    private fun wipeBound() {
        boundDek = null
        boundDekFile?.delete()
        boundKek?.delete()
    }

    /**
     * Screen went off: the E2EE DEK leaves memory (FR-012). The reference is dropped, not zeroed —
     * an operation that already holds the array must finish with the real key.
     */
    internal fun evictUnlockedKey() {
        if (twoKeys) boundDek = null
    }

    override suspend fun wrap(plain: ByteArray, purpose: VaultPurpose, extraAad: ByteArray?): ByteArray {
        val key = dekFor(purpose)
        val iv = ByteArray(IV_LEN).also(random::nextBytes)
        val c = Cipher.getInstance(GCM)
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, iv))
        c.updateAAD(aad(iv, purpose, extraAad))
        return byteArrayOf(BLOB_VERSION) + iv + c.doFinal(plain)
    }

    override suspend fun unwrap(blob: ByteArray, purpose: VaultPurpose, extraAad: ByteArray?): ByteArray {
        if (blob.size < 1 + IV_LEN + TAG_BITS / 8 || blob[0] != BLOB_VERSION) throw VaultException.Corrupt("unknown blob format")
        val key = dekFor(purpose)
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

    private suspend fun dekFor(purpose: VaultPurpose): ByteArray {
        gate()
        val e2ee = purpose == VaultPurpose.E2EE || purpose == VaultPurpose.E2EE_PLAINTEXT
        if (e2ee && twoKeys && !legacy()) {
            boundDek?.let { return it }
            return loadMutex.withLock { boundDek ?: loadBoundDek().also { boundDek = it } }
        }
        dek?.let { return it }
        return loadMutex.withLock { dek ?: loadDek().also { dek = it } }
    }

    private fun loadDek(): ByteArray {
        if (!unlock.isUserUnlocked()) throw VaultException.Locked()
        if (!kek.exists() || !dekFile.exists()) throw VaultException.KeyGone()
        return decryptDek(kek, dekFile, DEK_AAD, setOf(LEGACY_VERSION, SLOT_VERSION))
    }

    private fun loadBoundDek(): ByteArray {
        if (!unlock.isUserUnlocked()) throw VaultException.Locked()
        if (!screen.isSecure()) {
            // the lock screen was removed: the E2EE half must not outlive it (FR-010)
            wipeBound()
            Journal.event("vault_e2ee_wiped", "no screen lock")
            throw VaultException.KeyGone("screen lock removed")
        }
        if (!screen.isUnlockedNow()) throw VaultException.Locked("device is locked")
        if (!boundKek!!.exists() || !boundDekFile!!.exists()) throw VaultException.KeyGone()
        val stored = boundDekFile.readBytes()
        if (stored.size != DEK_FILE_LEN || stored[0] != SLOT_VERSION) throw VaultException.KeyGone("unknown DEK file format")
        return try {
            boundKek.decrypt(stored.copyOfRange(1, stored.size), BOUND_DEK_AAD).also {
                if (it.size != DEK_LEN) throw VaultException.KeyGone("DEK has wrong length")
            }
        } catch (e: AEADBadTagException) {
            throw VaultException.KeyGone("DEK cannot be decrypted", e)
        } catch (e: GeneralSecurityException) {
            // Only a key the system destroyed is gone. Any other refusal — above all "device locked",
            // when the lock came between the check above and this call — is temporary: answering
            // KeyGone would make the web app throw its E2EE data away.
            if (e.javaClass.name.endsWith("KeyPermanentlyInvalidatedException")) throw VaultException.KeyGone("E2EE key invalidated", e)
            throw VaultException.Locked("E2EE key is not available now")
        }
    }

    private fun decryptDek(kek: Kek, file: File, aad: ByteArray, versions: Set<Byte>): ByteArray {
        val stored = file.readBytes()
        if (stored.size != DEK_FILE_LEN || stored[0] !in versions) throw VaultException.KeyGone("unknown DEK file format")
        return try {
            kek.decrypt(stored.copyOfRange(1, stored.size), aad).also {
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
        internal const val LEGACY_VERSION: Byte = 0x01
        internal const val SLOT_VERSION: Byte = 0x03
        internal const val IV_LEN = 12
        internal const val TAG_BITS = 128
        internal const val DEK_LEN = 32
        private const val DEK_FILE_LEN = 1 + IV_LEN + DEK_LEN + TAG_BITS / 8
        internal const val AAD_LABEL = "wolp-vault-v1|"
        internal val DEK_AAD = "wolp-dek-v1".toByteArray(Charsets.US_ASCII)
        internal val BOUND_DEK_AAD = "wolp-dek-u-v1".toByteArray(Charsets.US_ASCII)
        private const val GCM = "AES/GCM/NoPadding"

        /** Two-key vault over the platform Keystore; DEK files in `noBackupFilesDir/dt/` (S2 §11). */
        public fun android(context: Context): EnvelopeVault = android(context, gate = {})

        internal fun android(context: Context, gate: suspend () -> Unit): EnvelopeVault {
            lateinit var vault: EnvelopeVault
            vault = EnvelopeVault(
                kek = AndroidKek(),
                dekFile = File(context.noBackupFilesDir, "dt/dek.bin"),
                unlock = UnlockState.android(context),
                gate = gate,
                boundKek = AndroidKek(KeystoreKeys.VAULT_UNLOCKED_ALIAS, unlockedDeviceRequired = true),
                boundDekFile = File(context.noBackupFilesDir, "dt/dek-u.bin"),
                screen = AndroidScreenLock(context) { vault.evictUnlockedKey() },
            )
            return vault
        }
    }
}
