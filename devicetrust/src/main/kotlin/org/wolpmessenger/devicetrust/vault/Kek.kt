package org.wolpmessenger.devicetrust.vault

import android.content.Context
import android.os.UserManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import org.wolpmessenger.devicetrust.keys.KeystoreKeys
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The key-encryption key `dt.vault` (S2 §3, §9): non-extractable AES-256-GCM in Keystore,
 * used only to encrypt and decrypt the DEK. Behind an interface for JVM tests.
 */
internal interface Kek {
    fun exists(): Boolean
    fun create()
    fun delete()

    /** Encrypts with a Keystore-chosen IV; returns `iv ‖ ciphertext ‖ tag`. */
    fun encrypt(plain: ByteArray, aad: ByteArray): ByteArray

    /** Inverse of [encrypt]. Throws `AEADBadTagException` if the key or data do not match. */
    fun decrypt(ivCiphertextTag: ByteArray, aad: ByteArray): ByteArray
}

internal class AndroidKek(private val alias: String = KeystoreKeys.VAULT_ALIAS) : Kek {
    private fun keyStore() = KeyStore.getInstance(PROVIDER).apply { load(null) }
    private fun key(): SecretKey = keyStore().getKey(alias, null) as SecretKey

    override fun exists(): Boolean = keyStore().containsAlias(alias)

    override fun create() {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(false)
            .setUnlockedDeviceRequired(false)
            .build()
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER).apply { init(spec) }.generateKey()
    }

    override fun delete() {
        val ks = keyStore()
        if (ks.containsAlias(alias)) ks.deleteEntry(alias)
    }

    override fun encrypt(plain: ByteArray, aad: ByteArray): ByteArray {
        val c = Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, key()) }
        c.updateAAD(aad)
        return c.iv + c.doFinal(plain)
    }

    override fun decrypt(ivCiphertextTag: ByteArray, aad: ByteArray): ByteArray {
        val c = Cipher.getInstance(TRANSFORMATION)
        c.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, ivCiphertextTag, 0, IV_LEN))
        c.updateAAD(aad)
        return c.doFinal(ivCiphertextTag, IV_LEN, ivCiphertextTag.size - IV_LEN)
    }

    private companion object {
        const val PROVIDER = "AndroidKeyStore"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val IV_LEN = 12
    }
}

/** Whether credential-encrypted storage is available (first unlock after boot happened). */
internal fun interface UnlockState {
    fun isUserUnlocked(): Boolean

    companion object {
        fun android(context: Context): UnlockState {
            val um = context.applicationContext.getSystemService(UserManager::class.java)
            return UnlockState { um.isUserUnlocked }
        }
    }
}
