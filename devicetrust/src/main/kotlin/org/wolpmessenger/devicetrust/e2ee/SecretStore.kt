package org.wolpmessenger.devicetrust.e2ee

import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.util.KeyHelper
import org.wolpmessenger.devicetrust.Journal
import org.wolpmessenger.devicetrust.api.E2eeException
import org.wolpmessenger.devicetrust.api.E2eeFailure
import org.wolpmessenger.devicetrust.api.Vault
import org.wolpmessenger.devicetrust.api.VaultException
import org.wolpmessenger.devicetrust.api.VaultPurpose
import org.wolpmessenger.devicetrust.io.AtomicFiles
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.IOException
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** A signed or post-quantum prekey record with the time it stopped being the published one (0 — it is current). */
internal class KeptKey(val record: ByteArray, var replacedAt: Long = 0)

/** A prekey message that already used the multi-use post-quantum key: seeing it again is a replay. */
internal data class UsedBaseKey(val kyberId: Int, val signedId: Int, val baseKey: String)

/** Own keys of this installation: one file. */
internal class Account(
    /** Keys the peer file names, so the names say nothing about who the peers are. */
    val nameKey: ByteArray,
    val identity: IdentityKeyPair,
    val registrationId: Int,
) {
    var nextPreKeyId = 1
    var nextSignedId = 1
    var nextKyberId = 1
    var currentSignedId = 0
    var currentKyberId = 0
    val preKeys = HashMap<Int, ByteArray>()
    val signed = HashMap<Int, KeptKey>()
    val kyber = HashMap<Int, KeptKey>()
    val usedBaseKeys = HashSet<UsedBaseKey>()
    var dirty = false
}

/** Everything about one peer: one file. */
internal class Peer(val file: File) {
    /** The peer's identity key as last seen (33 bytes), or null. */
    var identity: ByteArray? = null

    /** libsignal session record: the current session and the earlier ones it still decrypts with. */
    var session: ByteArray? = null
    var dirty = false
}

/**
 * Files of the secret-chat state (specs/002, FR-002, FR-004, FR-006): `account.bin` and one file per
 * peer, each a Vault blob with purpose `E2EE` bound to its file name. Nothing is cached in memory:
 * while the device is locked the Vault refuses and no key of this state is in the process.
 */
internal class SecretStore(private val dir: File, private val vault: Vault, private val random: SecureRandom = SecureRandom()) {
    private val accountFile = File(dir, "account.bin")

    /**
     * Own keys; created on first use. A state the Vault can no longer open is gone for good (the
     * vault key was destroyed and made anew): it is deleted and a new identity key is made.
     */
    suspend fun account(): Account {
        if (accountFile.exists()) {
            try {
                return decodeAccount(open(accountFile))
            } catch (e: Unreadable) {
                Journal.event("e2ee_state_reset", "account unreadable")
            }
        }
        wipe()
        val fresh = Account(ByteArray(32).also(random::nextBytes), IdentityKeyPair.generate(), KeyHelper.generateRegistrationId(false))
        save(fresh)
        return fresh
    }

    suspend fun peer(account: Account, user: String): Peer {
        val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(account.nameKey, "HmacSHA256")) }
        val name = "p-" + mac.doFinal(user.toByteArray()).take(20).joinToString("") { "%02x".format(it) } + ".bin"
        val peer = Peer(File(dir, name))
        if (!peer.file.exists()) return peer
        try {
            val d = DataInputStream(ByteArrayInputStream(open(peer.file)))
            if (d.readByte() != FORMAT) throw Unreadable()
            val identity = d.readBlob()
            peer.session = d.readBlob()
            peer.identity = identity
        } catch (e: E2eeException) {
            throw e
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            // only this peer is lost: the next message from them fails and comes back through recovery
            Journal.event("e2ee_peer_reset")
            peer.file.delete()
            peer.identity = null
            peer.session = null
        }
        return peer
    }

    suspend fun save(account: Account) {
        val out = ByteArrayOutputStream()
        DataOutputStream(out).apply {
            writeByte(FORMAT.toInt())
            writeBlob(account.nameKey)
            writeBlob(account.identity.serialize())
            writeInt(account.registrationId)
            writeInt(account.nextPreKeyId)
            writeInt(account.nextSignedId)
            writeInt(account.nextKyberId)
            writeInt(account.currentSignedId)
            writeInt(account.currentKyberId)
            writeInt(account.preKeys.size)
            account.preKeys.forEach { (id, record) -> writeInt(id); writeBlob(record) }
            for (kept in listOf(account.signed, account.kyber)) {
                writeInt(kept.size)
                kept.forEach { (id, k) -> writeInt(id); writeLong(k.replacedAt); writeBlob(k.record) }
            }
            writeInt(account.usedBaseKeys.size)
            account.usedBaseKeys.forEach { writeInt(it.kyberId); writeInt(it.signedId); writeUTF(it.baseKey) }
        }
        seal(accountFile, out.toByteArray())
        account.dirty = false
    }

    suspend fun save(peer: Peer) {
        val out = ByteArrayOutputStream()
        DataOutputStream(out).apply {
            writeByte(FORMAT.toInt())
            writeBlob(peer.identity)
            writeBlob(peer.session)
        }
        seal(peer.file, out.toByteArray())
        peer.dirty = false
    }

    fun wipe() {
        dir.listFiles()?.forEach { it.delete() }
    }

    private fun decodeAccount(bytes: ByteArray): Account = try {
        val d = DataInputStream(ByteArrayInputStream(bytes))
        if (d.readByte() != FORMAT) throw Unreadable()
        Account(d.readBlob()!!, IdentityKeyPair(d.readBlob()!!), d.readInt()).apply {
            nextPreKeyId = d.readInt()
            nextSignedId = d.readInt()
            nextKyberId = d.readInt()
            currentSignedId = d.readInt()
            currentKyberId = d.readInt()
            repeat(d.readInt()) { preKeys[d.readInt()] = d.readBlob()!! }
            for (kept in listOf(signed, kyber)) {
                repeat(d.readInt()) {
                    val id = d.readInt()
                    val replacedAt = d.readLong()
                    kept[id] = KeptKey(d.readBlob()!!, replacedAt)
                }
            }
            repeat(d.readInt()) { usedBaseKeys += UsedBaseKey(d.readInt(), d.readInt(), d.readUTF()) }
        }
    } catch (e: Exception) {
        throw Unreadable()
    }

    /** The file's plain content. Locked and "no vault key" are refusals; anything else means the file is lost. */
    private suspend fun open(file: File): ByteArray = try {
        vault.unwrap(file.readBytes(), VaultPurpose.E2EE, file.name.toByteArray())
    } catch (e: VaultException.Locked) {
        throw E2eeException(E2eeFailure.LOCKED, e)
    } catch (e: VaultException.KeyGone) {
        wipe() // FR-006: the state must not outlive its key
        throw E2eeException(E2eeFailure.NOT_ENROLLED, e)
    } catch (e: VaultException.Corrupt) {
        throw Unreadable()
    }

    private suspend fun seal(file: File, plain: ByteArray) {
        val blob = try {
            vault.wrap(plain, VaultPurpose.E2EE, file.name.toByteArray())
        } catch (e: VaultException.Locked) {
            throw E2eeException(E2eeFailure.LOCKED, e)
        } catch (e: VaultException) {
            throw E2eeException(E2eeFailure.NOT_ENROLLED, e)
        }
        AtomicFiles.write(file, blob) // FR-004: the file is either the old one or the new one
    }

    private class Unreadable : Exception()

    private fun DataOutputStream.writeBlob(b: ByteArray?) {
        writeInt(b?.size ?: -1)
        if (b != null) write(b)
    }

    private fun DataInputStream.readBlob(): ByteArray? {
        val n = readInt()
        if (n < 0) return null
        if (n > available()) throw IOException("blob longer than the file")
        return ByteArray(n).also(::readFully)
    }

    private companion object {
        const val FORMAT: Byte = 1
    }
}
