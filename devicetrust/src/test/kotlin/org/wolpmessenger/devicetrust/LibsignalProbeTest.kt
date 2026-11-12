package org.wolpmessenger.devicetrust

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.SessionBuilder
import org.signal.libsignal.protocol.SessionCipher
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.UntrustedIdentityException
import org.signal.libsignal.protocol.ecc.ECKeyPair
import org.signal.libsignal.protocol.fingerprint.NumericFingerprintGenerator
import org.signal.libsignal.protocol.kem.KEMKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyType
import org.signal.libsignal.protocol.message.CiphertextMessage
import org.signal.libsignal.protocol.message.PreKeySignalMessage
import org.signal.libsignal.protocol.message.SignalMessage
import org.signal.libsignal.protocol.state.KyberPreKeyRecord
import org.signal.libsignal.protocol.state.PreKeyBundle
import org.signal.libsignal.protocol.state.PreKeyRecord
import org.signal.libsignal.protocol.state.SignedPreKeyRecord
import org.signal.libsignal.protocol.state.impl.InMemorySignalProtocolStore

/**
 * Pins what specs/002 relies on in the pinned libsignal version: a session is built from a bundle with a
 * post-quantum prekey, messages go both ways, a changed identity key is refused, the safety number is symmetric.
 * libsignal changes its API without notice — a version bump that breaks this file breaks the spec's assumptions.
 */
class LibsignalProbeTest {
    private class Party(val user: String) {
        val identity: IdentityKeyPair = IdentityKeyPair.generate()
        val store = InMemorySignalProtocolStore(identity, 1)
        val address = SignalProtocolAddress(user, 1)

        /** What the phone publishes to the key directory: signed, one-time and post-quantum prekeys. */
        fun bundle(): PreKeyBundle {
            val now = System.currentTimeMillis()
            val signed = ECKeyPair.generate()
            val signedSig = identity.privateKey.calculateSignature(signed.publicKey.serialize())
            store.storeSignedPreKey(1, SignedPreKeyRecord(1, now, signed, signedSig))
            val oneTime = ECKeyPair.generate()
            store.storePreKey(100, PreKeyRecord(100, oneTime))
            val kyber = KEMKeyPair.generate(KEMKeyType.KYBER_1024)
            val kyberSig = identity.privateKey.calculateSignature(kyber.publicKey.serialize())
            store.storeKyberPreKey(7, KyberPreKeyRecord(7, now, kyber, kyberSig))
            return PreKeyBundle(
                1, 1, 100, oneTime.publicKey, 1, signed.publicKey, signedSig,
                identity.publicKey, 7, kyber.publicKey, kyberSig,
            )
        }

        /** Trap: SessionBuilder takes (store, remote, local), SessionCipher takes (store, local, remote). */
        fun startSession(peer: Party, bundle: PreKeyBundle) = SessionBuilder(store, peer.address, address).process(bundle)

        fun cipher(peer: Party) = SessionCipher(store, address, peer.address)

        fun decrypt(from: Party, m: CiphertextMessage): ByteArray = when (m.type) {
            CiphertextMessage.PREKEY_TYPE -> cipher(from).decrypt(PreKeySignalMessage(m.serialize()))
            else -> cipher(from).decrypt(SignalMessage(m.serialize()))
        }
    }

    @Test
    fun `session from a bundle with a post-quantum prekey carries messages both ways`() {
        val alice = Party("alice")
        val bob = Party("bob")

        alice.startSession(bob, bob.bundle())
        val first = alice.cipher(bob).encrypt("привет".toByteArray())
        assertEquals(CiphertextMessage.PREKEY_TYPE, first.type)
        assertArrayEquals("привет".toByteArray(), bob.decrypt(alice, first))

        val reply = bob.cipher(alice).encrypt("ответ".toByteArray())
        assertEquals(CiphertextMessage.WHISPER_TYPE, reply.type)
        assertArrayEquals("ответ".toByteArray(), alice.decrypt(bob, reply))

        val next = alice.cipher(bob).encrypt("дальше".toByteArray())
        assertEquals(CiphertextMessage.WHISPER_TYPE, next.type)
        assertArrayEquals("дальше".toByteArray(), bob.decrypt(alice, next))
    }

    @Test
    fun `a changed identity key of a remembered peer is refused`() {
        val alice = Party("alice")
        val bob = Party("bob")
        alice.startSession(bob, bob.bundle())

        val impostor = Party("bob")
        assertThrows(UntrustedIdentityException::class.java) {
            alice.startSession(bob, impostor.bundle())
        }
    }

    @Test
    fun `safety number is the same on both sides and differs for another key`() {
        val alice = Party("alice")
        val bob = Party("bob")
        val gen = NumericFingerprintGenerator(5200)
        fun number(me: Party, peer: Party) = gen.createFor(
            2, me.user.toByteArray(), me.identity.publicKey, peer.user.toByteArray(), peer.identity.publicKey,
        ).displayableFingerprint.displayText

        val a = number(alice, bob)
        assertEquals(a, number(bob, alice))
        assertTrue(a.length == 60 && a.all { it.isDigit() })
        assertNotEquals(a, number(alice, Party("bob")))
    }
}
