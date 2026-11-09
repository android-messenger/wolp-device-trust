package org.wolpmessenger.devicetrust

import android.content.pm.PackageManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.wolpmessenger.devicetrust.api.DeviceTrustConfig
import org.wolpmessenger.devicetrust.api.PrecheckResult
import org.wolpmessenger.devicetrust.api.UnsupportedReason
import org.wolpmessenger.devicetrust.attest.AttestationChain
import org.wolpmessenger.devicetrust.attest.Precheck
import org.wolpmessenger.devicetrust.keys.KeyGenResult
import org.wolpmessenger.devicetrust.keys.KeystoreKeys
import java.security.KeyStore
import java.security.PrivateKey

/**
 * Runs against the real AndroidKeyStore. On a device with TEE/StrongBox the key must be
 * hardware-confirmed and attested; on an emulator the result is reported as it is
 * (S2 §15 п. 2 expects Unsupported(SOFTWARE_KEYSTORE) there).
 */
@RunWith(AndroidJUnit4::class)
class KeystoreDeviceTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val keys = KeystoreKeys.android()
    private val challenge = ByteArray(32) { (it * 7 + 3).toByte() }

    @After
    fun cleanup() {
        keys.deleteOrphans(keep = emptySet())
    }

    @Test
    fun deviceKeyIsAttestedAndNotExtractable() {
        val alias = keys.nextDeviceAlias()
        when (val r = keys.generate(alias, challenge, preferStrongBox = false)) {
            is KeyGenResult.SoftwareKeystore -> {
                assertTrue("software key must be deleted", alias !in keys.deviceKeyAliases())
                println("DT-DEVICE-TEST keystore level ${r.level}: device cannot be enrolled")
            }
            is KeyGenResult.Ok -> {
                val chain = AttestationChain(r.key.chain)
                assertTrue("attestation chain has a root", chain.certificates.size >= 2)
                assertTrue(chain.hasKeyDescription)
                val ext = chain.leaf.getExtensionValue(AttestationChain.OID_KEY_DESCRIPTION)
                assertTrue("challenge is inside KeyDescription", ext.containsSubsequence(challenge))
                val pk = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.getKey(alias, null) as PrivateKey
                assertNull("private key bytes are never exposed", pk.encoded)
                println("DT-DEVICE-TEST level=${r.key.level} chain=${chain.chainType} len=${chain.certificates.size}")
            }
        }
    }

    /**
     * TLS client auth (mTLS to app.<host>): Conscrypt signs CertificateVerify over a digest it
     * computed itself, through `NONEwithECDSA` on the Keystore key. A key without DIGEST_NONE
     * makes the client abort the handshake silently (nginx: "peer closed connection in SSL
     * handshake"), found on the stand with the Galaxy A37.
     */
    @Test
    fun deviceKeySignsPrehashedDigestForTls() {
        val alias = keys.nextDeviceAlias()
        val r = keys.generate(alias, challenge, preferStrongBox = false)
        if (r !is KeyGenResult.Ok) return // software keystore: the device cannot be enrolled anyway
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val digest = java.security.MessageDigest.getInstance("SHA-256").digest("tls 1.3 CertificateVerify".toByteArray())
        val sig = java.security.Signature.getInstance("NONEwithECDSA").run {
            initSign(ks.getKey(alias, null) as PrivateKey); update(digest); sign()
        }
        val ok = java.security.Signature.getInstance("NONEwithECDSA").run {
            initVerify(ks.getCertificate(alias).publicKey); update(digest); verify(sig)
        }
        assertTrue("NONEwithECDSA signature verifies", ok)
    }

    @Test
    fun strongBoxRequestFallsBackOrSucceeds() {
        val hasStrongBox = context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        val r = keys.generate(keys.nextDeviceAlias(), challenge, preferStrongBox = true)
        if (r is KeyGenResult.Ok && !hasStrongBox) assertTrue("no StrongBox feature → must fall back", r.key.strongBoxFallback)
    }

    @Test
    fun orphansAreRemoved() {
        val a1 = keys.nextDeviceAlias()
        keys.generate(a1, null, preferStrongBox = false)
        val a2 = keys.nextDeviceAlias()
        keys.generate(a2, null, preferStrongBox = false)
        keys.deleteOrphans(keep = setOf(a2))
        val left = keys.deviceKeyAliases()
        assertTrue(a1 !in left)
    }

    @Test
    fun precheckMatchesKeystoreLevel() = runTest {
        val r = Precheck.android(context, DeviceTrustConfig()).run()
        println("DT-DEVICE-TEST precheck=$r")
        when (r) {
            is PrecheckResult.Supported -> assertTrue(r.info.keystoreLevel.isHardwareConfirmed)
            is PrecheckResult.Unsupported -> if (r.info?.keystoreLevel?.isHardwareConfirmed == false) {
                assertTrue(UnsupportedReason.SOFTWARE_KEYSTORE in r.reasons)
            }
            is PrecheckResult.Compromised -> error("no RASP checks in stage 1")
        }
        assertEquals(emptyList<String>(), keys.deviceKeyAliases())
    }

    private fun ByteArray.containsSubsequence(needle: ByteArray): Boolean =
        (0..size - needle.size).any { i -> needle.indices.all { this[i + it] == needle[it] } }
}
