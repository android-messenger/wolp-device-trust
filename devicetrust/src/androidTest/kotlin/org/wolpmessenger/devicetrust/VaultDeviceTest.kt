package org.wolpmessenger.devicetrust

import android.os.Build
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.test.runTest
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.wolpmessenger.devicetrust.api.VaultException
import org.wolpmessenger.devicetrust.api.VaultPurpose
import org.wolpmessenger.devicetrust.vault.EnvelopeVault
import org.wolpmessenger.devicetrust.vault.VaultKeys
import java.io.File

/** Vault over the real Keystore KEK (S2 §9) plus the stage-2 measurements (S2 §15 п. 8). */
@RunWith(AndroidJUnit4::class)
class VaultDeviceTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @After
    fun cleanup() = runTest { EnvelopeVault.android(context).wipe() }

    @Test
    fun roundTripAcrossInstancesAndWipe() = runTest {
        val v = EnvelopeVault.android(context)
        v.wipe()
        assertTrue(v.provision())
        val blob = v.wrap("signal".toByteArray(), VaultPurpose.E2EE)
        assertArrayEquals("signal".toByteArray(), EnvelopeVault.android(context).unwrap(blob, VaultPurpose.E2EE))
        try {
            v.unwrap(blob, VaultPurpose.NAMES)
            error("wrong purpose must fail")
        } catch (e: VaultException.Corrupt) {
        }
        v.wipe()
        assertEquals(VaultKeys.MISSING, v.keys())
        try {
            EnvelopeVault.android(context).unwrap(blob, VaultPurpose.E2EE)
            error("wiped vault must fail")
        } catch (e: VaultException.KeyGone) {
        }
    }

    @Test
    fun measure() = runTest {
        EnvelopeVault.android(context).provision()
        val plain = ByteArray(4096) { it.toByte() }

        // DEK unwrap: a fresh instance per run = first access after process start.
        val dekNs = List(DEK_RUNS) {
            val v = EnvelopeVault.android(context)
            val t = System.nanoTime()
            v.wrap(ByteArray(1), VaultPurpose.E2EE)
            System.nanoTime() - t
        }
        val v = EnvelopeVault.android(context)
        repeat(WARMUP) { v.unwrap(v.wrap(plain, VaultPurpose.E2EE), VaultPurpose.E2EE) }
        val blobs = mutableListOf<ByteArray>()
        val wrapNs = List(OPS) { val t = System.nanoTime(); blobs += v.wrap(plain, VaultPurpose.E2EE); System.nanoTime() - t }
        val unwrapNs = blobs.map { val t = System.nanoTime(); v.unwrap(it, VaultPurpose.E2EE); System.nanoTime() - t }

        val out = JSONObject()
            .put("device", JSONObject().put("manufacturer", Build.MANUFACTURER).put("model", Build.MODEL).put("sdkInt", Build.VERSION.SDK_INT))
            .put("dekUnwrapMs", stats(dekNs)).put("wrap4KiBMs", stats(wrapNs)).put("unwrap4KiBMs", stats(unwrapNs))
            .put("targets", JSONObject().put("wrapUnwrapP95Ms", 1.0).put("dekUnwrapP95Ms", 50.0))
        File(context.getExternalFilesDir("bench"), "vault-${Build.MODEL.replace(Regex("[^A-Za-z0-9._-]"), "_")}.json").writeText(out.toString(2))
        Log.i("DT-BENCH", out.toString())
        println("DT-BENCH $out")
    }

    private fun stats(ns: List<Long>): JSONObject {
        val s = ns.sorted().map { it / 1e6 }
        fun p(q: Double) = s[((s.size - 1) * q).toInt()]
        return JSONObject().put("n", s.size).put("p50", p(0.5)).put("p95", p(0.95)).put("max", s.last())
    }

    private companion object {
        const val DEK_RUNS = 30
        const val WARMUP = 50
        const val OPS = 500
    }
}
