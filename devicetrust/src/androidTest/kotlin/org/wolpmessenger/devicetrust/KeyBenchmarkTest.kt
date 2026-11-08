package org.wolpmessenger.devicetrust

import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Test
import org.junit.runner.RunWith
import org.wolpmessenger.devicetrust.keys.KeyGenResult
import org.wolpmessenger.devicetrust.keys.KeystoreKeys
import java.io.File
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * Stage-1 measurements that decide the `deviceKeyStrongBox` default (S2 §3, R4):
 * - key generation with attestation;
 * - ECDSA P-256 signature latency — the private-key operation of every full mTLS handshake;
 * - concurrent signing — WebView cold start opens several TLS connections at once.
 *
 * Results: logcat tag `DT-BENCH` and `files/bench/<model>.json` (tools/bench.sh pulls it).
 */
@RunWith(AndroidJUnit4::class)
class KeyBenchmarkTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val keys = KeystoreKeys.android()

    @Test
    fun measure() {
        val out = JSONObject()
            .put("device", JSONObject().put("manufacturer", Build.MANUFACTURER).put("model", Build.MODEL)
                .put("sdkInt", Build.VERSION.SDK_INT).put("securityPatch", Build.VERSION.SECURITY_PATCH)
                .put("strongBoxFeature", context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)))
        val levels = JSONArray()
        for (strongBox in listOf(false, true)) {
            levels.put(measureLevel(strongBox) ?: continue)
        }
        out.put("levels", levels)
        val file = File(context.getExternalFilesDir("bench"), "${Build.MODEL.replace(Regex("[^A-Za-z0-9._-]"), "_")}.json")
        file.writeText(out.toString(2))
        Log.i(TAG, out.toString())
        println("$TAG $out")
    }

    private fun measureLevel(strongBox: Boolean): JSONObject? {
        val keygen = mutableListOf<Long>()
        var alias = ""
        var result: KeyGenResult? = null
        repeat(KEYGEN_RUNS) {
            keys.delete(alias)
            alias = keys.nextDeviceAlias()
            val t = System.nanoTime()
            result = keys.generate(alias, ByteArray(32) { 1 }, preferStrongBox = strongBox)
            keygen += System.nanoTime() - t
        }
        val ok = result as? KeyGenResult.Ok ?: return JSONObject().put("requestedStrongBox", strongBox).put("result", result.toString())
        if (strongBox && ok.key.strongBoxFallback) {
            keys.delete(alias)
            return JSONObject().put("requestedStrongBox", true).put("result", "fallback to TEE: no StrongBox")
        }
        val key = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.getKey(alias, null) as PrivateKey
        val data = ByteArray(32) { it.toByte() }
        fun sign(): ByteArray = Signature.getInstance("SHA256withECDSA").run { initSign(key); update(data); sign() }

        repeat(WARMUP) { sign() }
        val single = List(SIGN_RUNS) { val t = System.nanoTime(); sign(); System.nanoTime() - t }

        val pool = Executors.newFixedThreadPool(PARALLEL)
        val t0 = System.nanoTime()
        val futures = List(PARALLEL) { pool.submit<List<Long>> { List(PER_THREAD) { val t = System.nanoTime(); sign(); System.nanoTime() - t } } }
        val parallel = futures.flatMap { it.get() }
        val wall = System.nanoTime() - t0
        pool.shutdown(); pool.awaitTermination(1, TimeUnit.MINUTES)
        keys.delete(alias)

        return JSONObject()
            .put("requestedStrongBox", strongBox)
            .put("level", ok.key.level.name)
            .put("keygenMs", stats(keygen))
            .put("signMs", stats(single))
            .put("parallelSignMs", stats(parallel).put("threads", PARALLEL).put("wallMs", wall / 1e6))
    }

    private fun stats(ns: List<Long>): JSONObject {
        val s = ns.sorted().map { it / 1e6 }
        fun p(q: Double) = s[((s.size - 1) * q).toInt()]
        return JSONObject().put("n", s.size).put("p50", p(0.5)).put("p95", p(0.95)).put("max", s.last())
    }

    private companion object {
        const val TAG = "DT-BENCH"
        const val KEYGEN_RUNS = 5
        const val WARMUP = 10
        const val SIGN_RUNS = 100
        const val PARALLEL = 6
        const val PER_THREAD = 20
    }
}
