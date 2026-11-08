package org.wolpmessenger.devicetrust.sample

import android.os.Build
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * Headless counterpart of the sample's buttons, driven over adb by tools/bench.sh and tools/export-testvectors.sh:
 * - [exportTestVectors] → `files/testvectors/<model>/<case>.json`;
 * - [measure] → `files/bench/<model>.json` (Keystore TEE/StrongBox + Vault).
 */
@RunWith(AndroidJUnit4::class)
class DeviceExportTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun exportTestVectors() {
        val dir = File(context.getExternalFilesDir("testvectors"), TestVectorExporter.modelDir())
        dir.deleteRecursively()
        dir.mkdirs()
        TestVectorExporter(context).export().forEach { (case, json) ->
            File(dir, "$case.json").writeText(json.toString(2) + "\n")
            println("DT-TESTVECTOR ${dir.name}/$case.json")
        }
    }

    @Test
    fun measure() {
        val d = Diagnostics(context)
        val keys = buildList {
            add(d.keyBench(strongBox = false))
            if (DeviceFacts.hasStrongBox(context)) add(d.keyBench(strongBox = true))
        }
        val out = JSONObject()
            .put("device", DeviceFacts.json(context))
            .put("keyBench", JSONArray(keys.map { it.json() }))
            .put("vaultBench", d.vaultBench().json())
        val file = File(context.getExternalFilesDir("bench"), "${TestVectorExporter.modelDir()}.json")
        file.writeText(out.toString(2) + "\n")
        Log.i("DT-BENCH", out.toString())
        println("DT-BENCH $out")
    }
}
