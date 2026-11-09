package org.wolpmessenger.devicetrust.pilot

import android.app.Activity
import android.content.pm.ApplicationInfo
import android.os.Bundle
import android.util.Log
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import org.wolpmessenger.devicetrust.DeviceTrust

/**
 * One screen: build facts, the trust state, and a RASP pass (`checkIntegrity`). Everything is also
 * logged with the tag DT-PILOT so a device run can be checked over adb.
 */
class PilotActivity : Activity() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private lateinit var out: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        out = TextView(this).apply { setTextIsSelectable(true); textSize = 13f }
        val run = Button(this).apply { text = "checkIntegrity()"; setOnClickListener { scan() } }
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 96, 32, 32)
            addView(run)
            addView(out)
        }
        setContentView(ScrollView(this).apply { addView(root) })
        val info = packageManager.getPackageInfo(packageName, 0)
        val debuggable = (applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
        log("build: kind=${BuildConfig.BUILD_KIND} dryRun=${BuildConfig.RASP_DRY_RUN} versionCode=${info.longVersionCode} debuggable=$debuggable")
        scope.launch { DeviceTrust.state.collect { log("state: $it") } }
        scope.launch { DeviceTrust.events.collect { log("event: $it") } }
        if (intent.getBooleanExtra("scan", false)) scan()
    }

    private fun scan() {
        scope.launch {
            val r = DeviceTrust.checkIntegrity()
            log("rasp: blocking=${r.blocking.map { "${it.id}(${it.detail})" }} reports=${r.reports.map { "${it.id}(${it.detail})" }}")
        }
    }

    private fun log(line: String) {
        Log.i("DT-PILOT", line)
        out.append(line + "\n\n")
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }
}
