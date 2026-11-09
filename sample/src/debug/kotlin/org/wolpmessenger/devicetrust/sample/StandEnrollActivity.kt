package org.wolpmessenger.devicetrust.sample

import android.app.Activity
import android.os.Bundle
import android.util.Log
import android.widget.ScrollView
import android.widget.TextView
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import org.wolpmessenger.devicetrust.DeviceTrust
import org.wolpmessenger.devicetrust.api.DeviceTrustConfig
import org.wolpmessenger.devicetrust.api.EnrollResult

/**
 * Debug only: a real enrollment against the devices stand (wolp-android/p1/stand/devices,
 * S3 §5.1–5.2) through the library's public API. Started by the stand's enroll.sh:
 *
 *   am start -n org.wolpmessenger.devicetrust.sample/.StandEnrollActivity \
 *     --es url https://localhost:9443 --es pins sha256/…,sha256/… --es cookie 'ory_kratos_session=…' --es password XXXX-XXXX-XXXX
 *
 * The outcome goes to the screen and to logcat (tag WOLP_STAND, lines starting with RESULT).
 */
class StandEnrollActivity : Activity() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private lateinit var out: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        out = TextView(this).apply { textSize = 15f; setPadding(40, 80, 40, 40); setTextIsSelectable(true) }
        setContentView(ScrollView(this).apply { addView(out) })

        val url = intent.getStringExtra("url") ?: "https://localhost:9443"
        val pins = intent.getStringExtra("pins")?.split(',')?.map { it.trim() }.orEmpty()
        val cookie = intent.getStringExtra("cookie").orEmpty()
        val password = intent.getStringExtra("password").orEmpty().toCharArray()
        intent.removeExtra("password")
        say("stand $url, pins ${pins.size}")

        try {
            DeviceTrust.init(this, DeviceTrustConfig(enrollBaseUrl = url, appBaseUrl = url, serverPins = pins, cookieProvider = { cookie }))
        } catch (e: Exception) {
            result("INIT_FAILED ${e.javaClass.simpleName}: ${e.message}")
            return
        }
        scope.launch {
            val r = try {
                DeviceTrust.enroll(cookie, password)
            } finally {
                password.fill('\u0000')
            }
            when (r) {
                is EnrollResult.Ok -> {
                    val leaf = DeviceTrust.clientCredentials()?.chain?.firstOrNull()
                    result("OK deviceId=${r.deviceId} serial=${leaf?.serialNumber?.toString(16)} notAfter=${leaf?.notAfter?.toInstant()} issuer=${leaf?.issuerX500Principal?.name}")
                }
                is EnrollResult.Transient -> result("TRANSIENT ${r.cause.javaClass.simpleName}: ${r.cause.message}")
                else -> result(r.toString())
            }
            say("state ${DeviceTrust.state.value}")
            DeviceTrust.deviceInfo()?.let { say("device $it") }
        }
    }

    private fun result(line: String) = say("RESULT $line")

    private fun say(line: String) {
        Log.i(TAG, line)
        out.append(line + "\n\n")
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    private companion object {
        const val TAG = "WOLP_STAND"
    }
}
