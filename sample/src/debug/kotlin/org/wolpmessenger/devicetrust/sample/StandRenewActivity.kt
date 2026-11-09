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
import kotlinx.coroutines.withContext
import okhttp3.Request
import org.wolpmessenger.devicetrust.DeviceTrust
import org.wolpmessenger.devicetrust.api.DeviceTrustConfig

/**
 * Debug only: live certificate renewal against the devices stand (S3 §5.3–5.5, task 5),
 * after StandEnrollActivity enrolled the device. Started by the stand's renew.sh:
 *
 *   am start -n org.wolpmessenger.devicetrust.sample/.StandRenewActivity \
 *     --es url https://localhost:9443 --es appUrl https://localhost:9444 --es pins sha256/…,sha256/… --es cookie 'ory_kratos_session=…'
 *
 * Steps: requests on the app host (mTLS + auth_request) with the current certificate,
 * DeviceTrust.ensureFresh() (renew → confirm when due), the same requests with the new one.
 * Logcat tag WOLP_STAND; lines starting with RESULT.
 */
class StandRenewActivity : Activity() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private lateinit var out: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        out = TextView(this).apply { textSize = 15f; setPadding(40, 80, 40, 40); setTextIsSelectable(true) }
        setContentView(ScrollView(this).apply { addView(out) })

        val url = intent.getStringExtra("url") ?: "https://localhost:9443"
        val appUrl = intent.getStringExtra("appUrl") ?: "https://localhost:9444"
        val pins = intent.getStringExtra("pins")?.split(',')?.map { it.trim() }.orEmpty()
        val cookie = intent.getStringExtra("cookie").orEmpty()
        say("stand enroll $url, app $appUrl")
        try {
            DeviceTrust.init(this, DeviceTrustConfig(enrollBaseUrl = url, appBaseUrl = appUrl, serverPins = pins, cookieProvider = { cookie }))
        } catch (e: Exception) {
            result("INIT_FAILED ${e.javaClass.simpleName}: ${e.message}")
            return
        }
        scope.launch {
            val before = serial()
            say("state ${DeviceTrust.state.value}, serial $before")
            probe(appUrl, cookie, "before")
            val state = DeviceTrust.ensureFresh()
            val after = serial()
            say("ensureFresh → $state, serial $after")
            probe(appUrl, cookie, "after")
            result(if (after != null && after != before) "RENEWED old=$before new=$after state=$state" else "NOT_RENEWED serial=$after state=$state")
        }
    }

    private fun serial() = DeviceTrust.clientCredentials()?.chain?.firstOrNull()?.serialNumber?.toString(16)

    /** ping and whoami (module, no session needed) and a proxied request (auth_request → Oathkeeper → echo). */
    private suspend fun probe(appUrl: String, cookie: String, label: String) = withContext(Dispatchers.IO) {
        val http = DeviceTrust.okHttpClient()
        for ((path, withCookie) in listOf("/v1/device/ping" to false, "/v1/device/whoami" to true, "/messenger/api/headers" to true)) {
            val line = try {
                val req = Request.Builder().url(appUrl + path).apply { if (withCookie) header("Cookie", cookie) }.build()
                http.newCall(req).execute().use { r ->
                    val used = (r.handshake?.localCertificates?.firstOrNull() as? java.security.cert.X509Certificate)?.serialNumber?.toString(16)
                    val body = r.body?.string().orEmpty()
                    val detail = if (path.startsWith("/messenger")) body.lineSequence().filter { it.startsWith("X-Device-Id") || it.startsWith("X-User-Id") }.joinToString(" ")
                    else body.take(120)
                    "${r.code} renew=${r.header("X-Device-Renew")} deny=${r.header("X-Device-Deny")} cert=$used $detail"
                }
            } catch (e: Exception) {
                "ERROR ${e.javaClass.simpleName}: ${e.message}"
            }
            withContext(Dispatchers.Main) { say("$label $path → $line") }
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
