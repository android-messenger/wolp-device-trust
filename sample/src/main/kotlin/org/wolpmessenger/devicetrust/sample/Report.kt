package org.wolpmessenger.devicetrust.sample

import android.content.Context
import android.content.Intent
import androidx.core.content.FileProvider
import org.json.JSONArray
import org.json.JSONObject
import org.wolpmessenger.devicetrust.api.PrecheckResult
import java.io.File
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

/** One JSON with everything the sample measured plus fresh test vectors — sent by the user to the team. */
object Report {
    fun build(
        context: Context,
        precheck: PrecheckResult?,
        attestation: List<AttestationProbe>,
        keyBench: List<KeyBench>,
        vaultBench: VaultBench?,
        vectors: Map<String, JSONObject>,
    ): JSONObject {
        val pkg = context.packageManager.getPackageInfo(context.packageName, 0)
        return JSONObject()
            .put("schema", "wolp-sample-report/1")
            .put("generatedAt", Instant.now().toString())
            .put("app", JSONObject().put("package", context.packageName).put("versionName", pkg.versionName).put("versionCode", pkg.longVersionCode))
            .put("device", DeviceFacts.json(context).put("screenLock", DeviceFacts.screenLock(context)))
            .put("precheck", precheck?.let(Diagnostics::precheckJson) ?: JSONObject.NULL)
            .put("attestation", JSONArray(attestation.map { a ->
                JSONObject().put("requestedStrongBox", a.requestedStrongBox).put("level", a.level).put("hardwareConfirmed", a.hardwareConfirmed)
                    .put("strongBoxFallback", a.strongBoxFallback).put("chainType", a.chainType).put("error", a.error ?: JSONObject.NULL)
                    .put("chain", JSONArray(a.chain.map { JSONObject().put("subject", it.subject).put("issuer", it.issuer) }))
            }))
            .put("keyBench", JSONArray(keyBench.map { it.json() }))
            .put("vaultBench", vaultBench?.json() ?: JSONObject.NULL)
            .put("testvectors", JSONObject().apply { vectors.forEach { (k, v) -> put(k, v) } })
    }

    fun share(context: Context, report: JSONObject) {
        val stamp = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss").withZone(ZoneOffset.UTC).format(Instant.now())
        val dir = File(context.cacheDir, "reports").apply { mkdirs() }
        val file = File(dir, "wolp-report-${TestVectorExporter.modelDir()}-$stamp.json").apply { writeText(report.toString(2)) }
        val uri = FileProvider.getUriForFile(context, "${context.packageName}.files", file)
        val send = Intent(Intent.ACTION_SEND)
            .setType("application/json")
            .putExtra(Intent.EXTRA_STREAM, uri)
            .putExtra(Intent.EXTRA_SUBJECT, file.name)
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        context.startActivity(Intent.createChooser(send, "Share report").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }
}
