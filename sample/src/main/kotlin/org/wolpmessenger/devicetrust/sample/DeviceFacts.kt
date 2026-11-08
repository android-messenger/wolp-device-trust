package org.wolpmessenger.devicetrust.sample

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import org.json.JSONObject

object DeviceFacts {
    fun hasStrongBox(context: Context): Boolean =
        context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

    fun screenLock(context: Context): Boolean = context.getSystemService(KeyguardManager::class.java).isDeviceSecure

    fun rows(context: Context): List<Pair<String, String>> = listOf(
        "Device" to "${Build.MANUFACTURER} ${Build.MODEL} (${Build.DEVICE})",
        "Android" to "${Build.VERSION.RELEASE} · API ${Build.VERSION.SDK_INT}",
        "Security patch" to Build.VERSION.SECURITY_PATCH,
        "StrongBox" to if (hasStrongBox(context)) "declared" else "not declared",
        "Screen lock" to if (screenLock(context)) "set" else "none",
    )

    fun json(context: Context): JSONObject = JSONObject()
        .put("manufacturer", Build.MANUFACTURER)
        .put("brand", Build.BRAND)
        .put("model", Build.MODEL)
        .put("device", Build.DEVICE)
        .put("sdkInt", Build.VERSION.SDK_INT)
        .put("release", Build.VERSION.RELEASE)
        .put("securityPatch", Build.VERSION.SECURITY_PATCH)
        .put("strongBoxFeature", hasStrongBox(context))
}
