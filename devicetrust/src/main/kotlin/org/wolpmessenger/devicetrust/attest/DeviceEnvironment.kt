package org.wolpmessenger.devicetrust.attest

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import java.time.LocalDate

/** Device facts the precheck reads; an interface so the precheck logic runs in JVM tests. */
internal interface DeviceEnvironment {
    val sdkInt: Int
    val securityPatch: String

    /** `Settings.Global.BOOT_COUNT`, or -1 if unavailable (then nothing is cached across processes). */
    val bootCount: Int
    val versionCode: Long
    val hasStrongBox: Boolean
    fun isDeviceSecure(): Boolean
    fun today(): LocalDate
}

internal class AndroidDeviceEnvironment(context: Context) : DeviceEnvironment {
    private val app = context.applicationContext

    override val sdkInt: Int get() = Build.VERSION.SDK_INT
    override val securityPatch: String get() = Build.VERSION.SECURITY_PATCH
    override val bootCount: Int get() = Settings.Global.getInt(app.contentResolver, Settings.Global.BOOT_COUNT, -1)
    override val versionCode: Long
        get() = app.packageManager.getPackageInfo(app.packageName, 0).longVersionCode
    override val hasStrongBox: Boolean
        get() = app.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

    override fun isDeviceSecure(): Boolean = app.getSystemService(KeyguardManager::class.java).isDeviceSecure
    override fun today(): LocalDate = LocalDate.now()
}
