package org.wolpmessenger.devicetrust.rasp

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Debug
import android.provider.Settings
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import org.wolpmessenger.devicetrust.api.SecurityLevel
import java.io.ByteArrayOutputStream
import java.security.MessageDigest

/** Everything the Kotlin checks read from the platform; faked in JVM tests. */
internal interface RaspEnv {
    /** `stat(2)`: exists → FOUND, EACCES/EPERM → DENIED, otherwise CLEAN. */
    fun stat(path: String): ProbeState

    /** `open(2)`/`read(2)` of a whole file: the text, or the failure state. */
    fun read(path: String): Result<String>
    fun env(name: String): String?
    val buildTags: String
    val buildHardware: String
    val buildFingerprint: String
    fun isDebuggerConnected(): Boolean
    val appDebuggable: Boolean
    val versionCode: Long

    /** SHA-256 hex (lowercase) of the current APK signers. */
    fun signingDigests(): List<String>

    /** Which of [names] are visible as installed packages (needs `<queries>`). */
    fun installedPackages(names: List<String>): List<String>
    fun classLoadable(name: String): Boolean
    fun stackClassNames(): List<String>
    fun devOptions(): Boolean
    fun adbEnabled(): Boolean
    fun deviceSecure(): Boolean

    /** Keystore level cached by the precheck (S2 §6.1 п. 2), or null if never measured. */
    fun keystoreLevel(): SecurityLevel?
}

/** Read failure carrying the probe state (DENIED for EACCES/EPERM). */
internal class ProbeFailure(val state: ProbeState) : Exception()

internal class AndroidRaspEnv(context: Context, private val cachedLevel: () -> SecurityLevel?) : RaspEnv {
    private val app = context.applicationContext
    private val pm = app.packageManager

    override fun stat(path: String): ProbeState = try {
        Os.stat(path)
        ProbeState.FOUND
    } catch (e: ErrnoException) {
        if (e.errno == OsConstants.EACCES || e.errno == OsConstants.EPERM) ProbeState.DENIED else ProbeState.CLEAN
    }

    override fun read(path: String): Result<String> = try {
        val fd = Os.open(path, OsConstants.O_RDONLY or OsConstants.O_CLOEXEC, 0)
        try {
            val out = ByteArrayOutputStream()
            val buf = ByteArray(8192)
            while (true) {
                val n = Os.read(fd, buf, 0, buf.size)
                if (n <= 0) break
                out.write(buf, 0, n)
            }
            Result.success(out.toString(Charsets.UTF_8.name()))
        } finally {
            Os.close(fd)
        }
    } catch (e: ErrnoException) {
        Result.failure(ProbeFailure(if (e.errno == OsConstants.EACCES || e.errno == OsConstants.EPERM) ProbeState.DENIED else ProbeState.CLEAN))
    }

    override fun env(name: String): String? = System.getenv(name)
    override val buildTags: String get() = Build.TAGS ?: ""
    override val buildHardware: String get() = Build.HARDWARE ?: ""
    override val buildFingerprint: String get() = Build.FINGERPRINT ?: ""
    override fun isDebuggerConnected(): Boolean = Debug.isDebuggerConnected() || Debug.waitingForDebugger()
    override val appDebuggable: Boolean get() = (app.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
    override val versionCode: Long get() = pm.getPackageInfo(app.packageName, 0).longVersionCode

    override fun signingDigests(): List<String> {
        val info = pm.getPackageInfo(app.packageName, PackageManager.GET_SIGNING_CERTIFICATES).signingInfo ?: return emptyList()
        val sha = MessageDigest.getInstance("SHA-256")
        return info.apkContentsSigners.map { sig -> sha.digest(sig.toByteArray()).joinToString("") { "%02x".format(it) } }
    }

    override fun installedPackages(names: List<String>): List<String> = names.filter {
        try {
            pm.getPackageInfo(it, 0)
            true
        } catch (e: PackageManager.NameNotFoundException) {
            false
        }
    }

    override fun classLoadable(name: String): Boolean = listOf(ClassLoader.getSystemClassLoader(), javaClass.classLoader).any { cl ->
        try {
            Class.forName(name, false, cl)
            true
        } catch (e: Throwable) {
            false
        }
    }

    override fun stackClassNames(): List<String> = Throwable().stackTrace.map { it.className }
    override fun devOptions(): Boolean = Settings.Global.getInt(app.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) != 0
    override fun adbEnabled(): Boolean = Settings.Global.getInt(app.contentResolver, Settings.Global.ADB_ENABLED, 0) != 0
    override fun deviceSecure(): Boolean = app.getSystemService(KeyguardManager::class.java).isDeviceSecure
    override fun keystoreLevel(): SecurityLevel? = cachedLevel()
}
