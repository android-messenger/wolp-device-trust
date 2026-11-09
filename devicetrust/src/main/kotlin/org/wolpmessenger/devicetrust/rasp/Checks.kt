package org.wolpmessenger.devicetrust.rasp

import org.wolpmessenger.devicetrust.api.RaspCheck

/**
 * Kotlin RASP checks (S2 §7.1). ROOT_SU, DEBUGGER (TracerPid) and EMULATOR have a native twin in
 * `devicetrust-native/src/rasp.c` with **the same inputs and syscalls** (stat, open/read, the
 * same system properties) — keep the lists identical: a difference between the two results is
 * reported as HOOK_TAMPER.
 */
internal class KotlinChecks(private val env: RaspEnv, private val expectedDigests: Set<String>) {
    /** Checks with a native twin, keyed by id. */
    fun dual(): Map<String, Probe> = mapOf(
        RaspCheck.ROOT_SU to su(),
        RaspCheck.DEBUGGER to tracer(),
        RaspCheck.EMULATOR to emulator(),
    )

    /** Kotlin-only findings. */
    fun single(): List<RawFinding> = buildList {
        if (env.isDebuggerConnected()) add(RawFinding(RaspCheck.DEBUGGER, "jdwp"))
        env.installedPackages(ROOT_MANAGERS).forEach { add(RawFinding(RaspCheck.ROOT_MANAGER_PKG, it)) }
        if ("test-keys" in env.buildTags) add(RawFinding(RaspCheck.ROOT_PROPS, "Build.TAGS=test-keys"))
        xposed()?.let { add(RawFinding(RaspCheck.HOOK_XPOSED, it)) }
        apkSignature()?.let { add(RawFinding(RaspCheck.APK_SIGNATURE, it)) }
        if (env.appDebuggable) add(RawFinding(RaspCheck.APP_DEBUGGABLE))
        env.keystoreLevel()?.takeIf { !it.isHardwareConfirmed }?.let { add(RawFinding(RaspCheck.KEYSTORE_SOFTWARE, it.name)) }
        if (env.devOptions()) add(RawFinding(RaspCheck.DEV_OPTIONS))
        if (env.adbEnabled()) add(RawFinding(RaspCheck.ADB_ENABLED))
        if (!env.deviceSecure()) add(RawFinding(RaspCheck.NO_SCREEN_LOCK))
    }

    /** Fixed paths, then `<dir>/su` for every PATH entry; first FOUND wins, else first DENIED. */
    private fun su(): Probe = firstHit(SU_PATHS + (env.env("PATH") ?: "").split(':').filter { it.isNotEmpty() }.map { "$it/su" })

    private fun tracer(): Probe {
        val status = env.read("/proc/self/status").getOrElse { e ->
            return Probe((e as? ProbeFailure)?.state?.takeIf { it == ProbeState.DENIED } ?: ProbeState.CLEAN, "status unreadable")
        }
        val pid = Regex("TracerPid:\\s*(\\d+)").find(status)?.groupValues?.get(1)?.toLongOrNull() ?: 0
        return if (pid != 0L) Probe(ProbeState.FOUND, "tracer=$pid") else Probe.CLEAN
    }

    private fun emulator(): Probe {
        val hw = env.buildHardware
        if (hw in EMU_HARDWARE) return Probe(ProbeState.FOUND, "hardware=$hw")
        val fp = env.buildFingerprint
        if (fp.startsWith("generic") || "emulator" in fp || "sdk_gphone" in fp) return Probe(ProbeState.FOUND, "fingerprint=$fp")
        return firstHit(EMU_PATHS)
    }

    private fun firstHit(paths: List<String>): Probe {
        var denied: String? = null
        for (p in paths) {
            when (env.stat(p)) {
                ProbeState.FOUND -> return Probe(ProbeState.FOUND, p)
                ProbeState.DENIED -> if (denied == null) denied = p
                ProbeState.CLEAN -> Unit
            }
        }
        return denied?.let { Probe(ProbeState.DENIED, it) } ?: Probe.CLEAN
    }

    private fun xposed(): String? {
        XPOSED_CLASSES.firstOrNull(env::classLoadable)?.let { return it }
        return env.stackClassNames().firstOrNull { n -> XPOSED_STACK.any { it in n } }
    }

    /** The current signers must all be expected; nothing configured (debuggable app only) → not checked. */
    private fun apkSignature(): String? {
        if (expectedDigests.isEmpty()) return null
        val actual = env.signingDigests()
        if (actual.isEmpty()) return "no signers"
        return actual.firstOrNull { it !in expectedDigests }?.let { "unexpected=$it" }
    }

    internal companion object {
        val SU_PATHS = listOf(
            "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su", "/data/local/su", "/data/local/bin/su",
            "/data/local/xbin/su", "/system/sd/xbin/su", "/vendor/bin/su", "/product/bin/su", "/odm/bin/su", "/debug_ramdisk/su",
        )
        val EMU_HARDWARE = setOf("goldfish", "ranchu", "vbox86")
        val EMU_PATHS = listOf(
            "/dev/qemu_pipe", "/dev/goldfish_pipe", "/dev/socket/qemud", "/sys/qemu_trace", "/system/bin/qemu-props",
            "/system/lib/libc_malloc_debug_qemu.so",
        )

        /** Also declared in the library manifest `<queries>` — invisible otherwise on Android 11+. */
        val ROOT_MANAGERS = listOf(
            "com.topjohnwu.magisk", "io.github.vvb2060.magisk", "io.github.huskydg.magisk", "me.weishu.kernelsu",
            "me.bmax.apatch", "eu.chainfire.supersu", "com.koushikdutta.superuser", "com.noshufou.android.su",
        )
        val XPOSED_CLASSES = listOf("de.robv.android.xposed.XposedBridge", "de.robv.android.xposed.XposedHelpers", "org.lsposed.lspd.core.Main")
        val XPOSED_STACK = listOf("de.robv.android.xposed", "org.lsposed", "LSPHooker", "EdHooker")

        /** Normalises configured digests: lowercase hex, no separators. */
        fun normalize(digests: List<String>): Set<String> = digests.map { it.lowercase().filter { c -> c in '0'..'9' || c in 'a'..'f' } }.toSet()
    }
}
