package org.wolpmessenger.devicetrust

/**
 * Library log (logcat tag `DeviceTrust`). Never passwords, cookies, nonces, keys or DEK (S2 §4):
 * callers pass codes and states only.
 */
internal object Journal {
    fun event(name: String, detail: String = "") {
        // android.util.Log is a stub on the JVM: tests run without it
        runCatching { android.util.Log.i("DeviceTrust", if (detail.isEmpty()) name else "$name $detail") }
    }
}
