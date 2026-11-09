package org.wolpmessenger.devicetrust

import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.wolpmessenger.devicetrust.api.BuildKind
import org.wolpmessenger.devicetrust.api.DeviceTrustConfig
import org.wolpmessenger.devicetrust.api.RaspCheck
import org.wolpmessenger.devicetrust.rasp.AndroidRaspEnv
import org.wolpmessenger.devicetrust.rasp.EffectivePolicy
import org.wolpmessenger.devicetrust.rasp.KotlinChecks
import org.wolpmessenger.devicetrust.rasp.NativeChecks
import org.wolpmessenger.devicetrust.rasp.NativeResult
import org.wolpmessenger.devicetrust.rasp.RaspEngine

/**
 * Real RASP pass on the device (S2 §13 "сравнение Kotlin- и native-реализаций"): the native
 * library loads, its HMAC verifies, the dual checks agree, and a stock phone yields no BLOCK
 * except APP_DEBUGGABLE (the test APK is debuggable). On an emulator EMULATOR must be found by both.
 */
@RunWith(AndroidJUnit4::class)
class RaspDeviceTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val env = AndroidRaspEnv(context) { null }
    private val kotlin = KotlinChecks(env, emptySet())

    @Test
    fun nativeAndKotlinAgreeAndStockPhoneIsClean() {
        val native = NativeChecks().scan()
        assertTrue("native library loads and the JNI result verifies: $native", native is NativeResult.Ok)
        native as NativeResult.Ok
        val dual = kotlin.dual()
        println("DT-RASP kotlin=$dual")
        println("DT-RASP native=${native.probes}")
        for ((id, k) in dual) assertEquals("$id: Kotlin and native agree", k.state, native.probes.getValue(id).state)

        val report = RaspEngine(kotlin, NativeChecks()::scan, EffectivePolicy(DeviceTrustConfig(buildKind = BuildKind.DEBUG), env.appDebuggable, env.versionCode)).evaluate()
        println("DT-RASP findings=${report.findings}")
        assertTrue("no tamper: ${report.findings}", report.findings.none { it.id == RaspCheck.HOOK_TAMPER })
        val emulator = Build.HARDWARE in KotlinChecks.EMU_HARDWARE
        if (emulator) {
            assertTrue(report.blocking.any { it.id == RaspCheck.EMULATOR })
        } else {
            assertEquals("stock phone: only the debuggable test APK blocks", setOf(RaspCheck.APP_DEBUGGABLE), report.blocking.map { it.id }.toSet())
        }
    }
}
