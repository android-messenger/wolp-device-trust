package org.wolpmessenger.devicetrust

import android.app.KeyguardManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

/**
 * A probe, not a test (specs/001-rasp-hardening, story 2 and FR-013): how Keystore keys bound to
 * the lock screen behave on THIS device, and what the RASP inputs look like on it. It never fails;
 * it prints lines tagged `DT-PROBE` for the device matrix. Skipped unless run with `-e dtProbe <phase>`:
 *
 *   adb install -r -t devicetrust-debug-androidTest.apk
 *   adb shell am instrument -w -e class org.wolpmessenger.devicetrust.LockBindingProbeDeviceTest \
 *       -e dtProbe create|use|env|cleanup org.wolpmessenger.devicetrust.test/androidx.test.runner.AndroidJUnitRunner
 *
 * `create` while unlocked, then `use` in every state of interest (unlocked, locked, after unlock,
 * after the lock screen was removed). The keys stay until `cleanup` or until the test APK is removed.
 */
@RunWith(AndroidJUnit4::class)
class LockBindingProbeDeviceTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val phase: String? = InstrumentationRegistry.getArguments().getString("dtProbe")
    private val dir = File(context.noBackupFilesDir, "dt-probe").apply { mkdirs() }
    private val ks: KeyStore get() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun say(s: String) = println("DT-PROBE $s")
    private fun err(e: Throwable): String = generateSequence(e) { it.cause }.joinToString(" <- ") { "${it.javaClass.simpleName}(${it.message?.take(120)})" }

    private val specs: Map<String, (KeyGenParameterSpec.Builder) -> Unit> = mapOf(
        "plain" to { _ -> },
        "unlocked" to { b -> b.setUnlockedDeviceRequired(true) },
        "auth30" to { b ->
            b.setUserAuthenticationRequired(true)
            b.setUserAuthenticationParameters(30, KeyProperties.AUTH_DEVICE_CREDENTIAL or KeyProperties.AUTH_BIOMETRIC_STRONG)
        },
        "auth30+unlocked" to { b ->
            b.setUnlockedDeviceRequired(true)
            b.setUserAuthenticationRequired(true)
            b.setUserAuthenticationParameters(30, KeyProperties.AUTH_DEVICE_CREDENTIAL or KeyProperties.AUTH_BIOMETRIC_STRONG)
        },
    )

    private fun alias(name: String) = "dt.probe.$name"

    private fun deviceState(): String {
        val kg = context.getSystemService(KeyguardManager::class.java)
        return "deviceSecure=${kg.isDeviceSecure} deviceLocked=${kg.isDeviceLocked} keyguardLocked=${kg.isKeyguardLocked}"
    }

    @Test
    fun probe() {
        assumeTrue("probe only: pass -e dtProbe <phase>", phase != null)
        say("phase=$phase ${deviceState()}")
        when (phase) {
            "create" -> create()
            "use" -> use()
            "env" -> env()
            "cleanup" -> cleanup()
            "vault-create" -> vaultCreate()
            "vault-use" -> vaultUse()
            "vault-wipe" -> kotlinx.coroutines.runBlocking { org.wolpmessenger.devicetrust.vault.EnvelopeVault.android(context).wipe(); say("vault wiped") }
            else -> say("unknown phase")
        }
    }

    private fun create() {
        cleanup()
        for ((name, tweak) in specs) {
            try {
                val b = KeyGenParameterSpec.Builder(alias(name), KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).setKeySize(256)
                tweak(b)
                KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply { init(b.build()) }.generateKey()
                val key = ks.getKey(alias(name), null) as SecretKey
                val info = SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore").getKeySpec(key, KeyInfo::class.java) as KeyInfo
                say(
                    "create $name: OK level=${info.securityLevel} authRequired=${info.isUserAuthenticationRequired} authType=${info.userAuthenticationType} " +
                        "validity=${info.userAuthenticationValidityDurationSeconds}s hwEnforced=${info.isUserAuthenticationRequirementEnforcedBySecureHardware} " +
                        "invalidatedByBiometric=${info.isInvalidatedByBiometricEnrollment}",
                )
            } catch (e: Throwable) {
                say("create $name: FAIL ${err(e)}")
                continue
            }
            try {
                val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, ks.getKey(alias(name), null)) }
                File(dir, "$name.bin").writeBytes(c.iv + c.doFinal("probe".toByteArray()))
                say("encrypt $name: OK")
            } catch (e: Throwable) {
                say("encrypt $name: FAIL ${err(e)}")
            }
        }
    }

    private fun use() {
        for (name in specs.keys) {
            val present = runCatching { ks.containsAlias(alias(name)) }.getOrElse { say("alias $name: FAIL ${err(it)}"); false }
            if (!present) { say("use $name: key absent"); continue }
            try {
                val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, ks.getKey(alias(name), null)) }
                c.doFinal("x".toByteArray())
                say("encrypt $name: OK")
            } catch (e: Throwable) {
                say("encrypt $name: FAIL ${err(e)}")
            }
            val blob = File(dir, "$name.bin").takeIf { it.exists() }?.readBytes()
            if (blob == null) { say("decrypt $name: no blob from create"); continue }
            try {
                val c = Cipher.getInstance("AES/GCM/NoPadding")
                c.init(Cipher.DECRYPT_MODE, ks.getKey(alias(name), null), GCMParameterSpec(128, blob, 0, 12))
                say("decrypt $name: OK '${String(c.doFinal(blob, 12, blob.size - 12))}'")
            } catch (e: Throwable) {
                say("decrypt $name: FAIL ${err(e)}")
            }
        }
    }

    /** What the RASP inputs look like on a stock device: which paths answer what, which tokens occur. */
    private fun env() {
        val paths = listOf(
            "/data/adb", "/data/adb/magisk", "/data/adb/ksu", "/data/adb/ap", "/data/adb/modules", "/sbin", "/sbin/.magisk",
            "/debug_ramdisk", "/debug_ramdisk/.magisk", "/system/bin/su", "/system/xbin/su", "/data/local/tmp", "/proc/self/maps", "/proc/self/mountinfo",
        )
        for (p in paths) {
            val r = try {
                Os.stat(p); "exists"
            } catch (e: ErrnoException) {
                OsConstants.errnoName(e.errno)
            }
            say("stat $p: $r")
        }
        val maps = runCatching { File("/proc/self/maps").readLines() }.getOrElse { say("maps: FAIL ${err(it)}"); emptyList() }
        say("maps lines=${maps.size}")
        for (t in listOf("frida", "gum-js", "gadget", "libgadget.so", "magisk", "zygisk", "lsposed", "xposed", "riru")) {
            val hits = maps.filter { it.contains(t, ignoreCase = true) }
            say("maps token '$t': ${hits.size}" + hits.take(3).joinToString("") { " | " + it.substringAfterLast(' ').take(90) })
        }
        val mounts = runCatching { File("/proc/self/mountinfo").readLines() }.getOrElse { say("mountinfo: FAIL ${err(it)}"); emptyList() }
        say("mountinfo lines=${mounts.size}")
        for (t in listOf("magisk", "/data/adb/modules", "KSU", "APatch", " KSU ", " APatch ")) {
            val hits = mounts.filter { it.contains(t) }
            say("mountinfo token '$t': ${hits.size}" + hits.take(3).joinToString("") { " | " + it.take(140) })
        }
        say("status TracerPid: " + runCatching { File("/proc/self/status").readLines().first { it.startsWith("TracerPid") } }.getOrElse { err(it) })
        say("task threads=" + (File("/proc/self/task").list()?.size ?: -1))
    }

    // ---------------------------------------------------------------- the real two-key Vault (story 2)

    private fun vaultFile(name: String) = File(dir, "vault-$name.bin")

    private fun <T> attempt(what: String, block: suspend () -> T): T? = kotlinx.coroutines.runBlocking {
        try {
            block().also { say("$what: OK" + if (it is ByteArray) " (${it.size} bytes)" else if (it is Unit) "" else " $it") }
        } catch (e: Throwable) {
            say("$what: ${e.javaClass.simpleName}(${e.message?.take(80)})")
            null
        }
    }

    /** Unlocked: an older single-key vault with data, moved to two keys; blobs saved for `vault-use`. */
    private fun vaultCreate() {
        val v = org.wolpmessenger.devicetrust.vault.EnvelopeVault
        kotlinx.coroutines.runBlocking { v.android(context).wipe() }
        val legacy = org.wolpmessenger.devicetrust.vault.EnvelopeVault(
            org.wolpmessenger.devicetrust.vault.AndroidKek(), File(context.noBackupFilesDir, "dt/dek.bin"),
            org.wolpmessenger.devicetrust.vault.UnlockState.android(context),
        )
        attempt("legacy provision") { legacy.provision() }
        attempt("legacy wrap E2EE") { legacy.wrap("ratchet".toByteArray(), org.wolpmessenger.devicetrust.api.VaultPurpose.E2EE) }?.let { vaultFile("e2ee").writeBytes(it) }
        val two = v.android(context)
        say("keys before migrate=${two.keys()}")
        attempt("migrate") { two.migrate() }
        say("keys after migrate=${two.keys()}")
        attempt("wrap PUSH_KEY") { two.wrap("push".toByteArray(), org.wolpmessenger.devicetrust.api.VaultPurpose.PUSH_KEY) }?.let { vaultFile("push").writeBytes(it) }
        attempt("unwrap E2EE (made before migrate)") { String(two.unwrap(vaultFile("e2ee").readBytes(), org.wolpmessenger.devicetrust.api.VaultPurpose.E2EE)) }
    }

    /** In any state, as a new process: what each half of the Vault answers. */
    private fun vaultUse() {
        val two = org.wolpmessenger.devicetrust.vault.EnvelopeVault.android(context)
        say("keys=${two.keys()}")
        attempt("unwrap E2EE") { String(two.unwrap(vaultFile("e2ee").readBytes(), org.wolpmessenger.devicetrust.api.VaultPurpose.E2EE)) }
        attempt("wrap E2EE") { two.wrap("x".toByteArray(), org.wolpmessenger.devicetrust.api.VaultPurpose.E2EE) }
        attempt("unwrap PUSH_KEY") { String(two.unwrap(vaultFile("push").readBytes(), org.wolpmessenger.devicetrust.api.VaultPurpose.PUSH_KEY)) }
        attempt("wrap NAMES") { two.wrap("x".toByteArray(), org.wolpmessenger.devicetrust.api.VaultPurpose.NAMES) }
        say("keys after=${two.keys()}")
    }

    private fun cleanup() {
        for (name in specs.keys) runCatching { if (ks.containsAlias(alias(name))) ks.deleteEntry(alias(name)) }
        dir.listFiles()?.forEach { it.delete() }
        say("cleanup done")
    }
}
