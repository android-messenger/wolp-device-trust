package org.wolpmessenger.devicetrust

import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.wolpmessenger.devicetrust.alert.AlertQueue
import org.wolpmessenger.devicetrust.alert.Alerts
import org.wolpmessenger.devicetrust.api.BlockReason
import org.wolpmessenger.devicetrust.api.BuildKind
import org.wolpmessenger.devicetrust.api.DeviceTrustConfig
import org.wolpmessenger.devicetrust.api.RaspCheck
import org.wolpmessenger.devicetrust.api.RaspFinding
import org.wolpmessenger.devicetrust.api.RaspPolicy
import org.wolpmessenger.devicetrust.api.RaspReaction
import org.wolpmessenger.devicetrust.api.RaspReaction.BLOCK
import org.wolpmessenger.devicetrust.api.RaspReaction.IGNORE
import org.wolpmessenger.devicetrust.api.RaspReaction.REPORT
import org.wolpmessenger.devicetrust.api.ReportLimit
import org.wolpmessenger.devicetrust.api.SecurityLevel
import org.wolpmessenger.devicetrust.api.TrustEvent
import org.wolpmessenger.devicetrust.api.TrustState
import org.wolpmessenger.devicetrust.attest.Precheck
import org.wolpmessenger.devicetrust.attest.RaspScanner
import org.wolpmessenger.devicetrust.cert.CertManager
import org.wolpmessenger.devicetrust.cert.Versions
import org.wolpmessenger.devicetrust.clock.TrustClock
import org.wolpmessenger.devicetrust.enroll.Enroller
import org.wolpmessenger.devicetrust.keys.KeystoreKeys
import org.wolpmessenger.devicetrust.net.GatewayClient
import org.wolpmessenger.devicetrust.rasp.EffectivePolicy
import org.wolpmessenger.devicetrust.rasp.KotlinChecks
import org.wolpmessenger.devicetrust.rasp.NativeChecks
import org.wolpmessenger.devicetrust.rasp.NativeResult
import org.wolpmessenger.devicetrust.rasp.ProbeFailure
import org.wolpmessenger.devicetrust.rasp.ProbeState
import org.wolpmessenger.devicetrust.rasp.RaspEngine
import org.wolpmessenger.devicetrust.rasp.RaspEnv
import org.wolpmessenger.devicetrust.store.ActiveCert
import org.wolpmessenger.devicetrust.store.Phase
import org.wolpmessenger.devicetrust.store.StoredState
import org.wolpmessenger.devicetrust.store.TrustStore
import java.time.Instant
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** S2 §7: checks, Kotlin/native comparison, JNI integrity, the §7.3 policy, reactions. */
class RaspTest {
    @get:Rule
    val tmp = TemporaryFolder()

    /** A clean, locked-down phone; tests flip what they need. */
    private class Env : RaspEnv {
        val present = mutableSetOf<String>()
        val denied = mutableSetOf<String>()
        var status = "Name:\tapp\nTracerPid:\t0\n"
        var path = "/product/bin:/apex/com.android.runtime/bin:/system/bin"
        override var buildTags = "release-keys"
        override var buildHardware = "s5e8855"
        override var buildFingerprint = "samsung/a37xnaeea/a37x:16/BP2A.250605.031.A3/A376BXXU1AYJ1:user/release-keys"
        var jdwp = false
        override var appDebuggable = false
        override var versionCode = 10300L
        var signers = listOf("aa".repeat(32))
        var packages = emptyList<String>()
        var classes = emptySet<String>()
        var stack = listOf("org.wolpmessenger.devicetrust.rasp.KotlinChecks")
        var dev = false
        var adb = false
        var secure = true
        var level: SecurityLevel? = SecurityLevel.TRUSTED_ENVIRONMENT

        override fun stat(path: String) = when (path) {
            in present -> ProbeState.FOUND
            in denied -> ProbeState.DENIED
            else -> ProbeState.CLEAN
        }
        override fun read(path: String): Result<String> =
            if (path in denied) Result.failure(ProbeFailure(ProbeState.DENIED)) else Result.success(status)
        override fun env(name: String) = if (name == "PATH") path else null
        override fun isDebuggerConnected() = jdwp
        override fun signingDigests() = signers
        override fun installedPackages(names: List<String>) = names.filter { it in packages }
        override fun classLoadable(name: String) = name in classes
        override fun stackClassNames() = stack
        override fun devOptions() = dev
        override fun adbEnabled() = adb
        override fun deviceSecure() = secure
        override fun keystoreLevel() = level
    }

    private val env = Env()
    private val key = ByteArray(32) { 9 }

    /** What a native library would return for [lines], with a correct or a forged HMAC. */
    private fun nativeBytes(lines: String, k: ByteArray = key): ByteArray {
        val body = lines.toByteArray()
        return body + Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(k, "HmacSHA256")) }.doFinal(body)
    }

    private val cleanNative = "ROOT_SU|C|\nDEBUGGER|C|\nEMULATOR|C|\nAPK_SIGNATURE|C|\nROOT_MAGISK|C|\nROOT_PROPS|C|\nHOOK_FRIDA_MAPS|C|\nHOOK_FRIDA_PORT|C|\n"
    private var nativeOut: () -> NativeResult = { NativeChecks.parse(nativeBytes(cleanNative), key) }

    private fun config(policy: RaspPolicy = RaspPolicy.default(), kind: BuildKind = BuildKind.RELEASE, dryRun: Boolean = false) =
        DeviceTrustConfig(expectedSigningDigests = listOf("AA:".repeat(31) + "AA"), raspPolicy = policy, buildKind = kind, raspDryRun = dryRun)

    private fun engine(cfg: DeviceTrustConfig = config()): RaspEngine =
        RaspEngine(KotlinChecks(env, KotlinChecks.normalize(cfg.expectedSigningDigests)), { nativeOut() }, EffectivePolicy(cfg, env.appDebuggable, env.versionCode))

    private fun ids(r: org.wolpmessenger.devicetrust.api.RaspReport) = r.findings.map { it.id to it.reaction }.toSet()

    @Test
    fun `clean locked-down release phone - no findings`() {
        assertEquals(emptyList<RaspFinding>(), engine().evaluate().findings)
    }

    @Test
    fun `settings findings are REPORT by default`() {
        env.dev = true; env.adb = true; env.secure = false
        env.packages = listOf("com.topjohnwu.magisk")
        assertEquals(
            setOf(RaspCheck.DEV_OPTIONS to REPORT, RaspCheck.ADB_ENABLED to REPORT, RaspCheck.NO_SCREEN_LOCK to REPORT, RaspCheck.ROOT_MANAGER_PKG to REPORT),
            ids(engine().evaluate()),
        )
    }

    @Test
    fun `su found by both implementations - one BLOCK, no tamper`() {
        env.present += "/system/xbin/su"
        nativeOut = { NativeChecks.parse(nativeBytes(cleanNative.replace("ROOT_SU|C|", "ROOT_SU|F|/system/xbin/su")), key) }
        val r = engine().evaluate()
        assertEquals(listOf(RaspFinding(RaspCheck.ROOT_SU, BLOCK, "/system/xbin/su")), r.findings)
    }

    @Test
    fun `su in a PATH directory is found`() {
        env.path = "/sbin/bin:/opt/xbin"
        env.present += "/opt/xbin/su"
        nativeOut = { NativeChecks.parse(nativeBytes(cleanNative.replace("ROOT_SU|C|", "ROOT_SU|F|/opt/xbin/su")), key) }
        assertEquals(RaspFinding(RaspCheck.ROOT_SU, BLOCK, "/opt/xbin/su"), engine().evaluate().findings.single())
    }

    @Test
    fun `Kotlin and native disagree - the finding plus HOOK_TAMPER (REPORT)`() {
        // native says clean, Kotlin found: someone hooked the native side (or the other way round)
        env.present += "/sbin/su"
        val r = engine().evaluate()
        assertEquals(setOf(RaspCheck.ROOT_SU to BLOCK, RaspCheck.HOOK_TAMPER to REPORT), ids(r))
        assertEquals("ROOT_SU kotlin=FOUND native=CLEAN", r.findings.first { it.id == RaspCheck.HOOK_TAMPER }.detail)

        // found only natively
        env.present.clear()
        nativeOut = { NativeChecks.parse(nativeBytes(cleanNative.replace("EMULATOR|C|", "EMULATOR|F|/dev/qemu_pipe")), key) }
        val r2 = engine().evaluate()
        assertEquals(setOf(RaspCheck.EMULATOR to BLOCK, RaspCheck.HOOK_TAMPER to REPORT), ids(r2))
        assertEquals("native:/dev/qemu_pipe", r2.findings.first { it.id == RaspCheck.EMULATOR }.detail)
    }

    @Test
    fun `EACCES is its own result, never found - but a mismatch is still tamper`() {
        env.denied += "/sbin/su"
        nativeOut = { NativeChecks.parse(nativeBytes(cleanNative.replace("ROOT_SU|C|", "ROOT_SU|D|/sbin/su")), key) }
        assertEquals(emptyList<RaspFinding>(), engine().evaluate().findings)

        nativeOut = { NativeChecks.parse(nativeBytes(cleanNative), key) }
        assertEquals(setOf(RaspCheck.HOOK_TAMPER to REPORT), ids(engine().evaluate()))
    }

    @Test
    fun `native-only findings - frida, magisk, props`() {
        nativeOut = {
            NativeChecks.parse(nativeBytes(cleanNative.replace("HOOK_FRIDA_PORT|C|", "HOOK_FRIDA_PORT|F|port=27042")
                .replace("ROOT_MAGISK|C|", "ROOT_MAGISK|F|mountinfo:magisk").replace("ROOT_PROPS|C|", "ROOT_PROPS|F|ro.debuggable=1")), key)
        }
        assertEquals(setOf(RaspCheck.HOOK_FRIDA_PORT to BLOCK, RaspCheck.ROOT_MAGISK to BLOCK, RaspCheck.ROOT_PROPS to BLOCK), ids(engine().evaluate()))
    }

    @Test
    fun `APK_SIGNATURE - native reads the APK itself, a PackageManager hook is HOOK_TAMPER`() {
        // PackageManager (hooked) says the expected signer, the installed file says otherwise
        nativeOut = { NativeChecks.parse(nativeBytes(cleanNative.replace("APK_SIGNATURE|C|", "APK_SIGNATURE|F|unexpected=" + "cc".repeat(32))), key) }
        assertEquals(
            setOf(
                RaspFinding(RaspCheck.APK_SIGNATURE, BLOCK, "native:unexpected=" + "cc".repeat(32)),
                RaspFinding(RaspCheck.HOOK_TAMPER, REPORT, "APK_SIGNATURE kotlin=CLEAN native=FOUND"),
            ),
            engine().evaluate().findings.toSet(),
        )
        // the APK could not be read natively: only the tamper signal, no BLOCK
        nativeOut = { NativeChecks.parse(nativeBytes(cleanNative.replace("APK_SIGNATURE|C|", "APK_SIGNATURE|D|apk not found")), key) }
        assertEquals(listOf(RaspFinding(RaspCheck.HOOK_TAMPER, REPORT, "APK_SIGNATURE kotlin=CLEAN native=DENIED")), engine().evaluate().findings)
        // no signers at all
        env.signers = emptyList()
        nativeOut = { NativeChecks.parse(nativeBytes(cleanNative.replace("APK_SIGNATURE|C|", "APK_SIGNATURE|F|no signers")), key) }
        assertEquals(listOf(RaspFinding(RaspCheck.APK_SIGNATURE, BLOCK, "no signers")), engine().evaluate().findings)
    }

    @Test
    fun `APK_SIGNATURE - nothing configured (debuggable app) means no check on either side`() {
        env.appDebuggable = true
        val cfg = DeviceTrustConfig(buildKind = BuildKind.DEBUG, raspPolicy = RaspPolicy.default().with(RaspCheck.APP_DEBUGGABLE, IGNORE))
        nativeOut = { NativeChecks.parse(nativeBytes(cleanNative.replace("APK_SIGNATURE|C|\n", "")), key) }
        env.signers = listOf("bb".repeat(32))
        assertEquals(emptyList<RaspFinding>(), engine(cfg).evaluate().findings)
    }

    @Test
    fun `expected digests - normalised, passed to native as raw bytes, garbage rejected`() {
        val digests = KotlinChecks.normalize(listOf("AA:".repeat(31) + "AA", "0f".repeat(32)))
        assertEquals(setOf("aa".repeat(32), "0f".repeat(32)), digests)
        var seen = ByteArray(0)
        NativeChecks(digests) { _, e -> seen = e; null }.scan()
        assertEquals(64, seen.size)
        assertEquals(setOf(ByteArray(32) { 0x0f }.toList(), ByteArray(32) { 0xaa.toByte() }.toList()), setOf(seen.copyOfRange(0, 32).toList(), seen.copyOfRange(32, 64).toList()))
        for (bad in listOf("aa".repeat(31), "zz".repeat(32), "sha256/" + "aa".repeat(32))) {
            assertTrue(bad, runCatching { KotlinChecks.normalize(listOf(bad)) }.exceptionOrNull() is IllegalArgumentException)
        }
    }

    @Test
    fun `JNI integrity - forged HMAC, malformed output, missing library are HOOK_TAMPER`() {
        assertEquals(NativeResult.Tampered("jni hmac"), NativeChecks.parse(nativeBytes(cleanNative, ByteArray(32)), key))
        assertEquals(NativeResult.Tampered("malformed"), NativeChecks.parse(nativeBytes("ROOT_SU|X|\n"), key))
        assertEquals(NativeResult.Tampered("short"), NativeChecks.parse(ByteArray(5), key))
        val real = NativeChecks { _, _ -> throw UnsatisfiedLinkError("no libwolpdt") }
        assertEquals(NativeResult.Tampered("native unavailable"), real.scan())

        nativeOut = { NativeResult.Tampered("jni hmac") }
        assertEquals(listOf(RaspFinding(RaspCheck.HOOK_TAMPER, REPORT, "jni hmac")), engine().evaluate().findings)
    }

    @Test
    fun `Kotlin-only checks - debugger, xposed, signature, debuggable, software keystore, test-keys`() {
        env.jdwp = true
        env.classes = setOf("de.robv.android.xposed.XposedBridge")
        env.signers = listOf("bb".repeat(32))
        env.appDebuggable = true
        env.level = SecurityLevel.SOFTWARE
        env.buildTags = "test-keys"
        env.status = "TracerPid:\t4242\n"
        nativeOut = {
            NativeChecks.parse(
                nativeBytes(cleanNative.replace("DEBUGGER|C|", "DEBUGGER|F|tracer=4242").replace("APK_SIGNATURE|C|", "APK_SIGNATURE|F|unexpected=" + "bb".repeat(32))),
                key,
            )
        }
        val r = engine().evaluate()
        assertEquals(
            setOf(RaspCheck.DEBUGGER to BLOCK, RaspCheck.HOOK_XPOSED to BLOCK, RaspCheck.APK_SIGNATURE to BLOCK, RaspCheck.APP_DEBUGGABLE to BLOCK,
                RaspCheck.KEYSTORE_SOFTWARE to BLOCK, RaspCheck.ROOT_TEST_KEYS to REPORT),
            ids(r),
        )
        assertEquals(setOf("tracer=4242", "jdwp"), r.findings.filter { it.id == RaspCheck.DEBUGGER }.map { it.detail }.toSet())
        assertEquals("unexpected=" + "bb".repeat(32), r.findings.first { it.id == RaspCheck.APK_SIGNATURE }.detail)
    }

    @Test
    fun `test-keys alone never blocks - from Kotlin, from native or from both`() {
        env.buildTags = "test-keys"
        nativeOut = { NativeChecks.parse(nativeBytes(cleanNative + "ROOT_TEST_KEYS|F|ro.build.tags=test-keys\n"), key) }
        val r = engine().evaluate()
        assertTrue(r.blocking.isEmpty())
        assertEquals(setOf(RaspCheck.ROOT_TEST_KEYS to REPORT), ids(r))
    }

    @Test
    fun `xposed frames on the stack`() {
        env.stack = listOf("java.lang.Thread", "de.robv.android.xposed.XC_MethodHook")
        assertEquals(RaspFinding(RaspCheck.HOOK_XPOSED, BLOCK, "de.robv.android.xposed.XC_MethodHook"), engine().evaluate().findings.single())
    }

    // ---------------------------------------------------------------- §7.3 policy

    @Test
    fun `release - lowering is ignored, raising and unknown ids work`() {
        val policy = RaspPolicy.default().with(RaspCheck.ROOT_SU, IGNORE).with(RaspCheck.DEV_OPTIONS, BLOCK).with("CUSTOM", BLOCK)
        val p = EffectivePolicy(config(policy, kind = BuildKind.DEBUG, dryRun = true), debuggable = false, versionCode = 10300)
        assertEquals("DEBUG declared, but not debuggable and not a pilot versionCode", BuildKind.RELEASE, p.kind)
        assertEquals(BLOCK, p.reaction(RaspCheck.ROOT_SU))
        assertEquals(BLOCK, p.reaction(RaspCheck.DEV_OPTIONS))
        assertEquals(BLOCK, p.reaction("CUSTOM"))
        assertEquals(REPORT, p.reaction("NEVER_HEARD"))
        assertTrue("dry run ignored in release", !p.dryRun)
    }

    @Test
    fun `debuggable - lowering works, IGNORE drops the finding`() {
        env.appDebuggable = true
        val cfg = config(RaspPolicy.default().with(RaspCheck.APP_DEBUGGABLE, IGNORE).with(RaspCheck.EMULATOR, REPORT), kind = BuildKind.DEBUG)
        env.buildHardware = "ranchu"
        nativeOut = { NativeChecks.parse(nativeBytes(cleanNative.replace("EMULATOR|C|", "EMULATOR|F|hardware=ranchu")), key) }
        assertEquals(listOf(RaspFinding(RaspCheck.EMULATOR, REPORT, "hardware=ranchu")), engine(cfg).evaluate().findings)
    }

    @Test
    fun `pilot - only with a pilot versionCode, dry run turns BLOCK into a marked REPORT`() {
        val cfg = config(kind = BuildKind.PILOT, dryRun = true)
        assertEquals(BuildKind.RELEASE, EffectivePolicy(cfg, debuggable = false, versionCode = 10300).kind)
        val p = EffectivePolicy(cfg, debuggable = false, versionCode = 10295)
        assertEquals(BuildKind.PILOT, p.kind)
        assertTrue(p.dryRun)

        env.versionCode = 10295
        env.present += "/system/bin/su"
        nativeOut = { NativeChecks.parse(nativeBytes(cleanNative.replace("ROOT_SU|C|", "ROOT_SU|F|/system/bin/su")), key) }
        val r = engine(cfg).evaluate()
        assertEquals(listOf(RaspFinding(RaspCheck.ROOT_SU, REPORT, "dryRun;BLOCK;/system/bin/su")), r.findings)
        assertTrue(r.blocking.isEmpty())
    }

    // ---------------------------------------------------------------- reactions through the core

    @Test
    fun `checkIntegrity - BLOCK runs the reaction once, REPORT is queued`() = runTest {
        val store = TrustStore(tmp.root)
        val backend = FakeBackend()
        val keys = KeystoreKeys(backend)
        val t0 = Instant.parse("2026-11-08T10:00:00Z")
        val clock = TrustClock(MutableClock(t0.toEpochMilli()))
        val k1 = ActiveCert("dt.device.k1", "abc", t0, t0.plusSeconds(72 * 3600), t0.plusSeconds(48 * 3600))
        backend.generateSigningKey(k1.alias, null, false)
        store.save(StoredState(phase = Phase.ENROLLED, deviceId = "01JD", active = k1))
        val events = mutableListOf<TrustEvent>()
        val queue = AlertQueue(tmp.root, ReportLimit())
        val alerts = Alerts(queue, store, keys, clock::now, { 10300 }, {})
        val cfg = config()
        val gateway = GatewayClient(OkHttpClient(), okhttp3.HttpUrl.Builder().scheme("http").host("localhost").build(), {})
        val scanner = RaspScanner { engine(cfg).scan().also { alerts.report(it.reports) } }
        val precheck = Precheck(keys, FakeEnv(), MemCache(), scanner, cfg)
        val vault = FakeVault()
        val enroller = Enroller(cfg, precheck::run, keys, gateway, store, { vault.provision() }, { 10300 }, clock::now)
        val certs = CertManager(cfg, store, keys, clock, gateway, OkHttpClient(), { OkHttpClient() }, vault, enroller,
            { Versions(10300, "2026-10-01") }, { events += it }, scanner::scan, alerts)
        val core = DeviceTrustCore(cfg, store, clock, precheck, enroller, certs, MutableSharedFlow(extraBufferCapacity = 16), rasp = scanner::scan)
        core.initialize()

        env.dev = true
        core.checkIntegrity()
        assertEquals(TrustState.Active(k1.notAfter, k1.renewAfter), core.state.value)
        assertEquals("REPORT queued (batched at send time)", false, queue.isEmpty())

        env.jdwp = true
        core.checkIntegrity()
        core.checkIntegrity()
        assertEquals(TrustState.Blocked(BlockReason.RASP), core.state.value)
        assertEquals("one wipe, one event", listOf<TrustEvent>(TrustEvent.Blocked(BlockReason.RASP)), events)
        assertEquals("one BLOCK message", 1, queue.list().count { it.kind == org.wolpmessenger.devicetrust.alert.AlertKind.BLOCK })
    }
}
