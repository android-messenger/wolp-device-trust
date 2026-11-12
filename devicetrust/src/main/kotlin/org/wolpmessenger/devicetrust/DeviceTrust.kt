package org.wolpmessenger.devicetrust

import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Build
import android.os.Handler
import android.os.Looper
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import kotlinx.coroutines.Job
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.drop
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.HttpUrl.Companion.toHttpUrl
import org.wolpmessenger.devicetrust.alert.AlertQueue
import org.wolpmessenger.devicetrust.alert.AlertSender
import org.wolpmessenger.devicetrust.alert.AlertWorker
import org.wolpmessenger.devicetrust.alert.Alerts
import org.wolpmessenger.devicetrust.api.ClientCredentials
import org.wolpmessenger.devicetrust.api.DenySource
import org.wolpmessenger.devicetrust.api.GatewayCode
import org.wolpmessenger.devicetrust.api.SessionBinding
import org.wolpmessenger.devicetrust.api.DeviceSecurityInfo
import org.wolpmessenger.devicetrust.api.DeviceTrustConfig
import org.wolpmessenger.devicetrust.api.E2ee
import org.wolpmessenger.devicetrust.api.EnrollResult
import org.wolpmessenger.devicetrust.api.PrecheckResult
import org.wolpmessenger.devicetrust.api.UnenrollResult
import org.wolpmessenger.devicetrust.api.TrustEvent
import org.wolpmessenger.devicetrust.api.TrustState
import org.wolpmessenger.devicetrust.api.Vault
import org.wolpmessenger.devicetrust.api.RaspReport
import org.wolpmessenger.devicetrust.attest.FilePrecheckCache
import org.wolpmessenger.devicetrust.attest.Precheck
import org.wolpmessenger.devicetrust.attest.RaspScanner
import org.wolpmessenger.devicetrust.rasp.AndroidRaspEnv
import org.wolpmessenger.devicetrust.rasp.EffectivePolicy
import org.wolpmessenger.devicetrust.rasp.IntegrityGate
import org.wolpmessenger.devicetrust.rasp.KotlinChecks
import org.wolpmessenger.devicetrust.rasp.NativeChecks
import org.wolpmessenger.devicetrust.rasp.RaspEngine
import org.wolpmessenger.devicetrust.rasp.RaspSummaryStore
import org.wolpmessenger.devicetrust.cert.CertManager
import org.wolpmessenger.devicetrust.cert.RenewWorker
import org.wolpmessenger.devicetrust.cert.VaultOps
import org.wolpmessenger.devicetrust.cert.Versions
import org.wolpmessenger.devicetrust.clock.AndroidClockSource
import org.wolpmessenger.devicetrust.clock.TrustClock
import org.wolpmessenger.devicetrust.e2ee.E2eeService
import org.wolpmessenger.devicetrust.e2ee.KeyDirectoryClient
import org.wolpmessenger.devicetrust.enroll.Enroller
import org.wolpmessenger.devicetrust.keys.KeystoreKeys
import org.wolpmessenger.devicetrust.net.GatewayClient
import org.wolpmessenger.devicetrust.net.HttpClients
import org.wolpmessenger.devicetrust.tls.DeviceHttp
import okhttp3.OkHttpClient
import org.wolpmessenger.devicetrust.store.TrustStore
import org.wolpmessenger.devicetrust.vault.EnvelopeVault
import java.io.File
import java.time.Duration
import java.time.Instant

/**
 * The only entry point for the application (S2 §4). Implemented so far: init (with the S2 §6.6
 * reconciliation), state, credentialsVersion, events, trustNow, precheck, enroll, ensureFresh
 * (renewal / recovery), onGatewayDenied, checkSessionBinding, unenroll, clientCredentials,
 * checkIntegrity (RASP), okHttpClient, updateHttpClient, vault, deviceInfo, e2ee (secret chats).
 */
public object DeviceTrust {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val uninitialized = MutableStateFlow<TrustState>(TrustState.Uninitialized)
    private val zero = MutableStateFlow(0L)
    private val eventSink = MutableSharedFlow<TrustEvent>(extraBufferCapacity = 16) // core-internal

    /**
     * Events wait here until S1 collects them: init's reconciliation emits `VaultReset` / `Blocked`
     * asynchronously, typically before anyone subscribed — a SharedFlow would drop them.
     */
    private val eventQueue = Channel<TrustEvent>(capacity = 64, onBufferOverflow = BufferOverflow.DROP_OLDEST)

    @Volatile
    private var core: DeviceTrustCore? = null
    private var vaultImpl: EnvelopeVault? = null
    private var deviceHttp: DeviceHttp? = null
    private var e2eeImpl: E2eeService<KeyDirectoryClient>? = null

    internal val isInitialized: Boolean get() = core != null

    /** Fast and non-blocking; safe in `Application.onCreate` (the process also starts for FCM). A second call is ignored. */
    @Synchronized
    public fun init(context: Context, config: DeviceTrustConfig) {
        if (core != null) return
        config.validateForNetwork()
        val passportTrust = E2eeService.trust(config.e2eeRoots, config.e2eeIssuers)
        val app = context.applicationContext
        val debuggable = (app.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
        require(debuggable || config.expectedSigningDigests.isNotEmpty()) { "expectedSigningDigests is required in a non-debuggable app (APK_SIGNATURE, S2 §7.1)" }
        val dir = File(app.noBackupFilesDir, "dt")
        val store = TrustStore(dir)
        val keys = KeystoreKeys.android()
        val clock = TrustClock(AndroidClockSource(app), store.load().clock)
        val gate = IntegrityGate()
        val vault = EnvelopeVault.android(app, gate = { gate.require() })
        val versionCodeEarly: Long = app.packageManager.getPackageInfo(app.packageName, 0).longVersionCode
        val precheckCache = FilePrecheckCache(File(dir, "precheck.properties"))
        val digests = KotlinChecks.normalize(config.expectedSigningDigests)
        val engine = RaspEngine(
            KotlinChecks(AndroidRaspEnv(app) { precheckCache.load()?.level }, digests),
            NativeChecks(digests)::scan,
            EffectivePolicy(config, debuggable, versionCodeEarly),
        )
        val summary = RaspSummaryStore(File(dir, "rasp-summary.json"), clock::now)
        lateinit var alertsRef: Alerts
        // every RASP pass queues its REPORT findings (rate-limited, S2 §7.4)
        // …and decides whether the Vault may hand out secrets: every pass goes through here (start-up,
        // foreground, precheck, renewal), so the gate always reflects the latest one
        val scanner = RaspScanner {
            val r = try {
                engine.scan()
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (e: Exception) {
                gate.record(open = false) // a pass that could not run proves nothing
                throw e
            }
            gate.record(engine.allowsSecrets(r))
            // counted for the summary sent with the next renewal (FR-035); a full disk must not fail the pass
            runCatching { summary.record(r, engine.nativeRan) }.onFailure { Journal.event("rasp_summary_failed", it.javaClass.simpleName) }
            if (r.reports.isNotEmpty()) alertsRef.report(r.reports)
            r
        }
        val precheck = Precheck.android(app, config, scanner)
        val onServerDate: (String?) -> Unit = { date -> clock.onPinnedResponse(date)?.let { anchor -> store.update { it.copy(clock = anchor) } } }
        val http = DeviceHttp(config, current = { core?.clientCredentials() }, onServerDate = onServerDate)
        val pinned = http.pinned
        val gateway = GatewayClient(pinned, config.enrollBaseUrl.toHttpUrl(), onServerDate, appBase = config.appBaseUrl.toHttpUrl())
        val versionCode = versionCodeEarly
        val queue = AlertQueue(dir, config.reportRateLimit)
        val alerts = Alerts(queue, store, keys, clock::now, { versionCode }, { AlertWorker.schedule(app) })
        alertsRef = alerts
        lateinit var certs: CertManager
        // a BLOCK finding in the precheck runs the BLOCK reaction (S2 §6.1 п. 1); enroll already holds the core lock
        val precheckReacting: suspend () -> PrecheckResult = {
            precheck.run().also { if (it is PrecheckResult.Compromised) certs.raspBlock(it.report.blocking) }
        }
        val enroller = Enroller(config, precheckReacting, keys, gateway, store, { vault.provision() }, { versionCode }, clock::now, onEnrolled = summary::reset)
        certs = CertManager(
            config, store, keys, clock, gateway, pinned,
            mtlsFor = { creds -> HttpClients.mtls(pinned, creds) },
            vault = object : VaultOps {
                override suspend fun provision() = vault.provision()
                override fun keys() = vault.keys()
                override suspend fun wipe() = vault.wipe()
                override suspend fun migrate() = vault.migrate()
            },
            enroller = enroller,
            versions = { Versions(versionCode, Build.VERSION.SECURITY_PATCH) },
            emit = { eventQueue.trySend(it) },
            integrity = scanner::scan,
            alerts = alerts,
            summary = summary,
        )
        val sender = AlertSender(queue, alerts, gateway, config.cookieProvider, clock::now)
        val c = DeviceTrustCore(config, store, clock, precheck, enroller, certs, eventSink, sender, appClient = { http.client }, gateway = gateway, rasp = scanner::scan)
        // secret chats (specs/002): the key directory is behind the app host, reached with the device certificate
        val e2ee = passportTrust?.let {
            val directory = KeyDirectoryClient({ http.client }, config.appBaseUrl.toHttpUrl(), config.cookieProvider)
            E2eeService(File(dir, "e2ee"), vault, store, keys, it, directory, alerts, clock::now, config.cookieProvider)
        }
        vaultImpl = vault
        deviceHttp = http
        e2eeImpl = e2ee
        core = c
        // pooled connections stay authenticated with the old certificate (S2 §10)
        scope.launch { c.credentialsVersion.collect { http.onCredentialsChanged() } }
        // a renewed certificate means a new passport: the record in the key directory follows it (FR-023)
        if (e2ee != null) scope.launch { c.credentialsVersion.drop(1).collect { e2ee.syncIfDue() } }
        Handler(Looper.getMainLooper()).post { ProcessLifecycleOwner.get().lifecycle.addObserver(ForegroundRasp(c, config, e2ee)) }
        scope.launch {
            // Each step on its own: an uncaught exception here would kill the process (no handler
            // on this scope), and a failed step must not cancel the ones after it.
            step("initialize") { c.initialize() }
            // reconciliation failed half-way (e.g. Keystore unavailable): still leave `Uninitialized`
            if (c.state.value is TrustState.Uninitialized) step("publish") { c.publish() }
            step("integrity") { c.checkIntegrity() }
            step("renew_worker") { RenewWorker.schedule(app, config.workInterval) }
            step("alert_worker") { if (!queue.isEmpty()) AlertWorker.schedule(app) }
            step("ensure_fresh") { c.ensureFresh() }
            step("e2ee_sync") { e2ee?.syncIfDue() }
            deadlineTimer(c)
        }
    }

    private suspend fun step(name: String, block: suspend () -> Unit) {
        try {
            block()
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            Journal.event("init_step_failed", "$name ${e.javaClass.simpleName}")
        }
    }

    /** RASP when the app comes to the foreground and then every `raspIntervalForeground` while it stays there (S2 §7.2). */
    private class ForegroundRasp(private val c: DeviceTrustCore, private val config: DeviceTrustConfig, private val e2ee: E2eeService<*>?) : DefaultLifecycleObserver {
        private var job: Job? = null

        override fun onStart(owner: LifecycleOwner) {
            job?.cancel()
            job = scope.launch {
                while (true) {
                    runCatching { c.checkIntegrity() }
                    runCatching { c.migrateVault() } // a no-op once done; the foreground is where the device is unlocked
                    // the key directory record: published here at the latest, the keys need the device unlocked
                    e2ee?.syncIfDue()
                    delay(config.raspIntervalForeground.inWholeMilliseconds)
                }
            }
        }

        override fun onStop(owner: LifecycleOwner) {
            job?.cancel()
            job = null
        }
    }

    /**
     * Re-evaluates at the next deadline (renewAfter / notAfter / end of grace). Sleeps at most
     * 15 minutes at a time so a deep sleep or a clock change is caught up quickly (S2 §5.2).
     */
    private suspend fun deadlineTimer(c: DeviceTrustCore) {
        while (true) {
            // deadlines are in library time (server-relative when known): compare with the same clock,
            // not with Instant.now() — a phone clock that runs behind would never reach the deadline
            val next = runCatching { c.nextDeadline() }.getOrNull()
            val wait = next?.let { Duration.between(c.now(), it).toMillis() } ?: Long.MAX_VALUE
            delay(wait.coerceIn(1_000, 15 * 60_000))
            step("deadline") { if (next != null && !c.now().isBefore(next)) c.ensureFresh() else c.publish() }
        }
    }

    private fun requireCore(): DeviceTrustCore = checkNotNull(core) { "DeviceTrust.init() was not called" }

    /**
     * Every suspend entry point is main-safe: Keystore, files and the connection pool (closing a
     * TLS socket writes to it) never run on the caller's thread — S1 calls from `Dispatchers.Main`.
     */
    private suspend fun <T> io(block: suspend DeviceTrustCore.() -> T): T = requireCore().let { c -> withContext(Dispatchers.IO) { c.block() } }

    /** `Uninitialized` until the start-up reconciliation finishes. */
    public val state: StateFlow<TrustState> get() = core?.state ?: uninitialized.asStateFlow()

    /** Grows on every key/certificate change and key deletion; cannot be missed (S1 §4.1). */
    public val credentialsVersion: StateFlow<Long> get() = core?.credentialsVersion ?: zero.asStateFlow()

    /**
     * `Blocked(reason)` (also on every start while blocked) and `VaultReset`. Buffered until
     * collected (up to 64, oldest dropped) and delivered **once**: collect it in exactly one
     * place, for the whole process (S1: `Application.onCreate`, right after `init`). An event
     * emitted before that collector starts is not lost.
     */
    public val events: Flow<TrustEvent> = eventQueue.receiveAsFlow()

    /** Server-relative time, or null until the first pinned response in this boot (S2 §5.2). */
    public fun trustNow(): Instant? = core?.trustNow()

    public suspend fun precheck(): PrecheckResult = io { precheck() }

    /** Enrollment with the admin-issued onboarding password (S2 §6.2). [onboardingPassword] is zeroed. */
    public suspend fun enroll(kratosCookie: String, onboardingPassword: CharArray): EnrollResult =
        io { enroll(kratosCookie, onboardingPassword) }

    /** Renews when due, recovers when expired (S2 §6.3–6.5); call on start, onResume and on `X-Device-Renew: 1`. */
    public suspend fun ensureFresh(): TrustState = io { ensureFresh() }

    /**
     * A gateway denial S1 saw (S2 §5.3). [source] = `PINNED_CLIENT` (a response to [okHttpClient])
     * is acted upon; `WEBVIEW` only triggers a pinned `ping` (≤ once per 30 s) whose answer decides
     * — a code from the WebView alone never deletes keys (R3). [reason] — `UPDATE_REQUIRED` only.
     */
    public suspend fun onGatewayDenied(code: GatewayCode, source: DenySource, reason: String? = null): TrustState =
        io { onGatewayDenied(code, source, reason) }

    /**
     * `GET /v1/device/whoami` over [okHttpClient] with the WebView's Kratos cookie: confirms a
     * `USER_MISMATCH` (S3 §5.8c). Only with a valid certificate (Active / RenewalDue); otherwise
     * `Failed(NO_CREDENTIALS)`. S1 never offers unenroll on `NoSession` / `Failed`.
     */
    public suspend fun checkSessionBinding(kratosCookie: String): SessionBinding = io { checkSessionBinding(kratosCookie) }

    /**
     * Unenroll (S2 §6.5a; not offered to users in S1 v1, D15). Always completes locally (R5): with
     * a device key a signed `UNENROLL` is queued first and delivered in the background.
     */
    public suspend fun unenroll(): UnenrollResult = io { unenroll() }

    /**
     * One RASP pass now (S2 §7). Runs by itself at init, on coming to the foreground and every
     * `raspIntervalForeground` there, and before enroll / renewal / recovery. A BLOCK finding runs
     * the BLOCK reaction (S2 §8); REPORT findings are sent rate-limited (S2 §7.4).
     */
    public suspend fun checkIntegrity(): RaspReport = io { checkIntegrity() }

    /** One pass of the alert sender (AlertWorker); returns the number of messages still waiting. */
    internal fun sendAlerts(): Int = core?.sendAlerts() ?: 0

    public fun clientCredentials(): ClientCredentials? = core?.clientCredentials()

    /**
     * mTLS + server-key pinning for everything except updates (S2 §10). Presents the active
     * certificate at handshake time; R7 is built in (a denial for a superseded certificate is
     * retried once with the current one). Successful responses feed `trustNow()`.
     */
    public fun okHttpClient(): OkHttpClient = checkNotNull(deviceHttp) { "DeviceTrust.init() was not called" }.client

    /** System CAs only — no pinning, no client certificate. ONLY for the signed update manifest and the APK (S1 §8). */
    public fun updateHttpClient(): OkHttpClient = checkNotNull(deviceHttp) { "DeviceTrust.init() was not called" }.update

    public val vault: Vault get() = checkNotNull(vaultImpl) { "DeviceTrust.init() was not called" }

    /**
     * Secret chats (specs/002): what the app's bridge hands to the web app. Needs `e2eeRoots` and
     * `e2eeIssuers` in the configuration.
     */
    public val e2ee: E2ee get() = checkNotNull(e2eeImpl) { "DeviceTrust.init() was not called, or e2eeRoots / e2eeIssuers are not configured" }

    /** Last precheck result details, or null before the first precheck. */
    public fun deviceInfo(): DeviceSecurityInfo? = core?.deviceInfo()
}
