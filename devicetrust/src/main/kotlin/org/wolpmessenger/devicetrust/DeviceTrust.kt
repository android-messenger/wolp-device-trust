package org.wolpmessenger.devicetrust

import android.content.Context
import android.os.Build
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import okhttp3.HttpUrl.Companion.toHttpUrl
import org.wolpmessenger.devicetrust.api.ClientCredentials
import org.wolpmessenger.devicetrust.api.DeviceSecurityInfo
import org.wolpmessenger.devicetrust.api.DeviceTrustConfig
import org.wolpmessenger.devicetrust.api.EnrollResult
import org.wolpmessenger.devicetrust.api.PrecheckResult
import org.wolpmessenger.devicetrust.api.TrustEvent
import org.wolpmessenger.devicetrust.api.TrustState
import org.wolpmessenger.devicetrust.api.Vault
import org.wolpmessenger.devicetrust.attest.Precheck
import org.wolpmessenger.devicetrust.cert.CertManager
import org.wolpmessenger.devicetrust.cert.RenewWorker
import org.wolpmessenger.devicetrust.cert.VaultOps
import org.wolpmessenger.devicetrust.cert.Versions
import org.wolpmessenger.devicetrust.clock.AndroidClockSource
import org.wolpmessenger.devicetrust.clock.TrustClock
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
 * (renewal / recovery), clientCredentials, okHttpClient, updateHttpClient, vault, deviceInfo.
 * Gateway denials from S1 (`onGatewayDenied`), whoami, unenroll and RASP arrive in stage 6.
 */
public object DeviceTrust {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val uninitialized = MutableStateFlow<TrustState>(TrustState.Uninitialized)
    private val zero = MutableStateFlow(0L)
    private val eventSink = MutableSharedFlow<TrustEvent>(extraBufferCapacity = 16)

    @Volatile
    private var core: DeviceTrustCore? = null
    private var vaultImpl: EnvelopeVault? = null
    private var deviceHttp: DeviceHttp? = null

    internal val isInitialized: Boolean get() = core != null

    /** Fast and non-blocking; safe in `Application.onCreate` (the process also starts for FCM). A second call is ignored. */
    @Synchronized
    public fun init(context: Context, config: DeviceTrustConfig) {
        if (core != null) return
        config.validateForNetwork()
        val app = context.applicationContext
        val store = TrustStore(File(app.noBackupFilesDir, "dt"))
        val keys = KeystoreKeys.android()
        val clock = TrustClock(AndroidClockSource(app), store.load().clock)
        val vault = EnvelopeVault.android(app)
        val precheck = Precheck.android(app, config)
        val onServerDate: (String?) -> Unit = { date -> clock.onPinnedResponse(date)?.let { anchor -> store.update { it.copy(clock = anchor) } } }
        val http = DeviceHttp(config, current = { core?.clientCredentials() }, onServerDate = onServerDate)
        val pinned = http.pinned
        val gateway = GatewayClient(pinned, config.enrollBaseUrl.toHttpUrl(), onServerDate, appBase = config.appBaseUrl.toHttpUrl())
        val versionCode = app.packageManager.getPackageInfo(app.packageName, 0).longVersionCode
        val enroller = Enroller(config, precheck::run, keys, gateway, store, { vault.provision() }, { versionCode }, clock::now)
        val certs = CertManager(
            config, store, keys, clock, gateway, pinned,
            mtlsFor = { creds -> HttpClients.mtls(pinned, creds) },
            vault = object : VaultOps {
                override suspend fun provision() = vault.provision()
                override fun keys() = vault.keys()
                override suspend fun wipe() = vault.wipe()
            },
            enroller = enroller,
            versions = { Versions(versionCode, Build.VERSION.SECURITY_PATCH) },
            emit = { eventSink.tryEmit(it) },
        )
        val c = DeviceTrustCore(config, store, clock, precheck, enroller, certs, eventSink)
        vaultImpl = vault
        deviceHttp = http
        core = c
        // pooled connections stay authenticated with the old certificate (S2 §10)
        scope.launch { c.credentialsVersion.collect { http.onCredentialsChanged() } }
        scope.launch {
            c.initialize()
            RenewWorker.schedule(app, config.workInterval)
            c.ensureFresh()
            deadlineTimer(c)
        }
    }

    /**
     * Re-evaluates at the next deadline (renewAfter / notAfter / end of grace). Sleeps at most
     * 15 minutes at a time so a deep sleep or a clock change is caught up quickly (S2 §5.2).
     */
    private suspend fun deadlineTimer(c: DeviceTrustCore) {
        while (true) {
            val next = c.nextDeadline()
            val wait = next?.let { Duration.between(Instant.now(), it).toMillis() } ?: Long.MAX_VALUE
            delay(wait.coerceIn(1_000, 15 * 60_000))
            if (next != null && !Instant.now().isBefore(next)) c.ensureFresh() else c.publish()
        }
    }

    private fun requireCore(): DeviceTrustCore = checkNotNull(core) { "DeviceTrust.init() was not called" }

    /** `Uninitialized` until the start-up reconciliation finishes. */
    public val state: StateFlow<TrustState> get() = core?.state ?: uninitialized.asStateFlow()

    /** Grows on every key/certificate change and key deletion; cannot be missed (S1 §4.1). */
    public val credentialsVersion: StateFlow<Long> get() = core?.credentialsVersion ?: zero.asStateFlow()

    /** `Blocked(reason)` (also on every start while blocked) and `VaultReset`. */
    public val events: SharedFlow<TrustEvent> get() = eventSink.asSharedFlow()

    /** Server-relative time, or null until the first pinned response in this boot (S2 §5.2). */
    public fun trustNow(): Instant? = core?.trustNow()

    public suspend fun precheck(): PrecheckResult = requireCore().precheck()

    /** Enrollment with the admin-issued onboarding password (S2 §6.2). [onboardingPassword] is zeroed. */
    public suspend fun enroll(kratosCookie: String, onboardingPassword: CharArray): EnrollResult =
        requireCore().enroll(kratosCookie, onboardingPassword)

    /** Renews when due, recovers when expired (S2 §6.3–6.5); call on start, onResume and on `X-Device-Renew: 1`. */
    public suspend fun ensureFresh(): TrustState = requireCore().ensureFresh()

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

    /** Last precheck result details, or null before the first precheck. */
    public fun deviceInfo(): DeviceSecurityInfo? = core?.deviceInfo()
}
