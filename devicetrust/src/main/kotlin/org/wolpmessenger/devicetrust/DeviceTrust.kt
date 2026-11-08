package org.wolpmessenger.devicetrust

import android.content.Context
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import okhttp3.HttpUrl.Companion.toHttpUrl
import org.wolpmessenger.devicetrust.api.ClientCredentials
import org.wolpmessenger.devicetrust.api.DeviceSecurityInfo
import org.wolpmessenger.devicetrust.api.DeviceTrustConfig
import org.wolpmessenger.devicetrust.api.EnrollResult
import org.wolpmessenger.devicetrust.api.PrecheckResult
import org.wolpmessenger.devicetrust.api.TrustState
import org.wolpmessenger.devicetrust.api.Vault
import org.wolpmessenger.devicetrust.attest.Precheck
import org.wolpmessenger.devicetrust.clock.AndroidClockSource
import org.wolpmessenger.devicetrust.clock.TrustClock
import org.wolpmessenger.devicetrust.enroll.Enroller
import org.wolpmessenger.devicetrust.keys.KeystoreKeys
import org.wolpmessenger.devicetrust.net.GatewayClient
import org.wolpmessenger.devicetrust.net.HttpClients
import org.wolpmessenger.devicetrust.store.TrustStore
import org.wolpmessenger.devicetrust.vault.EnvelopeVault
import java.io.File
import java.time.Instant

/**
 * The only entry point for the application (S2 §4). Stage 3 surface: init, state,
 * credentialsVersion, trustNow, precheck, enroll, clientCredentials, vault, deviceInfo.
 * Renewal (`ensureFresh`), gateway denials, unenroll, RASP and the HTTP clients are added
 * with stages 4–6.
 */
public object DeviceTrust {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val uninitialized = MutableStateFlow<TrustState>(TrustState.Uninitialized)
    private val zero = MutableStateFlow(0L)

    @Volatile
    private var core: DeviceTrustCore? = null
    private var vaultImpl: EnvelopeVault? = null

    /** Fast and non-blocking; safe in `Application.onCreate`. A second call is ignored. */
    @Synchronized
    public fun init(context: Context, config: DeviceTrustConfig) {
        if (core != null) return
        config.validateForNetwork()
        val app = context.applicationContext
        val dir = File(app.noBackupFilesDir, "dt")
        val store = TrustStore(dir)
        val keys = KeystoreKeys.android()
        val clock = TrustClock(AndroidClockSource(app), store.load().clock)
        val vault = EnvelopeVault.android(app)
        val precheck = Precheck.android(app, config)
        val gateway = GatewayClient(HttpClients.pinned(config), config.enrollBaseUrl.toHttpUrl()) { date ->
            clock.onPinnedResponse(date)?.let { anchor -> store.update { it.copy(clock = anchor) } }
        }
        val versionCode = app.packageManager.getPackageInfo(app.packageName, 0).longVersionCode
        val enroller = Enroller(config, precheck::run, keys, gateway, store, { vault.provision() }, { versionCode }, clock::now)
        val c = DeviceTrustCore(config, store, keys, clock, precheck, enroller)
        vaultImpl = vault
        core = c
        scope.launch { c.initialize() }
    }

    private fun requireCore(): DeviceTrustCore = checkNotNull(core) { "DeviceTrust.init() was not called" }

    /** `Uninitialized` until the initial evaluation finishes. */
    public val state: StateFlow<TrustState> get() = core?.state ?: uninitialized.asStateFlow()

    /** Grows on every key/certificate change and key deletion; cannot be missed (S1 §4.1). */
    public val credentialsVersion: StateFlow<Long> get() = core?.credentialsVersion ?: zero.asStateFlow()

    /** Server-relative time, or null until the first pinned response in this boot (S2 §5.2). */
    public fun trustNow(): Instant? = core?.trustNow()

    public suspend fun precheck(): PrecheckResult = requireCore().precheck()

    /** Enrollment with the admin-issued onboarding password (S2 §6.2). [onboardingPassword] is zeroed. */
    public suspend fun enroll(kratosCookie: String, onboardingPassword: CharArray): EnrollResult =
        requireCore().enroll(kratosCookie, onboardingPassword)

    public fun clientCredentials(): ClientCredentials? = core?.clientCredentials()

    public val vault: Vault get() = checkNotNull(vaultImpl) { "DeviceTrust.init() was not called" }

    /** Last precheck result details, or null before the first precheck. */
    public fun deviceInfo(): DeviceSecurityInfo? = core?.deviceInfo()
}
