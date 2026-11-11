package org.wolpmessenger.devicetrust

import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.wolpmessenger.devicetrust.alert.AlertSender
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import org.wolpmessenger.devicetrust.api.BindingFailure
import org.wolpmessenger.devicetrust.api.ClientCredentials
import org.wolpmessenger.devicetrust.api.DenySource
import org.wolpmessenger.devicetrust.api.GatewayCode
import org.wolpmessenger.devicetrust.api.SessionBinding
import org.wolpmessenger.devicetrust.api.DeviceSecurityInfo
import org.wolpmessenger.devicetrust.api.DeviceTrustConfig
import org.wolpmessenger.devicetrust.api.EnrollResult
import org.wolpmessenger.devicetrust.api.PrecheckResult
import org.wolpmessenger.devicetrust.api.RaspReport
import org.wolpmessenger.devicetrust.api.TrustEvent
import org.wolpmessenger.devicetrust.api.TrustState
import org.wolpmessenger.devicetrust.api.UnenrollResult
import org.wolpmessenger.devicetrust.attest.Precheck
import org.wolpmessenger.devicetrust.cert.CertManager
import org.wolpmessenger.devicetrust.cert.deriveState
import org.wolpmessenger.devicetrust.clock.TrustClock
import org.wolpmessenger.devicetrust.enroll.Enroller
import org.wolpmessenger.devicetrust.net.GatewayClient
import org.wolpmessenger.devicetrust.net.GatewayResult
import org.wolpmessenger.devicetrust.store.Phase
import org.wolpmessenger.devicetrust.store.TrustStore
import java.time.Instant

/**
 * Everything behind the `DeviceTrust` facade, with injected collaborators so it is tested on
 * the JVM. Every state-changing operation (reconcile, enroll, ensureFresh) runs under one
 * coordinator lock; concurrent `ensureFresh` calls therefore collapse — the second one finds
 * the certificate already fresh.
 */
internal class DeviceTrustCore(
    private val config: DeviceTrustConfig,
    private val store: TrustStore,
    private val clock: TrustClock,
    private val precheck: Precheck,
    private val enroller: Enroller,
    private val certs: CertManager,
    private val events: MutableSharedFlow<TrustEvent>,
    private val sender: AlertSender? = null,
    /** `DeviceTrust.okHttpClient()`: mTLS with the current certificate, pinning, R7. */
    private val appClient: () -> OkHttpClient = { OkHttpClient() },
    private val gateway: GatewayClient? = null,
    /** Monotonic milliseconds, for the WEBVIEW check rate limit. */
    private val monotonicMs: () -> Long = { System.nanoTime() / 1_000_000 },
    /** RASP pass with the policy applied; REPORT findings are queued by it (S2 §7.4). */
    private val rasp: suspend () -> RaspReport = { RaspReport.CLEAN },
) {
    private val checkLock = Mutex()
    private var lastCheckMs: Long? = null

    private val lock = Mutex()
    private val _state = MutableStateFlow<TrustState>(TrustState.Uninitialized)
    private val _credentialsVersion = MutableStateFlow(0L)
    val state: StateFlow<TrustState> = _state.asStateFlow()
    val credentialsVersion: StateFlow<Long> = _credentialsVersion.asStateFlow()
    val eventFlow: SharedFlow<TrustEvent> = events.asSharedFlow()

    @Volatile
    private var lastInfo: DeviceSecurityInfo? = null

    /** Start-up: reconciliation (S2 §6.6) and the first evaluation; leaves `Uninitialized`. */
    suspend fun initialize() = lock.withLock {
        certs.reconcile()
        publish()
    }

    suspend fun ensureFresh(): TrustState = lock.withLock {
        certs.ensureFresh().also { publish() }
    }

    suspend fun enroll(cookie: String, password: CharArray): EnrollResult = lock.withLock {
        enroller.enroll(cookie, password).also { publish() }
    }

    /** Precheck (S2 §6.1); a BLOCK finding runs the BLOCK reaction (S2 §8) before returning. */
    suspend fun precheck(): PrecheckResult = precheck.run().also {
        when (it) {
            is PrecheckResult.Supported -> lastInfo = it.info
            is PrecheckResult.Unsupported -> lastInfo = it.info
            is PrecheckResult.Compromised -> lock.withLock {
                certs.raspBlock(it.report.blocking)
                publish()
            }
        }
    }

    /**
     * RASP pass (S2 §7.2: init, foreground, timer; S1 may call it too). A BLOCK finding runs the
     * BLOCK reaction (S2 §8) once — a device already blocked is not wiped again on every pass.
     */
    suspend fun checkIntegrity(): RaspReport {
        val r = rasp()
        if (r.blocking.isNotEmpty() && !certs.isBlocked()) {
            lock.withLock {
                // two passes may overlap (start-up and coming to the foreground): the second one
                // finds the device already blocked and must not wipe and emit again
                if (!certs.isBlocked()) {
                    certs.raspBlock(r.blocking)
                    publish()
                }
            }
        }
        return r
    }

    /** Story 2 migration of an older vault; needs the device unlocked, so it is retried whenever the app comes to the foreground. */
    suspend fun migrateVault() = lock.withLock { certs.migrateVault() }

    /** S2 §6.5a: completes locally in every state (R5). */
    suspend fun unenroll(): UnenrollResult = lock.withLock {
        certs.unenroll().also { publish() }
    }

    // ---------------------------------------------------------------- gateway denials (S2 §5.3, R3)

    /**
     * PINNED: acted upon (R7 is already applied by the pinned client). WEBVIEW: never destructive
     * by itself — at most once per 30 s a `GET /v1/device/ping` over the pinned channel decides,
     * and the action follows the code of **that** answer. A ping that fails (network, pinning
     * failure = possibly a fake server) changes nothing.
     */
    suspend fun onGatewayDenied(code: GatewayCode, source: DenySource, reason: String? = null): TrustState {
        if (source == DenySource.PINNED_CLIENT) {
            lock.withLock {
                certs.onPinnedDenial(code, reason)
                publish()
            }
            return state.value
        }
        when (code) {
            GatewayCode.NO_SESSION, GatewayCode.USER_MISMATCH, GatewayCode.RATE_LIMITED, GatewayCode.UNKNOWN -> return state.value
            GatewayCode.UPDATE_REQUIRED -> Journal.event("webview_update_required", "check never sends it") // suspicious; ping decides
            else -> Unit
        }
        checkLock.withLock {
            val now = monotonicMs()
            lastCheckMs?.let { if (now - it < WEBVIEW_CHECK_INTERVAL_MS) return state.value }
            lastCheckMs = now
            verifyByPing(code)
        }
        return state.value
    }

    private suspend fun verifyByPing(webviewCode: GatewayCode) {
        val gw = gateway ?: return
        if (clientCredentials() == null) {
            // no valid certificate to ping with: bring it up to date instead (renew / recover)
            ensureFresh()
            return
        }
        when (val r = withContext(Dispatchers.IO) { gw.ping(appClient()) }) {
            is GatewayResult.Ok -> {
                if (certs.isDestructive(webviewCode) || webviewCode == GatewayCode.UPDATE_REQUIRED) {
                    Journal.event("deny_unconfirmed", webviewCode.name)
                }
                if (r.value) ensureFresh()
            }
            is GatewayResult.Refused -> lock.withLock {
                Journal.event("deny_confirmed", "${webviewCode.name} -> ${r.error.code.name}")
                certs.onPinnedDenial(r.error.code, r.error.reason)
                publish()
            }
            is GatewayResult.Failed -> Journal.event("deny_check_failed", webviewCode.name)
        }
    }

    /** `GET /v1/device/whoami` with mTLS + the WebView's Kratos cookie (S2 §4, S3 §5.8c). */
    suspend fun checkSessionBinding(cookie: String): SessionBinding {
        val gw = gateway ?: return SessionBinding.Failed(BindingFailure.NO_CREDENTIALS)
        if (clientCredentials() == null) return SessionBinding.Failed(BindingFailure.NO_CREDENTIALS)
        return when (val r = withContext(Dispatchers.IO) { gw.whoami(appClient(), cookie) }) {
            is GatewayResult.Ok -> when (r.value.session) {
                "match" -> SessionBinding.Match
                "mismatch" -> SessionBinding.Mismatch.also { Journal.event("user_mismatch_confirmed") }
                else -> SessionBinding.NoSession
            }
            is GatewayResult.Refused -> {
                lock.withLock {
                    certs.onPinnedDenial(r.error.code, r.error.reason)
                    publish()
                }
                SessionBinding.Failed(BindingFailure.DENIED, r.error.code)
            }
            is GatewayResult.Failed -> SessionBinding.Failed(BindingFailure.NETWORK)
        }
    }

    /** One pass of the alert sender; returns the number of messages still waiting. */
    fun sendAlerts(): Int = sender?.sendAll() ?: 0

    fun trustNow(): Instant? = clock.trustNow()

    /** Library time: what every deadline of this class is measured against. */
    fun now(): Instant = clock.now()

    fun deviceInfo(): DeviceSecurityInfo? = lastInfo

    /** Current client certificate, only while it is valid (Active / RenewalDue). */
    fun clientCredentials(): ClientCredentials? {
        val s = store.load()
        val active = s.active ?: return null
        val st = deriveState(s, clock.now(), config.reattestGrace)
        if (st !is TrustState.Active && st !is TrustState.RenewalDue) return null
        return certs.credentials(active)
    }

    /** Next moment the state changes by itself (renewAfter / notAfter / end of grace), or null. */
    fun nextDeadline(): Instant? {
        val s = store.load()
        val a = s.active?.takeIf { s.phase == Phase.ENROLLED } ?: return null
        val now = clock.now()
        return listOf(a.renewAfter, a.notAfter, a.notAfter.plusSeconds(config.reattestGrace.inWholeSeconds)).firstOrNull { it > now }
    }

    private companion object {
        const val WEBVIEW_CHECK_INTERVAL_MS = 30_000L
    }

    /** Re-reads the store and recomputes the state by the clock. */
    fun publish() {
        val s = store.load()
        _credentialsVersion.value = s.credentialsVersion
        _state.value = deriveState(s, clock.now(), config.reattestGrace)
    }
}
