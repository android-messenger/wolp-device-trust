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
import org.wolpmessenger.devicetrust.api.ClientCredentials
import org.wolpmessenger.devicetrust.api.DeviceSecurityInfo
import org.wolpmessenger.devicetrust.api.DeviceTrustConfig
import org.wolpmessenger.devicetrust.api.EnrollResult
import org.wolpmessenger.devicetrust.api.PrecheckResult
import org.wolpmessenger.devicetrust.api.TrustEvent
import org.wolpmessenger.devicetrust.api.TrustState
import org.wolpmessenger.devicetrust.api.UnenrollResult
import org.wolpmessenger.devicetrust.attest.Precheck
import org.wolpmessenger.devicetrust.cert.CertManager
import org.wolpmessenger.devicetrust.cert.deriveState
import org.wolpmessenger.devicetrust.clock.TrustClock
import org.wolpmessenger.devicetrust.enroll.Enroller
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
) {
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

    /** S2 §6.5a: completes locally in every state (R5). */
    suspend fun unenroll(): UnenrollResult = lock.withLock {
        certs.unenroll().also { publish() }
    }

    /** One pass of the alert sender; returns the number of messages still waiting. */
    fun sendAlerts(): Int = sender?.sendAll() ?: 0

    fun trustNow(): Instant? = clock.trustNow()

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

    /** Re-reads the store and recomputes the state by the clock. */
    fun publish() {
        val s = store.load()
        _credentialsVersion.value = s.credentialsVersion
        _state.value = deriveState(s, clock.now(), config.reattestGrace)
    }
}
