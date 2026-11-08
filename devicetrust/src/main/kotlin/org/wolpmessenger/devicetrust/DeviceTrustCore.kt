package org.wolpmessenger.devicetrust

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.wolpmessenger.devicetrust.api.BlockReason
import org.wolpmessenger.devicetrust.api.ClientCredentials
import org.wolpmessenger.devicetrust.api.DeviceSecurityInfo
import org.wolpmessenger.devicetrust.api.DeviceTrustConfig
import org.wolpmessenger.devicetrust.api.EnrollResult
import org.wolpmessenger.devicetrust.api.PrecheckResult
import org.wolpmessenger.devicetrust.api.TrustState
import org.wolpmessenger.devicetrust.api.UpdateKind
import org.wolpmessenger.devicetrust.attest.Precheck
import org.wolpmessenger.devicetrust.clock.TrustClock
import org.wolpmessenger.devicetrust.enroll.Enroller
import org.wolpmessenger.devicetrust.keys.KeystoreKeys
import org.wolpmessenger.devicetrust.store.Phase
import org.wolpmessenger.devicetrust.store.StoredState
import org.wolpmessenger.devicetrust.store.TrustStore
import java.time.Instant
import kotlin.time.toJavaDuration

/**
 * Everything behind the `DeviceTrust` facade, with injected collaborators so it is tested
 * on the JVM. Stage 3 scope: state, precheck, enrollment, credentials. Renewal, recovery and
 * the full init reconciliation (S2 §6.3–6.6) arrive in stage 4.
 */
internal class DeviceTrustCore(
    private val config: DeviceTrustConfig,
    private val store: TrustStore,
    private val keys: KeystoreKeys,
    private val clock: TrustClock,
    private val precheck: Precheck,
    private val enroller: Enroller,
) {
    private val _state = MutableStateFlow<TrustState>(TrustState.Uninitialized)
    private val _credentialsVersion = MutableStateFlow(0L)
    val state: StateFlow<TrustState> = _state.asStateFlow()
    val credentialsVersion: StateFlow<Long> = _credentialsVersion.asStateFlow()

    @Volatile
    private var lastInfo: DeviceSecurityInfo? = null

    /** Initial evaluation (a subset of S2 §6.6: orphan cleanup п. 3 and recomputation п. 5a). */
    fun initialize() {
        val s = store.load()
        keys.deleteOrphans(keep = setOfNotNull(s.active?.alias, s.enrolling?.alias))
        publish(s)
    }

    suspend fun precheck(): PrecheckResult = precheck.run().also {
        when (it) {
            is PrecheckResult.Supported -> lastInfo = it.info
            is PrecheckResult.Unsupported -> lastInfo = it.info
            is PrecheckResult.Compromised -> Unit
        }
    }

    suspend fun enroll(cookie: String, password: CharArray): EnrollResult =
        enroller.enroll(cookie, password).also { publish(store.load()) }

    fun trustNow(): Instant? = clock.trustNow()

    fun deviceInfo(): DeviceSecurityInfo? = lastInfo

    /** Current client certificate, only while it is valid (Active / RenewalDue). */
    fun clientCredentials(): ClientCredentials? {
        val s = store.load()
        val active = s.active ?: return null
        if (derive(s, clock.now()) !is TrustState.Active && derive(s, clock.now()) !is TrustState.RenewalDue) return null
        val n = KeystoreKeys.deviceKeyNumber(active.alias) ?: return null
        val chain = store.readChain(n) ?: return null
        val key = keys.privateKey(active.alias) ?: return null
        return ClientCredentials(key, chain.toTypedArray())
    }

    /** Re-reads the store and recomputes the state by the clock. */
    fun refresh() = publish(store.load())

    private fun publish(s: StoredState) {
        _credentialsVersion.value = s.credentialsVersion
        _state.value = derive(s, clock.now())
    }

    /** StoredState + now → TrustState (S2 §5.1). */
    internal fun derive(s: StoredState, now: Instant): TrustState = when (s.phase) {
        Phase.NOT_ENROLLED, Phase.UNENROLLING -> TrustState.NotEnrolled
        Phase.RE_ENROLL_REQUIRED -> TrustState.ReEnrollRequired
        Phase.BLOCKED -> TrustState.Blocked(s.blockReason?.let { runCatching { BlockReason.valueOf(it) }.getOrNull() } ?: BlockReason.POLICY)
        Phase.UPDATE_REQUIRED -> TrustState.UpdateRequired(
            s.updateRequired?.kind?.let { runCatching { UpdateKind.valueOf(it) }.getOrNull() } ?: UpdateKind.APP,
            s.updateRequired?.reason ?: "",
        )
        Phase.ENROLLED -> {
            val a = s.active
            when {
                a == null -> TrustState.NotEnrolled
                now < a.renewAfter -> TrustState.Active(a.notAfter, a.renewAfter)
                now < a.notAfter -> TrustState.RenewalDue(a.notAfter)
                now < a.notAfter + config.reattestGrace.toJavaDuration() -> TrustState.ExpiredGrace(a.notAfter + config.reattestGrace.toJavaDuration())
                else -> TrustState.ReEnrollRequired
            }
        }
    }
}
