package org.wolpmessenger.devicetrust.cert

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import org.wolpmessenger.devicetrust.Journal
import org.wolpmessenger.devicetrust.alert.AlertKind
import org.wolpmessenger.devicetrust.alert.AlertSink
import org.wolpmessenger.devicetrust.api.BlockReason
import org.wolpmessenger.devicetrust.api.ClientCredentials
import org.wolpmessenger.devicetrust.api.DeviceTrustConfig
import org.wolpmessenger.devicetrust.api.GatewayCode
import org.wolpmessenger.devicetrust.api.RaspFinding
import org.wolpmessenger.devicetrust.api.RaspReport
import org.wolpmessenger.devicetrust.api.ServerNotice
import org.wolpmessenger.devicetrust.api.TrustEvent
import org.wolpmessenger.devicetrust.api.TrustState
import org.wolpmessenger.devicetrust.api.UnenrollResult
import org.wolpmessenger.devicetrust.api.UpdateKind
import org.wolpmessenger.devicetrust.asn1.Csr
import org.wolpmessenger.devicetrust.clock.TrustClock
import org.wolpmessenger.devicetrust.enroll.Enroller
import org.wolpmessenger.devicetrust.keys.KeyGenResult
import org.wolpmessenger.devicetrust.keys.KeystoreKeys
import org.wolpmessenger.devicetrust.net.Challenge
import org.wolpmessenger.devicetrust.net.GatewayClient
import org.wolpmessenger.devicetrust.net.GatewayError
import org.wolpmessenger.devicetrust.net.GatewayResult
import org.wolpmessenger.devicetrust.net.IssuedCert
import org.wolpmessenger.devicetrust.rasp.RaspSummary
import org.wolpmessenger.devicetrust.rasp.RaspSummarySource
import org.wolpmessenger.devicetrust.rasp.RaspSummaryStore
import org.wolpmessenger.devicetrust.store.ActiveCert
import org.wolpmessenger.devicetrust.store.Phase
import org.wolpmessenger.devicetrust.store.StoredState
import org.wolpmessenger.devicetrust.store.TrustStore
import org.wolpmessenger.devicetrust.store.UpdateRequiredInfo
import org.wolpmessenger.devicetrust.vault.VaultKeys
import java.math.BigInteger
import java.security.Signature
import java.time.Instant
import kotlin.time.Duration
import kotlin.time.toJavaDuration

/** The vault operations the certificate lifecycle needs (EnvelopeVault in production). */
internal interface VaultOps {
    suspend fun provision(): Boolean
    fun keys(): VaultKeys
    suspend fun wipe()

    /** Moves a single-key vault to the two-key layout when possible; true if it did (EnvelopeVault.migrate). */
    suspend fun migrate(): Boolean = false
}

/** Versions recorded with `UpdateRequired` (S2 §6.6 п. 5). */
internal data class Versions(val versionCode: Long, val securityPatch: String)

/** StoredState + now → TrustState (S2 §5.1). */
internal fun deriveState(s: StoredState, now: Instant, reattestGrace: Duration): TrustState = when (s.phase) {
    Phase.NOT_ENROLLED, Phase.UNENROLLING -> TrustState.NotEnrolled
    Phase.RE_ENROLL_REQUIRED -> TrustState.ReEnrollRequired
    Phase.BLOCKED -> TrustState.Blocked(s.blockReason?.let { runCatching { BlockReason.valueOf(it) }.getOrNull() } ?: BlockReason.POLICY)
    Phase.UPDATE_REQUIRED -> TrustState.UpdateRequired(
        s.updateRequired?.kind?.let { runCatching { UpdateKind.valueOf(it) }.getOrNull() } ?: UpdateKind.APP,
        s.updateRequired?.reason ?: "",
    )
    Phase.ENROLLED -> {
        val a = s.active
        val graceUntil = a?.notAfter?.plus(reattestGrace.toJavaDuration())
        when {
            a == null -> TrustState.NotEnrolled
            now < a.renewAfter -> TrustState.Active(a.notAfter, a.renewAfter)
            now < a.notAfter -> TrustState.RenewalDue(a.notAfter)
            now < graceUntil -> TrustState.ExpiredGrace(graceUntil!!)
            else -> TrustState.ReEnrollRequired
        }
    }
}

/**
 * Certificate lifecycle (S2 §6.3–6.6): renewal over mTLS with the current key, recovery after
 * expiry or a lost renewal response, gateway denials on the pinned channel (S2 §5.3), BLOCK
 * (S2 §8, with the signed message for RASP), unenroll (S2 §6.5a) and the start-up
 * reconciliation. Callers serialise access (one coordinator lock in DeviceTrustCore).
 * R7 (the serial actually used by a request) is enforced by the HTTP client (DeviceHttp).
 */
internal class CertManager(
    private val config: DeviceTrustConfig,
    private val store: TrustStore,
    private val keys: KeystoreKeys,
    private val clock: TrustClock,
    private val gateway: GatewayClient,
    private val pinned: OkHttpClient,
    private val mtlsFor: (ClientCredentials) -> OkHttpClient,
    private val vault: VaultOps,
    private val enroller: Enroller,
    private val versions: () -> Versions,
    private val emit: (TrustEvent) -> Unit,
    private val integrity: suspend () -> RaspReport = { RaspReport.CLEAN },
    private val alerts: AlertSink = AlertSink.None,
    private val summary: RaspSummarySource = RaspSummarySource.None,
) {
    fun isBlocked(): Boolean = store.load().phase == Phase.BLOCKED

    fun state(): TrustState = deriveState(store.load(), clock.now(), config.reattestGrace)

    /** Brings the certificate up to date: renew when due, recover when expired (S2 §6.5). */
    suspend fun ensureFresh(): TrustState {
        clearUpdateRequiredIfUpdated()
        val s = store.load()
        when (deriveState(s, clock.now(), config.reattestGrace)) {
            is TrustState.RenewalDue -> renew(s, nonceRetryLeft = true)
            is TrustState.ExpiredGrace -> recover(s)
            else -> Unit
        }
        return state()
    }

    // ---------------------------------------------------------------- renewal (S2 §6.3)

    private suspend fun renew(s: StoredState, nonceRetryLeft: Boolean) {
        val active = s.active ?: return
        integrity().blocking.takeIf { it.isNotEmpty() }?.let { return raspBlock(it) }
        val oldCreds = credentials(active) ?: return markReEnrollRequired()
        val oldClient = mtlsFor(oldCreds)

        val challenge = when (val r = io { gateway.renewChallenge(oldClient) }) {
            is GatewayResult.Ok -> r.value
            is GatewayResult.Refused -> return onDenied(r.error, s)
            is GatewayResult.Failed -> return
        }
        when (val r = rotate(s, ContinuitySig.RENEW, challenge) { csr, chain, sig, sum -> gateway.renew(oldClient, csr, chain, sig, sum) }) {
            is Rotation.Issued -> {
                switchToPending()
                // S2 §6.3 п. 7: confirm with the NEW key; an optimisation — the old cert expires from the gateway anyway.
                credentials(r.cert)?.let { io { gateway.renewConfirm(mtlsFor(it)) } }
                dropKey(active)
            }
            is Rotation.Refused ->
                if (r.error.code == GatewayCode.NONCE_INVALID && nonceRetryLeft) renew(store.load(), nonceRetryLeft = false)
                else onDenied(r.error, s)
            Rotation.Failed -> Unit
        }
    }

    // ---------------------------------------------------------------- recovery (S2 §6.4)

    /** Expired certificate within grace, or a lost renewal response (`CERT_SUPERSEDED`). */
    private suspend fun recover(s: StoredState) {
        val active = s.active ?: return
        integrity().blocking.takeIf { it.isNotEmpty() }?.let { return raspBlock(it) }
        if (keys.privateKey(active.alias) == null) return markReEnrollRequired()

        val challenge = when (val r = io { gateway.reattestChallenge(active.serialHex) }) {
            is GatewayResult.Ok -> r.value
            is GatewayResult.Refused -> return onDenied(r.error, s)
            is GatewayResult.Failed -> return
        }
        when (val r = rotate(s, ContinuitySig.REATTEST, challenge) { csr, chain, sig, sum -> gateway.reattestFinish(active.serialHex, csr, chain, sig, sum) }) {
            is Rotation.Issued -> {
                switchToPending()
                dropKey(active) // the gateway retires the old certificate at once (S3 §5.6): no confirm
            }
            is Rotation.Refused -> onDenied(r.error, s)
            Rotation.Failed -> Unit
        }
    }

    private sealed interface Rotation {
        data class Issued(val cert: ActiveCert) : Rotation
        data class Refused(val error: GatewayError) : Rotation
        data object Failed : Rotation
    }

    /**
     * New key bound to the nonce, CSR, continuitySig by the current key, send; on success the
     * new certificate is recorded as `pending` (S2 §6.3 п. 5). On a non-destructive error the
     * new key is deleted.
     *
     * The RASP summary and continuitySig v2 go only to a gateway whose challenge announced
     * `raspSummary` (FR-035): an older gateway verifies v1 only and would revoke the device.
     */
    private suspend fun rotate(
        s: StoredState,
        prefix: String,
        challenge: Challenge,
        send: (csr: ByteArray, chain: List<ByteArray>, sig: ByteArray, raspSummary: ByteArray?) -> GatewayResult<IssuedCert>,
    ): Rotation {
        val active = s.active!!
        val deviceId = s.deviceId ?: return Rotation.Failed
        val newAlias = keys.nextDeviceAlias()
        val key = when (val g = io { keys.generate(newAlias, challenge.nonce, config.deviceKeyStrongBox) }) {
            is KeyGenResult.Ok -> g.key
            is KeyGenResult.SoftwareKeystore -> return Rotation.Failed
        }
        val chainDer = key.chain.map { it.encoded }
        // best effort: a summary that cannot be read must not stop the renewal — it goes as v1, without one
        val sum: RaspSummary? = if (RaspSummaryStore.FEATURE in challenge.features) runCatching { summary.snapshot() }.getOrNull() else null
        val (csr, sig) = try {
            io {
                val pub = keys.publicKey(newAlias)!!
                val csr = Csr.build(pub, keys.privateKey(newAlias)!!)
                val serial = BigInteger(active.serialHex, 16)
                val payload =
                    if (sum == null) ContinuitySig.payload(prefix, deviceId, serial, challenge.nonce, pub.encoded, chainDer)
                    else ContinuitySig.payloadV2(ContinuitySig.v2(prefix), deviceId, serial, challenge.nonce, pub.encoded, chainDer, sum.bytes)
                val sig = Signature.getInstance("SHA256withECDSA").run { initSign(keys.privateKey(active.alias)!!); update(payload); sign() }
                csr to sig
            }
        } catch (e: Exception) {
            keys.delete(newAlias)
            return Rotation.Failed
        }

        return when (val r = io { send(csr, chainDer, sig, sum?.bytes) }) {
            is GatewayResult.Ok -> {
                val issued = r.value
                val cert = ActiveCert(newAlias, issued.certChain.first().serialNumber.toString(16), issued.notBefore, issued.notAfter, issued.renewAfter)
                store.writeChain(KeystoreKeys.deviceKeyNumber(newAlias)!!, issued.certChain)
                store.update { it.copy(pending = cert) }
                sum?.let { runCatching { summary.sent(it) } }
                Rotation.Issued(cert)
            }
            is GatewayResult.Refused -> {
                if (!isDestructive(r.error.code)) keys.delete(newAlias)
                Rotation.Refused(r.error)
            }
            is GatewayResult.Failed -> {
                keys.delete(newAlias)
                Rotation.Failed
            }
        }
    }

    /** `active = pending`, `pending = null` atomically → evict pooled connections → `credentialsVersion++` (S2 §6.3 п. 6). */
    private fun switchToPending() {
        store.update { it.copy(phase = Phase.ENROLLED, active = it.pending ?: it.active, pending = null, credentialsVersion = it.credentialsVersion + 1) }
        pinned.connectionPool.evictAll()
    }

    private fun dropKey(old: ActiveCert) {
        keys.delete(old.alias)
        KeystoreKeys.deviceKeyNumber(old.alias)?.let { n ->
            val keep = listOfNotNull(store.load().active, store.load().pending).mapNotNull { KeystoreKeys.deviceKeyNumber(it.alias) }.toSet()
            if (n !in keep) store.deleteChainsExcept(keep)
        }
    }

    // ---------------------------------------------------------------- denials on the pinned channel (S2 §5.3)

    /**
     * A denial S1 received over `okHttpClient()` — or the library's own ping / whoami (S2 §5.3,
     * PINNED rows). The client already applied R7, so the code refers to the active certificate.
     */
    suspend fun onPinnedDenial(code: GatewayCode, reason: String?) {
        val s = store.load()
        if (s.phase == Phase.BLOCKED) return
        when (code) {
            GatewayCode.CERT_INVALID, GatewayCode.CERT_UNKNOWN, GatewayCode.CERT_EXPIRED -> ensureFresh()
            GatewayCode.CERT_SUPERSEDED, GatewayCode.UPDATE_REQUIRED, GatewayCode.REATTEST_NOT_ALLOWED,
            GatewayCode.DEVICE_REVOKED, GatewayCode.DEVICE_REPLACED, GatewayCode.IDENTITY_REVOKED, GatewayCode.DEVICE_POLICY,
            -> if (s.phase != Phase.NOT_ENROLLED || isDestructive(code)) onDenied(GatewayError(0, code, reason = reason), s)
            else -> Unit // NO_SESSION, USER_MISMATCH (S1 confirms via whoami), RATE_LIMITED, NONCE_INVALID, UNKNOWN
        }
    }

    private suspend fun onDenied(err: GatewayError, s: StoredState) {
        when (err.code) {
            GatewayCode.UPDATE_REQUIRED -> {
                val v = versions()
                val kind = if (err.reason == "APP_VERSION_TOO_OLD") UpdateKind.APP else UpdateKind.OS
                store.update { it.copy(phase = Phase.UPDATE_REQUIRED, updateRequired = UpdateRequiredInfo(kind.name, err.reason ?: "", v.versionCode, v.securityPatch)) }
            }
            GatewayCode.DEVICE_REVOKED -> block(BlockReason.REVOKED)
            GatewayCode.DEVICE_REPLACED -> block(BlockReason.REPLACED)
            GatewayCode.IDENTITY_REVOKED -> block(BlockReason.IDENTITY_REVOKED)
            GatewayCode.DEVICE_POLICY -> block(BlockReason.POLICY)
            // the renewal response was lost and the gateway already issued a successor: recover with this key
            GatewayCode.CERT_SUPERSEDED -> recover(s)
            GatewayCode.CERT_EXPIRED, GatewayCode.CERT_UNKNOWN, GatewayCode.CERT_INVALID ->
                if (s.active != null && clock.now() >= s.active.notAfter) recover(s)
            GatewayCode.REATTEST_NOT_ALLOWED -> {
                val a = s.active
                if (a == null || clock.now() >= a.notAfter) markReEnrollRequired() // else: recovery was unnecessary
            }
            else -> Unit // RATE_LIMITED, NONCE_INVALID (second time), CSR_INVALID, 5xx, UNKNOWN: retried by the schedule
        }
    }

    fun isDestructive(code: GatewayCode) = code == GatewayCode.DEVICE_REVOKED || code == GatewayCode.DEVICE_REPLACED ||
        code == GatewayCode.IDENTITY_REVOKED || code == GatewayCode.DEVICE_POLICY

    /** Device keys gone, Vault kept (the device is not compromised, it was just offline too long). */
    private fun markReEnrollRequired() {
        keys.deviceKeyAliases().forEach(keys::delete)
        store.deleteChainsExcept(emptySet())
        store.update { it.copy(phase = Phase.RE_ENROLL_REQUIRED, active = null, pending = null, credentialsVersion = it.credentialsVersion + 1) }
        pinned.connectionPool.evictAll()
    }

    // ---------------------------------------------------------------- BLOCK (S2 §8, R1, R6)

    /**
     * RASP BLOCK, the full S2 §8 order: the message is built and **signed while the key still
     * exists** and persisted (п. 1–3), then the intent (п. 4), the wipe (п. 5), the event (п. 6),
     * and the sender is kicked (п. 7).
     */
    suspend fun raspBlock(findings: List<RaspFinding>) {
        // the message is best effort: a full disk or a broken queue must never stop the wipe
        if (store.load().phase != Phase.BLOCKED) {
            runCatching { alerts.enqueue(AlertKind.BLOCK, findings) }
                .onFailure { Journal.event("block_alert_failed", it.javaClass.simpleName) }
        }
        block(BlockReason.RASP)
        runCatching { alerts.schedule() }
    }

    /** Records the intent first, then destroys everything; safe to repeat. No message (S2 §8, last paragraph). */
    suspend fun block(reason: BlockReason) {
        store.update { it.copy(phase = Phase.BLOCKED, blockReason = reason.name) }
        wipeEverything()
        emit(TrustEvent.Blocked(reason))
    }

    // ---------------------------------------------------------------- unenroll (S2 §6.5a, R5, R6)

    /**
     * Always completes locally. With a device key the signed `UNENROLL` is queued **before** the
     * keys go (it is delivered later, also from the queue after the wipe); the intent
     * `UNENROLLING` makes an interrupted wipe finish on the next start.
     */
    suspend fun unenroll(): UnenrollResult {
        val s = store.load()
        if (s.phase == Phase.BLOCKED) return UnenrollResult.Ok(ServerNotice.NOT_NEEDED)
        val hasKey = s.active != null && keys.privateKey(s.active.alias) != null
        val notice = if (hasKey && alerts.enqueue(AlertKind.UNENROLL)) ServerNotice.PENDING else ServerNotice.NOT_NEEDED
        store.update { it.copy(phase = Phase.UNENROLLING) }
        wipeEverything()
        store.update { it.copy(phase = Phase.NOT_ENROLLED, deviceId = null, updateRequired = null, blockReason = null) }
        if (notice == ServerNotice.PENDING) alerts.schedule()
        return UnenrollResult.Ok(notice)
    }

    private suspend fun wipeEverything() {
        val hadKeys = keys.deviceKeyAliases().isNotEmpty() || store.load().active != null
        keys.deleteOrphans(keep = emptySet())
        vault.wipe()
        store.deleteChainsExcept(emptySet())
        store.update {
            it.copy(active = null, pending = null, enrolling = null, credentialsVersion = it.credentialsVersion + if (hadKeys) 1 else 0)
        }
        pinned.connectionPool.evictAll()
    }

    // ---------------------------------------------------------------- start-up reconciliation (S2 §6.6)

    suspend fun reconcile() {
        var s = store.load()

        // 1. a sticky BLOCK / an interrupted unenroll is finished idempotently (R6)
        if (s.phase == Phase.BLOCKED) {
            wipeEverything()
            emit(TrustEvent.Blocked(deriveState(store.load(), clock.now(), config.reattestGrace).let { (it as TrustState.Blocked).reason }))
            return
        }
        if (s.phase == Phase.UNENROLLING) {
            wipeEverything()
            store.update { it.copy(phase = Phase.NOT_ENROLLED, deviceId = null, updateRequired = null) }
            return
        }

        // 2. renewed certificate received but not switched to
        s.pending?.let { p ->
            val n = KeystoreKeys.deviceKeyNumber(p.alias)
            if (keys.privateKey(p.alias) != null && n != null && store.readChain(n) != null) {
                val old = s.active
                switchToPending()
                credentials(p)?.let { io { gateway.renewConfirm(mtlsFor(it)) } }
                old?.let(::dropKey)
            } else {
                store.update { it.copy(pending = null) }
            }
            s = store.load()
        }

        // 2a. lost enroll/finish response: replay within the gateway's replay window
        s.enrolling?.let { e ->
            val fresh = clock.now() < e.createdAt.plus(config.enrollReplayTtl.toJavaDuration())
            val cookie = config.cookieProvider()
            when {
                !fresh || keys.privateKey(e.alias) == null -> dropEnrolling() // a new password will be needed (rare)
                cookie != null -> enroller.replay(cookie) // success clears `enrolling`; a failure keeps it until the window closes
                else -> Unit // no session yet: try again on the next start
            }
            s = store.load()
        }

        // 3. orphans: keys and chains not referenced by active / pending / enrolling
        val keep = listOfNotNull(s.active?.alias, s.pending?.alias, s.enrolling?.alias)
        keys.deleteOrphans(keep = keep.toSet())
        store.deleteChainsExcept(listOfNotNull(s.active, s.pending).mapNotNull { KeystoreKeys.deviceKeyNumber(it.alias) }.toSet())

        // the active key itself is gone (e.g. Keystore reset): the certificate is unusable
        if (s.phase == Phase.ENROLLED && s.active != null && keys.privateKey(s.active.alias) == null) {
            markReEnrollRequired()
            s = store.load()
        }

        // 4. device key present but the Vault is gone → new Vault, the web app re-initialises E2EE
        if (s.phase == Phase.ENROLLED && s.active != null && vault.keys() != VaultKeys.PRESENT) {
            // needs an unlocked device with a screen lock now: when that is not the case (a start
            // from a push behind the lock screen) the next start tries again
            if (runCatching { vault.provision() }.isSuccess) emit(TrustEvent.VaultReset)
        }
        migrateVault()

        // 5. UpdateRequired is lifted once the app or the OS has been updated
        clearUpdateRequiredIfUpdated()
    }

    /** Story 2: an existing single-key vault moves its E2EE half under the unlocked-device key; safe to call often. */
    suspend fun migrateVault() {
        if (store.load().phase != Phase.ENROLLED) return
        val moved = try {
            vault.migrate()
        } catch (e: Exception) {
            Journal.event("vault_migrate_failed", e.javaClass.simpleName)
            false
        }
        if (moved) emit(TrustEvent.BackgroundKeysReset)
    }

    private fun dropEnrolling() {
        store.load().enrolling?.let { keys.delete(it.alias) }
        store.update { it.copy(enrolling = null) }
    }

    private fun clearUpdateRequiredIfUpdated() {
        val s = store.load()
        val info = s.updateRequired ?: return
        if (s.phase != Phase.UPDATE_REQUIRED) return
        val v = versions()
        if (v.versionCode != info.versionCode || v.securityPatch != info.securityPatch) {
            store.update { it.copy(phase = if (it.active != null) Phase.ENROLLED else Phase.NOT_ENROLLED, updateRequired = null) }
        }
    }

    // ---------------------------------------------------------------- helpers

    fun credentials(cert: ActiveCert): ClientCredentials? {
        val n = KeystoreKeys.deviceKeyNumber(cert.alias) ?: return null
        val chain = store.readChain(n) ?: return null
        val key = keys.privateKey(cert.alias) ?: return null
        return ClientCredentials(key, chain.toTypedArray())
    }

    private suspend fun <T> io(block: () -> T): T = withContext(Dispatchers.IO) { block() }
}
