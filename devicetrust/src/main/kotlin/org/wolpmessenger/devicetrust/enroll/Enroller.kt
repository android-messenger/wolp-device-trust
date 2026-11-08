package org.wolpmessenger.devicetrust.enroll

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.wolpmessenger.devicetrust.api.BlockReason
import org.wolpmessenger.devicetrust.api.DeviceTrustConfig
import org.wolpmessenger.devicetrust.api.EnrollResult
import org.wolpmessenger.devicetrust.api.GatewayCode
import org.wolpmessenger.devicetrust.api.PrecheckResult
import org.wolpmessenger.devicetrust.api.SecurityLevel
import org.wolpmessenger.devicetrust.api.UnsupportedReason
import org.wolpmessenger.devicetrust.api.UpdateKind
import org.wolpmessenger.devicetrust.asn1.Csr
import org.wolpmessenger.devicetrust.keys.KeyGenResult
import org.wolpmessenger.devicetrust.keys.KeystoreKeys
import org.wolpmessenger.devicetrust.net.GatewayClient
import org.wolpmessenger.devicetrust.net.GatewayError
import org.wolpmessenger.devicetrust.net.GatewayResult
import org.wolpmessenger.devicetrust.store.ActiveCert
import org.wolpmessenger.devicetrust.store.Enrolling
import org.wolpmessenger.devicetrust.store.Phase
import org.wolpmessenger.devicetrust.store.TrustStore
import java.io.IOException
import java.time.Instant

/** A gateway refusal carried as the cause of [EnrollResult.Transient]. */
internal class GatewayException(val error: GatewayError) : IOException("gateway refused: ${error.code} (${error.httpStatus})")

/**
 * Enrollment (S2 §6.2):
 * precheck → `enroll/start` → device key with the nonce → CSR → persist `enrolling` →
 * `enroll/finish` → Vault (KEK + DEK) → certificate + `ENROLLED`, `credentialsVersion++`.
 *
 * The caller's password array is zeroed when the call returns.
 */
internal class Enroller(
    private val config: DeviceTrustConfig,
    private val precheck: suspend () -> PrecheckResult,
    private val keys: KeystoreKeys,
    private val gateway: GatewayClient,
    private val store: TrustStore,
    private val provisionVault: suspend () -> Unit,
    private val versionCode: () -> Long,
    private val now: () -> Instant,
) {
    private val mutex = Mutex()

    suspend fun enroll(cookie: String, password: CharArray): EnrollResult = mutex.withLock {
        try {
            run(cookie, password, nonceRetryLeft = true)
        } finally {
            password.fill('\u0000')
        }
    }

    /**
     * Replays `enroll/finish` for a persisted intent after a lost response (S2 §6.6 п. 2a). The
     * gateway returns the same certificate within `DEVICES_ENROLL_REPLAY_TTL`.
     */
    suspend fun replay(cookie: String): EnrollResult = mutex.withLock {
        when (val r = finish(cookie)) {
            is FinishOutcome.Done -> r.result
            FinishOutcome.RetryWithNewNonce -> EnrollResult.Transient(IOException("enrollment expired; a new password is needed"), null)
        }
    }

    private suspend fun run(cookie: String, password: CharArray, nonceRetryLeft: Boolean): EnrollResult {
        val state = store.load()
        when (state.phase) {
            Phase.BLOCKED -> return EnrollResult.Blocked(state.blockReason?.let { runCatching { BlockReason.valueOf(it) }.getOrNull() } ?: BlockReason.POLICY)
            Phase.ENROLLED, Phase.UNENROLLING ->
                return EnrollResult.Transient(IllegalStateException("enroll is not allowed in ${state.phase}"), null)
            Phase.NOT_ENROLLED, Phase.RE_ENROLL_REQUIRED, Phase.UPDATE_REQUIRED -> Unit
        }

        // 1. precheck — nothing reaches the gateway if it fails
        val info = when (val p = precheck()) {
            is PrecheckResult.Unsupported -> return EnrollResult.Unsupported(p.reasons.map { it.name })
            // The BLOCK reaction itself (S2 §8) is wired with RASP in stage 6.
            is PrecheckResult.Compromised -> return EnrollResult.Blocked(BlockReason.RASP)
            is PrecheckResult.Supported -> p.info
        }

        // 2. enroll/start — body built straight into bytes, zeroed after sending
        val summary = PrecheckSummary(wireLevel(info.keystoreLevel), info.keystoreLevel == SecurityLevel.STRONGBOX, info.sdkInt, info.securityPatch)
        val body = EnrollStartBody.encode(password, versionCode(), summary)
        val started = try {
            io { gateway.enrollStart(cookie, body) }
        } finally {
            body.fill(0)
        }
        val start = when (started) {
            is GatewayResult.Ok -> started.value
            is GatewayResult.Refused -> return startRefused(started.error)
            is GatewayResult.Failed -> return EnrollResult.Transient(started.cause, null)
        }

        // 4. device key bound to the nonce
        val alias = keys.nextDeviceAlias()
        val key = when (val g = io { keys.generate(alias, start.nonce, config.deviceKeyStrongBox) }) {
            is KeyGenResult.SoftwareKeystore -> return EnrollResult.Unsupported(listOf(UnsupportedReason.SOFTWARE_KEYSTORE.name))
            is KeyGenResult.Ok -> g.key
        }

        // 5. CSR signed in Keystore
        val csr = try {
            io { Csr.build(keys.publicKey(alias)!!, keys.privateKey(alias)!!) }
        } catch (e: Exception) {
            keys.delete(alias)
            return EnrollResult.Transient(e, null)
        }

        // 6. persist intent before finish (lost response → replay, S2 §6.6 п. 2a)
        store.update { it.copy(enrolling = Enrolling(start.enrollmentId!!, alias, csr, key.chain.map { c -> c.encoded }, now())) }

        // 7. finish
        return when (val r = finish(cookie)) {
            FinishOutcome.RetryWithNewNonce ->
                if (nonceRetryLeft) run(cookie, password, nonceRetryLeft = false)
                else EnrollResult.Transient(IOException("NONCE_INVALID twice"), null)
            is FinishOutcome.Done -> r.result
        }
    }

    private sealed interface FinishOutcome {
        data class Done(val result: EnrollResult) : FinishOutcome
        data object RetryWithNewNonce : FinishOutcome
    }

    /** Sends `enroll/finish` for the persisted `enrolling` record and applies the outcome. */
    private suspend fun finish(cookie: String): FinishOutcome {
        val e = store.load().enrolling ?: return FinishOutcome.Done(EnrollResult.Transient(IllegalStateException("nothing to finish"), null))
        val done = { r: EnrollResult -> FinishOutcome.Done(r) }

        return when (val r = io { gateway.enrollFinish(cookie, e.enrollmentId, e.csr, e.chain) }) {
            is GatewayResult.Failed -> done(EnrollResult.Transient(r.cause, null)) // keep `enrolling` for replay
            is GatewayResult.Refused -> {
                val err = r.error
                val soft = updateKindOf(err.reason)
                when {
                    err.code == GatewayCode.UPDATE_REQUIRED || (err.code == GatewayCode.POLICY_REJECTED && soft != null) -> {
                        drop(e) // the enrollment is spent; the password is not (S3 §5.2 п. 4)
                        done(EnrollResult.UpdateRequired(soft ?: UpdateKind.APP))
                    }
                    err.code == GatewayCode.POLICY_REJECTED -> {
                        drop(e)
                        done(EnrollResult.PolicyRejected(err.reason ?: "UNKNOWN"))
                    }
                    err.code == GatewayCode.NONCE_INVALID -> {
                        drop(e)
                        FinishOutcome.RetryWithNewNonce
                    }
                    err.code == GatewayCode.IDENTITY_REVOKED -> {
                        drop(e)
                        done(EnrollResult.Blocked(BlockReason.IDENTITY_REVOKED))
                    }
                    err.code == GatewayCode.CSR_INVALID -> {
                        drop(e)
                        done(EnrollResult.Transient(GatewayException(err), null))
                    }
                    err.code == GatewayCode.NO_SESSION -> done(EnrollResult.NoSession) // keep: replay after re-login
                    else -> done(EnrollResult.Transient(GatewayException(err), err.retryAfter)) // 429/5xx: keep
                }
            }
            is GatewayResult.Ok -> {
                val f = r.value
                try {
                    provisionVault() // S2 §6.2 п. 7: Vault first, then the state that makes the device Active
                } catch (ex: Exception) {
                    return done(EnrollResult.Transient(ex, null)) // keep `enrolling`: replay returns the same certificate
                }
                val n = KeystoreKeys.deviceKeyNumber(e.alias)!!
                store.writeChain(n, f.certChain)
                store.update {
                    it.copy(
                        phase = Phase.ENROLLED,
                        deviceId = f.deviceId ?: it.deviceId,
                        active = ActiveCert(e.alias, f.certChain.first().serialNumber.toString(16), f.notBefore, f.notAfter, f.renewAfter),
                        enrolling = null,
                        updateRequired = null,
                        credentialsVersion = it.credentialsVersion + 1,
                    )
                }
                store.deleteChainsExcept(setOf(n))
                keys.deleteOrphans(keep = setOf(e.alias))
                done(EnrollResult.Ok(f.deviceId ?: ""))
            }
        }
    }

    private fun drop(e: Enrolling) {
        keys.delete(e.alias)
        store.update { it.copy(enrolling = null) }
    }

    private fun startRefused(err: GatewayError): EnrollResult = when (err.code) {
        GatewayCode.WRONG_PASSWORD -> EnrollResult.WrongPassword((err.attemptsLeft ?: 1).coerceAtLeast(1))
        GatewayCode.PASSWORD_BURNED -> EnrollResult.PasswordBurned
        GatewayCode.PASSWORD_EXPIRED -> EnrollResult.PasswordExpired
        GatewayCode.NO_PASSWORD -> EnrollResult.NoPassword
        GatewayCode.NO_SESSION -> EnrollResult.NoSession
        GatewayCode.IDENTITY_REVOKED -> EnrollResult.Blocked(BlockReason.IDENTITY_REVOKED)
        else -> EnrollResult.Transient(GatewayException(err), err.retryAfter)
    }

    private suspend fun <T> io(block: () -> T): T = withContext(Dispatchers.IO) { block() }

    internal companion object {
        fun wireLevel(level: SecurityLevel): String = when (level) {
            SecurityLevel.TRUSTED_ENVIRONMENT -> "TEE"
            SecurityLevel.STRONGBOX -> "STRONGBOX"
            else -> level.name
        }

        fun updateKindOf(reason: String?): UpdateKind? = when (reason) {
            "APP_VERSION_TOO_OLD" -> UpdateKind.APP
            "PATCH_TOO_OLD", "OS_TOO_OLD" -> UpdateKind.OS
            else -> null
        }
    }
}
