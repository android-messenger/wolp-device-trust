package org.wolpmessenger.devicetrust.rasp

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeoutOrNull
import org.wolpmessenger.devicetrust.api.VaultException

/**
 * Secrets only after a check (specs/001-rasp-hardening FR-017, FR-018): the Vault hands out
 * nothing until a RASP pass of this process has finished without a wiping finding, and closes
 * again when a later pass does not. `PENDING` until the first pass ends — the start-up pass is
 * launched by `init`, so the wait is one pass long.
 *
 * Closed is not a wipe: the wipe is the BLOCK reaction of the caller of the pass. The gate only
 * makes sure that nothing is decrypted in the meantime, or when the checks could not run at all.
 */
internal class IntegrityGate(private val waitMs: Long = 20_000) {
    private enum class Verdict { PENDING, OPEN, CLOSED }

    private val verdict = MutableStateFlow(Verdict.PENDING)

    /** Outcome of the latest pass. */
    fun record(open: Boolean) {
        verdict.value = if (open) Verdict.OPEN else Verdict.CLOSED
    }

    /** Returns when the latest pass allows secrets; throws [VaultException.Locked] otherwise. */
    suspend fun require() {
        val v = verdict.value.takeIf { it != Verdict.PENDING }
            ?: withTimeoutOrNull(waitMs) { verdict.first { it != Verdict.PENDING } }
        when (v) {
            Verdict.OPEN -> Unit
            Verdict.CLOSED -> throw VaultException.Locked("integrity check did not pass")
            else -> throw VaultException.Locked("integrity check has not finished")
        }
    }
}
