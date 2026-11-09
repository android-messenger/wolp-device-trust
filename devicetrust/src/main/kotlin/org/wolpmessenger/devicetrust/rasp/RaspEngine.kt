package org.wolpmessenger.devicetrust.rasp

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.wolpmessenger.devicetrust.Journal
import org.wolpmessenger.devicetrust.api.BuildKind
import org.wolpmessenger.devicetrust.api.DeviceTrustConfig
import org.wolpmessenger.devicetrust.api.RaspCheck
import org.wolpmessenger.devicetrust.api.RaspFinding
import org.wolpmessenger.devicetrust.api.RaspReaction
import org.wolpmessenger.devicetrust.api.RaspReport
import org.wolpmessenger.devicetrust.attest.RaspScanner

/**
 * S2 §7.3 applied at runtime, not by lint:
 * - the effective build kind is RELEASE unless the app is debuggable, or it is declared PILOT and
 *   its `versionCode` is in the pilot range — the declaration alone is not trusted;
 * - lowering a reaction below its default works only in a non-RELEASE build (otherwise ignored, journaled);
 * - `raspDryRun` works only in a non-RELEASE build: every BLOCK becomes a REPORT marked `dryRun`.
 */
internal class EffectivePolicy(config: DeviceTrustConfig, debuggable: Boolean, versionCode: Long) {
    val kind: BuildKind = when {
        debuggable -> config.buildKind
        config.buildKind == BuildKind.PILOT && config.pilotVersionCode(versionCode) -> BuildKind.PILOT
        else -> BuildKind.RELEASE
    }
    val dryRun: Boolean = config.raspDryRun && kind != BuildKind.RELEASE

    private val reactions: Map<String, RaspReaction> = RaspCheck.DEFAULTS + config.raspPolicy.overrides.mapNotNull { (id, wanted) ->
        val default = RaspCheck.DEFAULTS[id] ?: RaspReaction.REPORT
        if (wanted.weaker(default) && kind == BuildKind.RELEASE) {
            Journal.event("rasp_policy_downgrade_ignored", "$id $wanted<$default")
            null
        } else {
            id to wanted
        }
    }

    fun reaction(id: String): RaspReaction = reactions[id] ?: RaspReaction.REPORT

    fun apply(raw: List<RawFinding>): RaspReport = RaspReport(
        raw.distinctBy { it.id to it.detail }.mapNotNull { f ->
            when (val r = reaction(f.id)) {
                RaspReaction.IGNORE -> null
                RaspReaction.BLOCK -> if (dryRun) RaspFinding(f.id, RaspReaction.REPORT, "dryRun;BLOCK;${f.detail}") else RaspFinding(f.id, r, f.detail)
                RaspReaction.REPORT -> RaspFinding(f.id, r, f.detail)
            }
        },
    )

    private fun RaspReaction.weaker(than: RaspReaction): Boolean = rank(this) < rank(than)
    private fun rank(r: RaspReaction) = when (r) {
        RaspReaction.IGNORE -> 0
        RaspReaction.REPORT -> 1
        RaspReaction.BLOCK -> 2
    }
}

/**
 * One RASP pass (S2 §7): Kotlin checks, native checks (HMAC-verified), their comparison
 * (HOOK_TAMPER), then the policy. Findings only — the reaction (BLOCK §8, REPORT §7.4) is the
 * caller's.
 */
internal class RaspEngine(
    private val kotlin: KotlinChecks,
    private val native: () -> NativeResult,
    private val policy: EffectivePolicy,
) : RaspScanner {
    override suspend fun scan(): RaspReport = withContext(Dispatchers.IO) { evaluate() }

    fun evaluate(): RaspReport {
        val raw = mutableListOf<RawFinding>()
        val dual = kotlin.dual()
        dual.forEach { (id, p) -> if (p.state == ProbeState.FOUND) raw += RawFinding(id, p.detail) }
        raw += kotlin.single()
        when (val n = native()) {
            is NativeResult.Ok -> {
                for ((id, p) in n.probes) {
                    val k = dual[id]
                    if (p.state == ProbeState.FOUND && k?.state != ProbeState.FOUND) raw += RawFinding(id, "native:${p.detail}")
                    if (k != null && k.state != p.state) raw += RawFinding(RaspCheck.HOOK_TAMPER, "$id kotlin=${k.state} native=${p.state}")
                }
                (dual.keys - n.probes.keys).forEach { raw += RawFinding(RaspCheck.HOOK_TAMPER, "$it missing in native") }
            }
            is NativeResult.Tampered -> raw += RawFinding(RaspCheck.HOOK_TAMPER, n.why)
        }
        return policy.apply(raw)
    }
}
