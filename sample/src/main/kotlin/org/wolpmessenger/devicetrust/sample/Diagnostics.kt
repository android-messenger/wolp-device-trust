package org.wolpmessenger.devicetrust.sample

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import org.wolpmessenger.devicetrust.api.DeviceTrustConfig
import org.wolpmessenger.devicetrust.api.PrecheckResult
import org.wolpmessenger.devicetrust.api.VaultPurpose
import org.wolpmessenger.devicetrust.attest.AttestationChain
import org.wolpmessenger.devicetrust.attest.Precheck
import org.wolpmessenger.devicetrust.keys.KeyGenResult
import org.wolpmessenger.devicetrust.keys.KeystoreKeys
import org.wolpmessenger.devicetrust.vault.EnvelopeVault
import java.security.Signature
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** Latency summary in milliseconds. */
data class Stats(val n: Int, val p50: Double, val p95: Double, val max: Double) {
    fun json(): JSONObject = JSONObject().put("n", n).put("p50", p50).put("p95", p95).put("max", max)

    companion object {
        fun of(ns: List<Long>): Stats {
            val s = ns.sorted().map { it / 1e6 }
            fun p(q: Double) = s[((s.size - 1) * q).toInt()]
            return Stats(s.size, p(0.5), p(0.95), s.last())
        }
    }
}

/** One certificate of an attestation chain, for display. */
data class CertRow(val subject: String, val issuer: String)

data class AttestationProbe(
    val requestedStrongBox: Boolean,
    val level: String,
    val hardwareConfirmed: Boolean,
    val strongBoxFallback: Boolean,
    val chainType: String,
    val chain: List<CertRow>,
    val error: String? = null,
)

data class KeyBench(
    val requestedStrongBox: Boolean,
    val level: String?,
    val note: String?,
    val keygen: Stats? = null,
    val sign: Stats? = null,
    val parallelSign: Stats? = null,
    val parallelWallMs: Double? = null,
) {
    fun json(): JSONObject = JSONObject().put("requestedStrongBox", requestedStrongBox).put("level", level ?: JSONObject.NULL)
        .put("note", note ?: JSONObject.NULL).put("keygenMs", keygen?.json()).put("signMs", sign?.json())
        .put("parallelSignMs", parallelSign?.json()?.put("threads", PARALLEL)?.put("wallMs", parallelWallMs))
}

data class VaultBench(val dekUnwrap: Stats, val wrap4k: Stats, val unwrap4k: Stats) {
    fun json(): JSONObject = JSONObject().put("dekUnwrapMs", dekUnwrap.json()).put("wrap4KiBMs", wrap4k.json()).put("unwrap4KiBMs", unwrap4k.json())
        .put("targets", JSONObject().put("wrapUnwrapP95Ms", VAULT_OP_TARGET_MS).put("dekUnwrapP95Ms", DEK_TARGET_MS))
}

const val PARALLEL = 6
const val VAULT_OP_TARGET_MS = 1.0
const val DEK_TARGET_MS = 50.0

/**
 * Everything the sample shows. Blocking — call from a background dispatcher.
 * Uses the app's own Keystore namespace; every key it creates is deleted again.
 */
class Diagnostics(private val context: Context) {
    private val keys = KeystoreKeys.android()

    fun precheck(): PrecheckResult = kotlinx.coroutines.runBlocking { Precheck.android(context, DeviceTrustConfig()).run() }

    /** Device-shaped key with a challenge; the attestation chain as Keystore returns it. */
    fun attest(strongBox: Boolean): AttestationProbe {
        val alias = keys.nextDeviceAlias()
        return try {
            when (val r = keys.generate(alias, ByteArray(32) { 0x5A }, preferStrongBox = strongBox)) {
                is KeyGenResult.SoftwareKeystore -> {
                    // Show what the software chain looks like anyway (emulators, broken TEE).
                    val k = keys.generateUnchecked(alias, ByteArray(32) { 0x5A }, strongBox = false)
                    probe(strongBox, k.level.name, false, false, AttestationChain(k.chain))
                }
                is KeyGenResult.Ok -> probe(strongBox, r.key.level.name, true, r.key.strongBoxFallback, AttestationChain(r.key.chain))
            }
        } catch (e: Exception) {
            AttestationProbe(strongBox, "—", false, false, "—", emptyList(), e.javaClass.simpleName + ": " + e.message)
        } finally {
            keys.delete(alias)
        }
    }

    private fun probe(sb: Boolean, level: String, hw: Boolean, fallback: Boolean, chain: AttestationChain) = AttestationProbe(
        requestedStrongBox = sb, level = level, hardwareConfirmed = hw, strongBoxFallback = fallback,
        chainType = chain.chainType.name.lowercase(),
        chain = chain.certificates.map { CertRow(it.subjectX500Principal.name, it.issuerX500Principal.name) },
    )

    /** S2 §3 measurements: keygen with attestation, ECDSA signature latency, concurrent signing. */
    fun keyBench(strongBox: Boolean, onProgress: (String) -> Unit = {}): KeyBench {
        val keygen = mutableListOf<Long>()
        var alias = ""
        var result: KeyGenResult? = null
        try {
            repeat(KEYGEN_RUNS) { i ->
                onProgress("key generation ${i + 1}/$KEYGEN_RUNS")
                keys.delete(alias)
                alias = keys.nextDeviceAlias()
                val t = System.nanoTime()
                result = keys.generate(alias, ByteArray(32) { 1 }, preferStrongBox = strongBox)
                keygen += System.nanoTime() - t
            }
            val ok = result as? KeyGenResult.Ok
                ?: return KeyBench(strongBox, (result as? KeyGenResult.SoftwareKeystore)?.level?.name, "not hardware-backed: not measured")
            if (strongBox && ok.key.strongBoxFallback) return KeyBench(strongBox, ok.key.level.name, "StrongBox unavailable: fell back to TEE")
            val key = keys.privateKey(alias)!!
            val data = ByteArray(32) { it.toByte() }
            fun sign(): ByteArray = Signature.getInstance("SHA256withECDSA").run { initSign(key); update(data); sign() }

            onProgress("warm-up")
            repeat(WARMUP) { sign() }
            onProgress("$SIGN_RUNS signatures")
            val single = List(SIGN_RUNS) { val t = System.nanoTime(); sign(); System.nanoTime() - t }
            onProgress("$PARALLEL threads × $PER_THREAD signatures")
            val pool = Executors.newFixedThreadPool(PARALLEL)
            val t0 = System.nanoTime()
            val parallel = List(PARALLEL) { pool.submit<List<Long>> { List(PER_THREAD) { val t = System.nanoTime(); sign(); System.nanoTime() - t } } }
                .flatMap { it.get() }
            val wall = (System.nanoTime() - t0) / 1e6
            pool.shutdown(); pool.awaitTermination(1, TimeUnit.MINUTES)
            return KeyBench(strongBox, ok.key.level.name, null, Stats.of(keygen), Stats.of(single), Stats.of(parallel), wall)
        } catch (e: Exception) {
            return KeyBench(strongBox, null, e.javaClass.simpleName + ": " + e.message)
        } finally {
            keys.delete(alias)
        }
    }

    /** S2 §9 / §15 п. 8: DEK unwrap on first access, wrap/unwrap of 4 KiB. */
    fun vaultBench(onProgress: (String) -> Unit = {}): VaultBench = kotlinx.coroutines.runBlocking {
        val base = EnvelopeVault.android(context)
        base.wipe()
        base.provision()
        try {
            onProgress("DEK unwrap ×$DEK_RUNS")
            val dek = List(DEK_RUNS) {
                val v = EnvelopeVault.android(context)
                val t = System.nanoTime(); v.wrap(ByteArray(1), VaultPurpose.E2EE); System.nanoTime() - t
            }
            val plain = ByteArray(4096) { it.toByte() }
            repeat(50) { base.unwrap(base.wrap(plain, VaultPurpose.E2EE), VaultPurpose.E2EE) }
            onProgress("wrap/unwrap 4 KiB ×$VAULT_OPS")
            val blobs = ArrayList<ByteArray>(VAULT_OPS)
            val wrap = List(VAULT_OPS) { val t = System.nanoTime(); blobs += base.wrap(plain, VaultPurpose.E2EE); System.nanoTime() - t }
            val unwrap = blobs.map { val t = System.nanoTime(); base.unwrap(it, VaultPurpose.E2EE); System.nanoTime() - t }
            VaultBench(Stats.of(dek), Stats.of(wrap), Stats.of(unwrap))
        } finally {
            base.wipe()
        }
    }

    companion object {
        const val KEYGEN_RUNS = 5
        const val WARMUP = 10
        const val SIGN_RUNS = 100
        const val PER_THREAD = 20
        const val DEK_RUNS = 30
        const val VAULT_OPS = 500

        fun precheckJson(r: PrecheckResult): JSONObject = when (r) {
            is PrecheckResult.Supported -> JSONObject().put("result", "Supported").put("keystoreLevel", r.info.keystoreLevel.name)
                .put("reports", JSONArray(r.reports.map { it.id }))
            is PrecheckResult.Unsupported -> JSONObject().put("result", "Unsupported").put("reasons", JSONArray(r.reasons.map { it.name }))
                .put("keystoreLevel", r.info?.keystoreLevel?.name)
            is PrecheckResult.Compromised -> JSONObject().put("result", "Compromised").put("findings", JSONArray(r.report.findings.map { it.id }))
        }
    }
}
