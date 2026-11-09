package org.wolpmessenger.devicetrust.alert

import org.json.JSONArray
import org.json.JSONObject
import org.wolpmessenger.devicetrust.api.RaspFinding
import org.wolpmessenger.devicetrust.keys.KeystoreKeys
import org.wolpmessenger.devicetrust.store.TrustStore
import java.security.Signature
import java.time.Instant
import java.time.temporal.ChronoUnit

/** What the certificate lifecycle and RASP need from the alert channel. */
internal interface AlertSink {
    /**
     * Builds, signs with the current device key (if any) and persists a message. Must run
     * **before** the keys are wiped (S2 §8 п. 1–3, §6.5a п. 1). Returns false if nothing was
     * queued (an `UNENROLL` without a key: the gateway rejects unsigned ones).
     */
    fun enqueue(kind: AlertKind, checks: List<RaspFinding> = emptyList()): Boolean

    /** REPORT findings (S2 §7.4): rate-limited, batched at send time. */
    fun report(findings: List<RaspFinding>)

    /** Asks the background sender to run (WorkManager, network required). */
    fun schedule()

    object None : AlertSink {
        override fun enqueue(kind: AlertKind, checks: List<RaspFinding>) = false
        override fun report(findings: List<RaspFinding>) = Unit
        override fun schedule() = Unit
    }
}

/**
 * Messages to `POST /v1/device/alert` (S3 §5.7):
 * `{"v":1,"kind","deviceId","certSerial","ts","appVersionCode","checks":[{"id","detail"}]}`,
 * signed `SHA256withECDSA` (DER) by the key of the active certificate — also an expired one, the
 * gateway verifies with the registry copy. Without a key (before enrollment, after
 * `ReEnrollRequired`) the message goes unsigned and is sent with the Kratos session.
 */
internal class Alerts(
    private val queue: AlertQueue,
    private val store: TrustStore,
    private val keys: KeystoreKeys,
    private val now: () -> Instant,
    private val versionCode: () -> Long,
    private val scheduler: () -> Unit,
) : AlertSink {
    override fun enqueue(kind: AlertKind, checks: List<RaspFinding>): Boolean {
        val (payload, sig, serial) = build(kind, checks)
        if (kind == AlertKind.UNENROLL && sig == null) return false
        queue.add(kind, payload, sig, serial, now())
        return true
    }

    override fun report(findings: List<RaspFinding>) {
        if (queue.addReports(findings, now()).isNotEmpty()) scheduler()
    }

    override fun schedule() = scheduler()

    /** Batches pending REPORT findings into signed messages; called by the sender before sending. */
    fun drainReports() = queue.drainReports(now()) { batch -> build(AlertKind.REPORT, batch) }

    private fun build(kind: AlertKind, checks: List<RaspFinding>): Triple<ByteArray, ByteArray?, String?> {
        val s = store.load()
        val active = s.active
        val key = active?.let { runCatching { keys.privateKey(it.alias) }.getOrNull() }
        val signer = if (key != null) active else null
        val payload = JSONObject()
            .put("v", 1)
            .put("kind", kind.name)
            .put("deviceId", (if (signer != null) s.deviceId else null) ?: JSONObject.NULL)
            .put("certSerial", signer?.serialHex ?: JSONObject.NULL)
            .put("ts", now().truncatedTo(ChronoUnit.SECONDS).toString())
            .put("appVersionCode", versionCode())
            .put("checks", JSONArray(checks.map { JSONObject().put("id", it.id).put("detail", it.detail.take(MAX_DETAIL)) }))
            .toString().toByteArray()
        val sig = key?.let {
            try {
                Signature.getInstance("SHA256withECDSA").run { initSign(it); update(payload); sign() }
            } catch (e: Exception) {
                null // the key became unusable: send unsigned (REPORT/BLOCK) or not at all (UNENROLL)
            }
        }
        return Triple(payload, sig, if (sig != null) signer?.serialHex else null)
    }

    private companion object {
        /** The gateway keeps 200 characters of a detail (S3 §5.7). */
        const val MAX_DETAIL = 200
    }
}
