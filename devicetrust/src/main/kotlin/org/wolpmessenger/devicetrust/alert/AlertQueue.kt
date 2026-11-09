package org.wolpmessenger.devicetrust.alert

import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import org.wolpmessenger.devicetrust.api.RaspFinding
import org.wolpmessenger.devicetrust.api.ReportLimit
import org.wolpmessenger.devicetrust.io.AtomicFiles
import java.io.File
import java.time.Instant
import java.util.Base64
import java.util.UUID

/** `kind` of a message to `POST /v1/device/alert` (S3 §5.7). */
internal enum class AlertKind { BLOCK, REPORT, UNENROLL }

/**
 * One queued message, exactly as it will be sent: `payload` bytes are final (and signed when
 * [sig] is set); an unsigned message is sent with the Kratos cookie read at send time (S2 §8 п. 2).
 */
internal class QueuedAlert(
    val file: File,
    val kind: AlertKind,
    val payload: ByteArray,
    val sig: ByteArray?,
    val certSerial: String?,
    val createdAt: Instant,
) {
    /** Body of `POST /v1/device/alert`. */
    fun body(): ByteArray = JSONObject()
        .put("payload", b64.encodeToString(payload))
        .put("sig", sig?.let(b64::encodeToString) ?: JSONObject.NULL)
        .put("certSerial", certSerial ?: JSONObject.NULL)
        .toString().toByteArray()

    private companion object {
        val b64: Base64.Encoder = Base64.getEncoder()
    }
}

/**
 * Persistent queues under `noBackupFilesDir/dt/` (S2 §11):
 * - `alerts/` — ready messages (BLOCK, UNENROLL, batched REPORT), one atomic file each;
 * - `reports/` — REPORT findings waiting to be batched, and the per-finding rate-limit ledger.
 *
 * Survives BLOCK: the wipe deletes keys and the vault, never this directory.
 */
internal class AlertQueue(dir: File, private val limit: ReportLimit) {
    private val alertsDir = File(dir, "alerts")
    private val pendingFile = File(dir, "reports/pending.json")
    private val ledgerFile = File(dir, "reports/sent.json")
    private val lock = Any()
    private var seq = 0

    // ---------------------------------------------------------------- ready messages

    fun add(kind: AlertKind, payload: ByteArray, sig: ByteArray?, certSerial: String?, now: Instant): Unit = synchronized(lock) {
        val j = JSONObject().put("kind", kind.name).put("payload", b64.encodeToString(payload))
            .putOpt("sig", sig?.let(b64::encodeToString)).putOpt("certSerial", certSerial).put("createdAt", now.toString())
        // the name sorts by creation time, then by a per-process sequence (same millisecond): oldest first on send
        val name = "%013d-%06d-%s.json".format(now.toEpochMilli(), seq++ % 1_000_000, UUID.randomUUID())
        AtomicFiles.write(File(alertsDir, name), j.toString().toByteArray())
    }

    /** Ready messages, oldest first. Unreadable files are deleted (a torn write never happens — writes are atomic). */
    fun list(): List<QueuedAlert> = synchronized(lock) {
        val files = alertsDir.listFiles { f -> f.name.endsWith(".json") }?.sortedBy { it.name } ?: return emptyList()
        files.mapNotNull { f ->
            try {
                val j = JSONObject(f.readText())
                QueuedAlert(
                    f, AlertKind.valueOf(j.getString("kind")), unb64.decode(j.getString("payload")),
                    j.optString("sig").ifEmpty { null }?.let(unb64::decode), j.optString("certSerial").ifEmpty { null },
                    Instant.parse(j.getString("createdAt")),
                )
            } catch (e: Exception) {
                f.delete()
                null
            }
        }
    }

    fun remove(a: QueuedAlert) {
        synchronized(lock) { a.file.delete() }
    }

    fun isEmpty(): Boolean = synchronized(lock) { alertsDir.listFiles { f -> f.name.endsWith(".json") }.isNullOrEmpty() && pending().isEmpty() }

    // ---------------------------------------------------------------- REPORT findings (S2 §7.4)

    /**
     * Queues findings not reported within `perCheckWindow` for the same (id, detail).
     * Returns the findings actually queued.
     */
    fun addReports(findings: List<RaspFinding>, now: Instant): List<RaspFinding> = synchronized(lock) {
        val ledger = ledger().filterValues { now.toEpochMilli() - it < limit.perCheckWindow.inWholeMilliseconds }.toMutableMap()
        val fresh = findings.distinctBy { key(it) }.filter { key(it) !in ledger }
        if (fresh.isEmpty()) return emptyList()
        fresh.forEach { ledger[key(it)] = now.toEpochMilli() }
        val pending = (pending() + fresh).takeLast(limit.queue)
        AtomicFiles.write(pendingFile, JSONArray(pending.map { JSONObject().put("id", it.id).put("detail", it.detail) }).toString().toByteArray())
        AtomicFiles.write(ledgerFile, JSONObject(ledger as Map<*, *>).toString().toByteArray())
        fresh
    }

    /** Takes the pending findings in batches of `batch` and turns each batch into a ready message via [build]. */
    fun drainReports(now: Instant, build: (List<RaspFinding>) -> Triple<ByteArray, ByteArray?, String?>): Unit = synchronized(lock) {
        val pending = pending()
        if (pending.isEmpty()) return
        pending.chunked(limit.batch).forEach { batch ->
            val (payload, sig, serial) = build(batch)
            add(AlertKind.REPORT, payload, sig, serial, now)
        }
        pendingFile.delete()
    }

    private fun pending(): List<RaspFinding> = readJson(pendingFile) { s ->
        val a = JSONArray(s)
        List(a.length()) { i -> a.getJSONObject(i).let { RaspFinding(it.getString("id"), org.wolpmessenger.devicetrust.api.RaspReaction.REPORT, it.optString("detail")) } }
    } ?: emptyList()

    private fun ledger(): Map<String, Long> = readJson(ledgerFile) { s ->
        val j = JSONObject(s)
        j.keys().asSequence().associateWith { j.getLong(it) }
    } ?: emptyMap()

    private fun <T> readJson(f: File, parse: (String) -> T): T? = if (!f.exists()) null else try {
        parse(f.readText())
    } catch (e: JSONException) {
        f.delete()
        null
    }

    private fun key(f: RaspFinding) = f.id + "|" + f.detail

    private companion object {
        val b64: Base64.Encoder = Base64.getEncoder()
        val unb64: Base64.Decoder = Base64.getDecoder()
    }
}
