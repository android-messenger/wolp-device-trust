package org.wolpmessenger.devicetrust.rasp

import org.json.JSONArray
import org.json.JSONObject
import org.wolpmessenger.devicetrust.api.RaspReport
import org.wolpmessenger.devicetrust.io.AtomicFiles
import java.io.File
import java.time.Instant
import java.time.temporal.ChronoUnit

/**
 * What the gateway is told about RASP with every renewal and recovery (specs/001-rasp-hardening
 * FR-035): the exact bytes of
 * ```
 * {"v":1,"native":true,"passes":17,"nativeFail":0,"since":"2026-11-08T10:00:00Z","findings":["ADB_ENABLED","DEV_OPTIONS"]}
 * ```
 * - `passes` — RASP passes since the previous successful renewal (or the enrollment);
 * - `native` — the native half answered and verified in **every** one of them (false with no passes:
 *   nothing was proved); `nativeFail` — in how many it did not;
 * - `since` — when the counting started; absent if nothing was ever counted;
 * - `findings` — ids only, sorted, no details.
 *
 * The bytes are signed as they are (continuitySig v2 covers their SHA-256), so the gateway needs
 * no canonical form. [passes] and [nativeFail] are what [RaspSummaryStore.sent] takes off the counters.
 */
internal class RaspSummary(val bytes: ByteArray, val passes: Int, val nativeFail: Int)

/** Source of the summary for CertManager; [None] when the library has no RASP wired (tests). */
internal interface RaspSummarySource {
    fun snapshot(): RaspSummary?

    /** The gateway accepted the rotation that carried [summary]. */
    fun sent(summary: RaspSummary)

    /** A new enrollment: counting starts over. */
    fun reset()

    object None : RaspSummarySource {
        override fun snapshot(): RaspSummary? = null
        override fun sent(summary: RaspSummary) = Unit
        override fun reset() = Unit
    }
}

/**
 * Counters in `noBackupFilesDir/dt/rasp-summary.json`: the process restarts many times between
 * two renewals. Survives BLOCK and unenroll like the alert queue; [reset] on enrollment.
 * A lost or corrupt file only means the count starts again.
 */
internal class RaspSummaryStore(private val file: File, private val now: () -> Instant) : RaspSummarySource {
    private class Counters(var passes: Int = 0, var nativeFail: Int = 0, var since: String? = null, val findings: MutableSet<String> = sortedSetOf())

    /** One finished RASP pass. [nativeOk]: the native half answered and verified in it. */
    @Synchronized
    fun record(report: RaspReport, nativeOk: Boolean) {
        val c = load()
        if (c.since == null) c.since = stamp()
        if (c.passes < MAX_COUNT) c.passes++
        if (!nativeOk && c.nativeFail < MAX_COUNT) c.nativeFail++
        for (f in report.findings) {
            if (c.findings.size >= MAX_FINDINGS) break
            if (ID.matches(f.id)) c.findings += f.id
        }
        save(c)
    }

    @Synchronized
    override fun snapshot(): RaspSummary {
        val c = load()
        val json = buildString {
            append("{\"v\":1,\"native\":").append(c.passes > 0 && c.nativeFail == 0)
            append(",\"passes\":").append(c.passes)
            append(",\"nativeFail\":").append(c.nativeFail)
            c.since?.let { append(",\"since\":\"").append(it).append('"') }
            // ids match [ID]: nothing to escape
            append(",\"findings\":[").append(c.findings.joinToString(",") { "\"$it\"" }).append("]}")
        }
        return RaspSummary(json.toByteArray(Charsets.US_ASCII), c.passes, c.nativeFail)
    }

    /**
     * Takes the reported passes off the counters. A pass that ran between [snapshot] and the
     * gateway's answer stays counted, and then the findings stay too (they may be its own —
     * reporting one twice is harmless, losing it is not).
     */
    @Synchronized
    override fun sent(summary: RaspSummary) {
        val c = load()
        c.passes = (c.passes - summary.passes).coerceAtLeast(0)
        c.nativeFail = (c.nativeFail - summary.nativeFail).coerceAtLeast(0)
        if (c.passes == 0) c.findings.clear()
        c.since = stamp()
        save(c)
    }

    @Synchronized
    override fun reset() {
        file.delete()
    }

    private fun stamp(): String = now().truncatedTo(ChronoUnit.SECONDS).toString()

    private fun load(): Counters = try {
        val j = JSONObject(file.readText())
        val ids = j.optJSONArray("findings") ?: JSONArray()
        Counters(
            passes = j.optInt("passes").coerceIn(0, MAX_COUNT),
            nativeFail = j.optInt("nativeFail").coerceIn(0, MAX_COUNT),
            since = j.optString("since").takeIf { s -> runCatching { Instant.parse(s) }.isSuccess },
            findings = (0 until ids.length()).map { ids.optString(it) }.filter(ID::matches).take(MAX_FINDINGS).toSortedSet(),
        )
    } catch (e: Exception) { // missing, unreadable, not JSON
        Counters()
    }

    private fun save(c: Counters) {
        val j = JSONObject().put("passes", c.passes).put("nativeFail", c.nativeFail).put("findings", JSONArray(c.findings.toList()))
        c.since?.let { j.put("since", it) }
        AtomicFiles.write(file, j.toString().toByteArray())
    }

    internal companion object {
        /** `features` entry of a challenge that allows sending the summary (and continuitySig v2). */
        const val FEATURE = "raspSummary"
        const val MAX_FINDINGS = 32
        const val MAX_COUNT = 1_000_000
        private val ID = Regex("[A-Z0-9_]{1,48}")
    }
}
