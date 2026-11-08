package org.wolpmessenger.devicetrust.clock

import org.wolpmessenger.devicetrust.InternalDeviceTrustApi
import java.time.Instant
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.time.format.DateTimeParseException

/** Persisted anchor of server time (S2 §5.2, stored in `state.json`). */
@InternalDeviceTrustApi
public data class ClockAnchor(val serverEpochMs: Long, val elapsedAtReceipt: Long, val bootCount: Int)

/** Clock sources; an interface so the logic runs in JVM tests. */
internal interface ClockSource {
    /** `SystemClock.elapsedRealtime()`: monotonic, includes deep sleep, resets on reboot. */
    fun elapsedRealtime(): Long
    fun systemEpochMs(): Long

    /** `Settings.Global.BOOT_COUNT`, -1 if unknown. */
    fun bootCount(): Int
}

/**
 * Time relative to the server (S2 §5.2): the `Date` header of the last successful gateway
 * response received over the **pinned** channel, advanced by `elapsedRealtime`. Changing the
 * device clock does not move it. After a reboot, until the first pinned response, the library
 * falls back to system time and [trustNow] returns null.
 */
@InternalDeviceTrustApi
public class TrustClock internal constructor(
    private val source: ClockSource,
    anchor: ClockAnchor? = null,
) {
    @Volatile
    private var anchor: ClockAnchor? = anchor

    /** Server-relative now, or null if the server offset is unknown in this boot. */
    public fun trustNow(): Instant? {
        val a = anchor ?: return null
        val boot = source.bootCount()
        if (boot < 0 || a.bootCount != boot) return null
        return Instant.ofEpochMilli(a.serverEpochMs + (source.elapsedRealtime() - a.elapsedAtReceipt))
    }

    /** What the library uses for its own decisions: server time when known, system time otherwise. */
    public fun now(): Instant = trustNow() ?: Instant.ofEpochMilli(source.systemEpochMs())

    /**
     * Records the `Date` header of a pinned-channel response. Returns the new anchor to persist,
     * or null if the header is missing/unparseable (the old anchor stays).
     */
    public fun onPinnedResponse(dateHeader: String?): ClockAnchor? {
        val serverMs = parseHttpDate(dateHeader) ?: return null
        return ClockAnchor(serverMs, source.elapsedRealtime(), source.bootCount()).also { anchor = it }
    }

    public fun anchor(): ClockAnchor? = anchor

    public companion object {
        /** RFC 7231 IMF-fixdate (`Sun, 08 Nov 2026 19:08:53 GMT`) → epoch ms. */
        internal fun parseHttpDate(value: String?): Long? = try {
            value?.let { ZonedDateTime.parse(it.trim(), DateTimeFormatter.RFC_1123_DATE_TIME).toInstant().toEpochMilli() }
        } catch (e: DateTimeParseException) {
            null
        }
    }
}

internal class AndroidClockSource(context: android.content.Context) : ClockSource {
    private val resolver = context.applicationContext.contentResolver
    override fun elapsedRealtime(): Long = android.os.SystemClock.elapsedRealtime()
    override fun systemEpochMs(): Long = System.currentTimeMillis()
    override fun bootCount(): Int = android.provider.Settings.Global.getInt(resolver, android.provider.Settings.Global.BOOT_COUNT, -1)
}
