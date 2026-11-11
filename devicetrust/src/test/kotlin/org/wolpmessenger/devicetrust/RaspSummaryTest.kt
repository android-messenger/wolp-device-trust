package org.wolpmessenger.devicetrust

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.wolpmessenger.devicetrust.api.RaspFinding
import org.wolpmessenger.devicetrust.api.RaspReaction
import org.wolpmessenger.devicetrust.api.RaspReport
import org.wolpmessenger.devicetrust.rasp.RaspSummaryStore
import java.io.File
import java.time.Instant

/** specs/001-rasp-hardening FR-035: what is counted between two renewals. */
class RaspSummaryTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private var now = Instant.parse("2026-11-08T10:00:00.750Z")
    private val file by lazy { File(tmp.root, "dt/rasp-summary.json") }
    private fun store() = RaspSummaryStore(file) { now }
    private fun report(vararg ids: String) = RaspReport(ids.map { RaspFinding(it, RaspReaction.REPORT, "secret detail") })
    private fun text(s: RaspSummaryStore) = String(s.snapshot().bytes)

    @Test
    fun `nothing counted - zero passes, native not proved, no since`() {
        assertEquals("""{"v":1,"native":false,"passes":0,"nativeFail":0,"findings":[]}""", text(store()))
    }

    @Test
    fun `passes and finding ids are counted across process restarts, details never leave`() {
        store().record(report("DEV_OPTIONS"), nativeOk = true)
        now = now.plusSeconds(3600)
        store().record(report("ADB_ENABLED", "DEV_OPTIONS"), nativeOk = true)
        store().record(RaspReport.CLEAN, nativeOk = true)
        assertEquals(
            """{"v":1,"native":true,"passes":3,"nativeFail":0,"since":"2026-11-08T10:00:00Z","findings":["ADB_ENABLED","DEV_OPTIONS"]}""",
            text(store()),
        )
    }

    @Test
    fun `one pass without the native half makes native false`() {
        val s = store()
        s.record(RaspReport.CLEAN, nativeOk = true)
        s.record(report("HOOK_TAMPER"), nativeOk = false)
        s.record(RaspReport.CLEAN, nativeOk = true)
        assertEquals(
            """{"v":1,"native":false,"passes":3,"nativeFail":1,"since":"2026-11-08T10:00:00Z","findings":["HOOK_TAMPER"]}""",
            text(s),
        )
    }

    @Test
    fun `sent starts the next period`() {
        val s = store()
        s.record(report("DEV_OPTIONS"), nativeOk = false)
        val snap = s.snapshot()
        now = Instant.parse("2026-11-10T10:00:00Z")
        s.sent(snap)
        assertEquals("""{"v":1,"native":false,"passes":0,"nativeFail":0,"since":"2026-11-10T10:00:00Z","findings":[]}""", text(store()))
    }

    @Test
    fun `a pass between snapshot and the gateway answer is not lost`() {
        val s = store()
        s.record(RaspReport.CLEAN, nativeOk = true)
        val snap = s.snapshot()
        s.record(report("ADB_ENABLED"), nativeOk = false)
        now = Instant.parse("2026-11-10T10:00:00Z")
        s.sent(snap)
        assertEquals(
            """{"v":1,"native":false,"passes":1,"nativeFail":1,"since":"2026-11-10T10:00:00Z","findings":["ADB_ENABLED"]}""",
            text(s),
        )
    }

    @Test
    fun `reset on enrollment forgets everything`() {
        val s = store()
        s.record(report("DEV_OPTIONS"), nativeOk = true)
        s.reset()
        assertEquals(0, s.snapshot().passes)
        s.reset() // no file: still fine
    }

    @Test
    fun `a corrupt file only restarts the count`() {
        file.parentFile!!.mkdirs()
        for (garbage in listOf("", "not json", "[]", """{"passes":"x","findings":7,"since":"yesterday"}""", """{"passes":-5,"nativeFail":99999999}""")) {
            file.writeText(garbage)
            val snap = store().snapshot()
            assertTrue(garbage, snap.passes in 0..RaspSummaryStore.MAX_COUNT && snap.nativeFail in 0..RaspSummaryStore.MAX_COUNT)
            assertTrue(garbage, !String(snap.bytes).contains("since"))
            store().record(RaspReport.CLEAN, nativeOk = true)
        }
    }

    @Test
    fun `the summary stays small - ids are capped and anything that is not an id is dropped`() {
        val s = store()
        s.record(report("bad\"id", "", "lower", "X".repeat(49), *Array(100) { "CHECK_$it" }), nativeOk = true)
        val snap = s.snapshot()
        val ids = org.json.JSONObject(String(snap.bytes)).getJSONArray("findings")
        assertEquals(RaspSummaryStore.MAX_FINDINGS, ids.length())
        assertTrue((0 until ids.length()).all { ids.getString(it).startsWith("CHECK_") })
        assertTrue("fits the gateway limit of 2 KB", snap.bytes.size < 2048)
    }
}
