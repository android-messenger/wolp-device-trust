package org.wolpmessenger.devicetrust

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.wolpmessenger.devicetrust.api.RaspCheck
import org.wolpmessenger.devicetrust.rasp.KotlinChecks
import java.io.File

/**
 * The inputs of the dual checks are written down three times — `rasp/Checks.kt`,
 * `devicetrust-native/strings.txt`, the library manifest. A difference makes Kotlin and native
 * disagree on every device (HOOK_TAMPER) or hides a root manager from PackageManager, so the
 * build fails on it (specs/001-rasp-hardening FR-007).
 */
class ListsInSyncTest {
    /** Gradle runs unit tests in the module directory; fall back to the repository root. */
    private fun file(fromModule: String, fromRoot: String): File =
        listOf(File(fromModule), File(fromRoot)).firstOrNull { it.exists() } ?: error("not found: $fromModule (cwd ${File("").absolutePath})")

    private val strings: Map<String, List<String>> by lazy {
        file("../devicetrust-native/strings.txt", "devicetrust-native/strings.txt").readLines()
            .map { it.trimEnd() }.filter { it.isNotBlank() && !it.trimStart().startsWith("#") }
            .groupBy({ it.substringBefore(' ') }, { it.substringAfter(' ').trimStart() })
    }

    @Test
    fun `dual check inputs are identical in Kotlin and native`() {
        assertEquals(KotlinChecks.SU_PATHS, strings.getValue("SU_PATHS[]"))
        assertEquals(KotlinChecks.EMU_PATHS, strings.getValue("EMU_PATHS[]"))
        assertEquals(KotlinChecks.EMU_HARDWARE, strings.getValue("EMU_HARDWARE[]").toSet())
        assertEquals(listOf("generic"), strings.getValue("FP_GENERIC"))
        assertEquals(listOf("emulator"), strings.getValue("FP_EMULATOR"))
        assertEquals(listOf("sdk_gphone"), strings.getValue("FP_SDK_GPHONE"))
    }

    @Test
    fun `every native check id is a known RaspCheck with a default reaction`() {
        val ids = strings.filterKeys { it.startsWith("ID_") }.values.flatten()
        assertTrue(ids.isNotEmpty())
        ids.forEach { assertTrue("$it has no default reaction", it in RaspCheck.DEFAULTS) }
    }

    @Test
    fun `manifest queries list every root manager package`() {
        val manifest = file("src/main/AndroidManifest.xml", "devicetrust/src/main/AndroidManifest.xml").readText()
        val queried = Regex("""<package android:name="([^"]+)"""").findAll(manifest).map { it.groupValues[1] }.toList()
        assertEquals(KotlinChecks.ROOT_MANAGERS.sorted(), queried.sorted())
    }
}
