package org.wolpmessenger.devicetrust.rasp

/** Result of one probe. [DENIED] (EACCES/EPERM) is its own result, never "found" (S2 §7.1). */
internal enum class ProbeState(val wire: Char) {
    FOUND('F'), CLEAN('C'), DENIED('D');

    companion object {
        fun of(c: Char): ProbeState? = entries.firstOrNull { it.wire == c }
    }
}

internal data class Probe(val state: ProbeState, val detail: String = "") {
    companion object {
        val CLEAN = Probe(ProbeState.CLEAN)
    }
}

/** A raw finding before the policy assigns a reaction. */
internal data class RawFinding(val id: String, val detail: String = "")
