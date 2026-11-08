package org.wolpmessenger.devicetrust.api

/** Reaction to a RASP finding (S2 §7.3). */
public enum class RaspReaction { BLOCK, REPORT, IGNORE }

/** One RASP finding: check id from S2 §7.1 (e.g. `ROOT_SU`, `NO_SCREEN_LOCK`) and the applied reaction. */
public data class RaspFinding(val id: String, val reaction: RaspReaction, val detail: String = "")

/** Result of a RASP scan. The checks themselves arrive in stage 6 (S2 §14). */
public data class RaspReport(val findings: List<RaspFinding>) {
    public val blocking: List<RaspFinding> get() = findings.filter { it.reaction == RaspReaction.BLOCK }
    public val reports: List<RaspFinding> get() = findings.filter { it.reaction == RaspReaction.REPORT }

    public companion object {
        public val CLEAN: RaspReport = RaspReport(emptyList())
    }
}
