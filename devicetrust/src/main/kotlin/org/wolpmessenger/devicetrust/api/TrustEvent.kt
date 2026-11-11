package org.wolpmessenger.devicetrust.api

/** One-off events (S2 §4). Credential changes are not events — observe `credentialsVersion`. */
public sealed interface TrustEvent {
    /** Emitted on entering `Blocked` and on every start while blocked (S1 repeats its wipe). */
    public data class Blocked(val reason: BlockReason) : TrustEvent

    /** Vault keys were lost and recreated (S2 §6.6 п. 4): S1 clears the web app's E2EE data and re-registers push. */
    public data object VaultReset : TrustEvent

    /**
     * The key for push and the names cache was replaced when the Vault moved its E2EE half under
     * the unlocked-device key (specs/001-rasp-hardening, story 2). E2EE data is untouched; S1
     * drops its push key and names cache and registers push again. Emitted once per device.
     */
    public data object BackgroundKeysReset : TrustEvent
}
