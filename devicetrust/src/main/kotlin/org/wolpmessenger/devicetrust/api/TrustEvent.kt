package org.wolpmessenger.devicetrust.api

/** One-off events (S2 §4). Credential changes are not events — observe `credentialsVersion`. */
public sealed interface TrustEvent {
    /** Emitted on entering `Blocked` and on every start while blocked (S1 repeats its wipe). */
    public data class Blocked(val reason: BlockReason) : TrustEvent

    /** Vault keys were lost and recreated (S2 §6.6 п. 4): S1 clears the web app's E2EE data and re-registers push. */
    public data object VaultReset : TrustEvent
}
