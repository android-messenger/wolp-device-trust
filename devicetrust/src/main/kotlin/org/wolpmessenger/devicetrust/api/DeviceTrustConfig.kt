package org.wolpmessenger.devicetrust.api

/**
 * Library configuration (S2 §12). Stage 1 carries only what keys and precheck need;
 * the remaining fields (hosts, pins, RASP policy, timeouts…) are added with their stages.
 */
public data class DeviceTrustConfig(
    /** Device key in StrongBox (with TEE fallback); default TEE until stage-1 measurements decide (S2 §3, R4). */
    val deviceKeyStrongBox: Boolean = false,
    /** Oldest acceptable `SECURITY_PATCH`, in months (S2 §6.1 п. 3). */
    val maxPatchAgeMonths: Int = 12,
)
