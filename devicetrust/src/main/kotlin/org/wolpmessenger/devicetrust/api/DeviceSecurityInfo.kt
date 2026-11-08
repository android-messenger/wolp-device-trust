package org.wolpmessenger.devicetrust.api

/** What the precheck learned about the device (S2 §6.1); safe to log and to show in diagnostics. */
public data class DeviceSecurityInfo(
    /** Level of a device-key-shaped Keystore key (cached per boot and app version). */
    val keystoreLevel: SecurityLevel,
    /** `PackageManager.FEATURE_STRONGBOX_KEYSTORE` is declared. */
    val strongBoxAvailable: Boolean,
    /** StrongBox was requested but generation fell back to TEE (S2 §3). */
    val strongBoxFallback: Boolean,
    val sdkInt: Int,
    /** `Build.VERSION.SECURITY_PATCH`, `YYYY-MM-DD`. */
    val securityPatch: String,
    /** A screen lock (PIN, pattern, password) is set. */
    val screenLockSecure: Boolean,
)
