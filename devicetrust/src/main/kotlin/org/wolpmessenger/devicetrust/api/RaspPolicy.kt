package org.wolpmessenger.devicetrust.api

/** RASP check ids (S2 §7.1); also the `id` in REPORT/BLOCK messages (S3 §5.7). */
public object RaspCheck {
    public const val ROOT_SU: String = "ROOT_SU"
    public const val ROOT_MAGISK: String = "ROOT_MAGISK"
    public const val ROOT_MANAGER_PKG: String = "ROOT_MANAGER_PKG"
    public const val ROOT_PROPS: String = "ROOT_PROPS"
    public const val HOOK_FRIDA_MAPS: String = "HOOK_FRIDA_MAPS"
    public const val HOOK_FRIDA_PORT: String = "HOOK_FRIDA_PORT"
    public const val HOOK_XPOSED: String = "HOOK_XPOSED"
    public const val HOOK_TAMPER: String = "HOOK_TAMPER"
    public const val DEBUGGER: String = "DEBUGGER"
    public const val APK_SIGNATURE: String = "APK_SIGNATURE"
    public const val APP_DEBUGGABLE: String = "APP_DEBUGGABLE"
    public const val EMULATOR: String = "EMULATOR"
    public const val KEYSTORE_SOFTWARE: String = "KEYSTORE_SOFTWARE"
    public const val DEV_OPTIONS: String = "DEV_OPTIONS"
    public const val ADB_ENABLED: String = "ADB_ENABLED"
    public const val NO_SCREEN_LOCK: String = "NO_SCREEN_LOCK"

    /** Default reactions (S2 §7.1). `HOOK_TAMPER` is REPORT until the pilot data decides (BLOCK only after the pilot). */
    public val DEFAULTS: Map<String, RaspReaction> = mapOf(
        ROOT_SU to RaspReaction.BLOCK,
        ROOT_MAGISK to RaspReaction.BLOCK,
        ROOT_MANAGER_PKG to RaspReaction.REPORT,
        ROOT_PROPS to RaspReaction.BLOCK,
        HOOK_FRIDA_MAPS to RaspReaction.BLOCK,
        HOOK_FRIDA_PORT to RaspReaction.BLOCK,
        HOOK_XPOSED to RaspReaction.BLOCK,
        HOOK_TAMPER to RaspReaction.REPORT,
        DEBUGGER to RaspReaction.BLOCK,
        APK_SIGNATURE to RaspReaction.BLOCK,
        APP_DEBUGGABLE to RaspReaction.BLOCK,
        EMULATOR to RaspReaction.BLOCK,
        KEYSTORE_SOFTWARE to RaspReaction.BLOCK,
        DEV_OPTIONS to RaspReaction.REPORT,
        ADB_ENABLED to RaspReaction.REPORT,
        NO_SCREEN_LOCK to RaspReaction.REPORT,
    )
}

/**
 * Reactions by check id (S2 §7.3). Overrides that **lower** a reaction below its default are
 * ignored at runtime unless the app is debuggable or a pilot build (S2 §7.3); raising always works.
 */
public class RaspPolicy private constructor(public val overrides: Map<String, RaspReaction>) {
    public fun with(id: String, reaction: RaspReaction): RaspPolicy = RaspPolicy(overrides + (id to reaction))

    override fun equals(other: Any?): Boolean = other is RaspPolicy && other.overrides == overrides
    override fun hashCode(): Int = overrides.hashCode()
    override fun toString(): String = "RaspPolicy($overrides)"

    public companion object {
        public fun default(): RaspPolicy = RaspPolicy(emptyMap())
    }
}

/** What kind of build the app says it is (S2 §7.3); the library double-checks at runtime. */
public enum class BuildKind { RELEASE, PILOT, DEBUG }
