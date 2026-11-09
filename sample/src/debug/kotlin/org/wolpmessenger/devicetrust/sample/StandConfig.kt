package org.wolpmessenger.devicetrust.sample

import org.wolpmessenger.devicetrust.api.BuildKind
import org.wolpmessenger.devicetrust.api.DeviceTrustConfig
import org.wolpmessenger.devicetrust.api.RaspCheck
import org.wolpmessenger.devicetrust.api.RaspPolicy
import org.wolpmessenger.devicetrust.api.RaspReaction

/**
 * Stand configuration of the debug sample: a debuggable APK would otherwise block itself on the
 * first RASP pass (APP_DEBUGGABLE; DEBUGGER when Android Studio attaches). Lowering works only
 * because the app is debuggable (S2 §7.3) — in a release build these overrides are ignored.
 */
internal fun standConfig(enrollUrl: String, appUrl: String, pins: List<String>, cookie: String) = DeviceTrustConfig(
    enrollBaseUrl = enrollUrl,
    appBaseUrl = appUrl,
    serverPins = pins,
    cookieProvider = { cookie },
    buildKind = BuildKind.DEBUG,
    raspPolicy = RaspPolicy.default()
        .with(RaspCheck.APP_DEBUGGABLE, RaspReaction.REPORT)
        .with(RaspCheck.DEBUGGER, RaspReaction.REPORT),
)
