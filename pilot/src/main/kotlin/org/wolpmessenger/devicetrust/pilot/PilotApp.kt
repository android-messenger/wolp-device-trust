package org.wolpmessenger.devicetrust.pilot

import android.app.Application
import android.util.Log
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.launch
import org.wolpmessenger.devicetrust.DeviceTrust
import org.wolpmessenger.devicetrust.api.BuildKind
import org.wolpmessenger.devicetrust.api.DeviceTrustConfig

/**
 * What S1 does in `Application.onCreate` (S2 §4, §12): the RASP parameters come from BuildConfig,
 * i.e. from the flavor checked by `verify<Variant>BuildKind` (S2 §7.3). The gateway URLs are
 * placeholders — this app only exercises RASP and the policy; enrollment is the sample's job.
 */
class PilotApp : Application() {
    override fun onCreate() {
        super.onCreate()
        DeviceTrust.init(this, config())
        // the one collector of the process (events are delivered once, buffered until collected)
        MainScope().launch { DeviceTrust.events.collect { Log.i("DT-PILOT", "event: $it") } }
    }

    companion object {
        fun config() = DeviceTrustConfig(
            enrollBaseUrl = "https://enroll.wolp.invalid",
            appBaseUrl = "https://app.wolp.invalid",
            serverPins = listOf("sha256/" + "A".repeat(43) + "=", "sha256/" + "B".repeat(43) + "="),
            expectedSigningDigests = BuildConfig.EXPECTED_SIGNING_DIGESTS.split(',').filter { it.isNotBlank() },
            buildKind = BuildKind.valueOf(BuildConfig.BUILD_KIND),
            raspDryRun = BuildConfig.RASP_DRY_RUN,
        )
    }
}
