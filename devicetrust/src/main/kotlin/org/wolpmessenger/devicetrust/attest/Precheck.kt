package org.wolpmessenger.devicetrust.attest

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.wolpmessenger.devicetrust.InternalDeviceTrustApi
import org.wolpmessenger.devicetrust.api.DeviceSecurityInfo
import org.wolpmessenger.devicetrust.api.DeviceTrustConfig
import org.wolpmessenger.devicetrust.api.PrecheckResult
import org.wolpmessenger.devicetrust.api.RaspFinding
import org.wolpmessenger.devicetrust.api.RaspReaction
import org.wolpmessenger.devicetrust.api.RaspReport
import org.wolpmessenger.devicetrust.api.UnsupportedReason
import org.wolpmessenger.devicetrust.keys.KeyGenResult
import org.wolpmessenger.devicetrust.keys.KeystoreKeys
import java.io.File
import java.time.YearMonth
import java.time.format.DateTimeParseException
import java.time.temporal.ChronoUnit

/** Source of RASP findings (S2 §7): `rasp/RaspEngine` in production. */
@InternalDeviceTrustApi
public fun interface RaspScanner {
    public suspend fun scan(): RaspReport
}

/**
 * Precheck (S2 §6.1), in order:
 * 1. RASP — any BLOCK finding → [PrecheckResult.Compromised];
 * 2. Keystore level of a device-shaped key (`dt.precheck`, generated and deleted at once),
 *    cached per process and per (boot, app version);
 * 3. `SECURITY_PATCH` age;
 * 4. no screen lock → a REPORT finding (`NO_SCREEN_LOCK`, S2 §7.1), not a refusal.
 *
 * Concurrent calls are serialised; the Keystore probe runs at most once per process.
 */
@InternalDeviceTrustApi
public class Precheck internal constructor(
    private val keys: KeystoreKeys,
    private val env: DeviceEnvironment,
    private val cache: PrecheckCache,
    private val rasp: RaspScanner,
    private val config: DeviceTrustConfig,
) {
    private val mutex = Mutex()
    private var memo: CachedKeystoreLevel? = null

    public suspend fun run(): PrecheckResult = mutex.withLock {
        val raspReport = rasp.scan()
        if (raspReport.blocking.isNotEmpty()) return@withLock PrecheckResult.Compromised(raspReport)

        val keystore = withContext(Dispatchers.IO) { keystoreLevel() }
        val screenLock = env.isDeviceSecure()
        val info = DeviceSecurityInfo(
            keystoreLevel = keystore.level,
            strongBoxAvailable = env.hasStrongBox,
            strongBoxFallback = keystore.strongBoxFallback,
            sdkInt = env.sdkInt,
            securityPatch = env.securityPatch,
            screenLockSecure = screenLock,
        )

        val reasons = buildList {
            if (!keystore.level.isHardwareConfirmed) add(UnsupportedReason.SOFTWARE_KEYSTORE)
            if (!patchFresh(env.securityPatch)) add(UnsupportedReason.PATCH_TOO_OLD)
        }
        if (reasons.isNotEmpty()) return@withLock PrecheckResult.Unsupported(reasons, info)

        val reports = raspReport.reports + listOfNotNull(
            if (!screenLock && raspReport.findings.none { it.id == NO_SCREEN_LOCK }) RaspFinding(NO_SCREEN_LOCK, RaspReaction.REPORT) else null,
        )
        PrecheckResult.Supported(info, reports)
    }

    private fun keystoreLevel(): CachedKeystoreLevel {
        memo?.let { return it }
        val cached = cache.load()
        if (cached != null && env.bootCount >= 0 && cached.bootCount == env.bootCount && cached.versionCode == env.versionCode) {
            memo = cached
            return cached
        }
        val measured = try {
            when (val r = keys.generate(KeystoreKeys.PRECHECK_ALIAS, challenge = null, preferStrongBox = config.deviceKeyStrongBox)) {
                is KeyGenResult.Ok -> CachedKeystoreLevel(env.bootCount, env.versionCode, r.key.level, r.key.strongBoxFallback)
                is KeyGenResult.SoftwareKeystore -> CachedKeystoreLevel(env.bootCount, env.versionCode, r.level, false)
            }
        } finally {
            keys.delete(KeystoreKeys.PRECHECK_ALIAS)
        }
        memo = measured
        if (env.bootCount >= 0) runCatching { cache.save(measured) }
        return measured
    }

    /** True if the patch month is within `maxPatchAgeMonths` of today. Unparseable → not fresh. */
    internal fun patchFresh(securityPatch: String): Boolean {
        val patch = try {
            YearMonth.parse(securityPatch.take(7))
        } catch (e: DateTimeParseException) {
            return false
        }
        return ChronoUnit.MONTHS.between(patch, YearMonth.from(env.today())) <= config.maxPatchAgeMonths
    }

    public companion object {
        public const val NO_SCREEN_LOCK: String = "NO_SCREEN_LOCK"

        /** Precheck over the platform Keystore; the cache lives in `noBackupFilesDir/dt/`. */
        public fun android(
            context: Context,
            config: DeviceTrustConfig,
            rasp: RaspScanner = RaspScanner { RaspReport.CLEAN },
        ): Precheck = Precheck(
            keys = KeystoreKeys.android(),
            env = AndroidDeviceEnvironment(context),
            cache = FilePrecheckCache(File(context.noBackupFilesDir, "dt/precheck.properties")),
            rasp = rasp,
            config = config,
        )
    }
}

