package org.wolpmessenger.devicetrust.cert

import android.content.Context
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import org.wolpmessenger.devicetrust.DeviceTrust
import org.wolpmessenger.devicetrust.api.TrustState
import java.util.concurrent.TimeUnit
import kotlin.time.Duration

/**
 * Background renewal (S2 §6.5): periodic, network required, exponential backoff from 30 s.
 * The process may be started just for this — `DeviceTrust.init` runs in `Application.onCreate` (S1).
 */
internal class RenewWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result {
        if (!DeviceTrust.isInitialized) return Result.retry()
        return when (DeviceTrust.ensureFresh()) {
            // still due after the attempt → network/5xx/rate limit: retry with backoff
            is TrustState.RenewalDue, is TrustState.ExpiredGrace -> Result.retry()
            else -> Result.success()
        }
    }

    companion object {
        private const val NAME = "dt.renew"

        fun schedule(context: Context, interval: Duration) {
            val request = PeriodicWorkRequestBuilder<RenewWorker>(interval.inWholeMinutes, TimeUnit.MINUTES)
                .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.SECONDS)
                .build()
            WorkManager.getInstance(context).enqueueUniquePeriodicWork(NAME, ExistingPeriodicWorkPolicy.UPDATE, request)
        }

        fun cancel(context: Context) {
            WorkManager.getInstance(context).cancelUniqueWork(NAME)
        }
    }
}
