package org.wolpmessenger.devicetrust.alert

import android.content.Context
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import org.wolpmessenger.devicetrust.DeviceTrust
import org.wolpmessenger.devicetrust.net.GatewayClient
import org.wolpmessenger.devicetrust.net.GatewayResult
import java.time.Duration
import java.time.Instant

/**
 * Delivers `alerts/` to `enroll/v1/device/alert` over the pinned client (S2 §8 п. 7):
 * oldest first; `202` → delete; `400` → delete (it will never be accepted); network, 429, 5xx →
 * stop and retry later. Messages older than 7 days are dropped. An unsigned message waits for a
 * Kratos cookie (read at send time): without a session the gateway has nobody to attribute it to.
 */
internal class AlertSender(
    private val queue: AlertQueue,
    private val alerts: Alerts,
    private val gateway: GatewayClient,
    private val cookie: () -> String?,
    private val now: () -> Instant,
) {
    /** Sends what it can; returns the number of messages still waiting. */
    fun sendAll(): Int {
        alerts.drainReports()
        for (a in queue.list()) {
            if (Duration.between(a.createdAt, now()) > MAX_AGE) {
                queue.remove(a)
                continue
            }
            val c = if (a.sig == null) cookie() ?: continue else null
            when (val r = gateway.alert(a.body(), c)) {
                is GatewayResult.Ok -> queue.remove(a)
                is GatewayResult.Refused -> if (r.error.httpStatus == 400) queue.remove(a) else break
                is GatewayResult.Failed -> break
            }
        }
        return queue.list().size
    }

    internal companion object {
        val MAX_AGE: Duration = Duration.ofDays(7)
    }
}

/** WorkManager job for [AlertSender]; exponential backoff from 30 s while anything is left. */
internal class AlertWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result {
        if (!DeviceTrust.isInitialized) return Result.retry()
        return if (DeviceTrust.sendAlerts() > 0) Result.retry() else Result.success()
    }

    companion object {
        private const val NAME = "dt.alerts"

        fun schedule(context: Context) {
            val request = OneTimeWorkRequestBuilder<AlertWorker>()
                .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, java.util.concurrent.TimeUnit.SECONDS)
                .build()
            // REPLACE: a new message (BLOCK!) must not wait out the backoff of an earlier pass; a pass
            // cut short may resend a message — the gateway deduplicates by SHA-256(payload)
            WorkManager.getInstance(context).enqueueUniqueWork(NAME, ExistingWorkPolicy.REPLACE, request)
        }
    }
}
