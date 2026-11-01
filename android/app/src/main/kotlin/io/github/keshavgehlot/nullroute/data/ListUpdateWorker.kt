package io.github.keshavgehlot.nullroute.data

import android.content.Context
import android.util.Log
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import io.github.keshavgehlot.nullroute.NullRouteApp
import io.github.keshavgehlot.nullroute.vpn.NullRouteVpnService
import java.util.concurrent.TimeUnit

/** Refreshes the lists daily on an unmetered connection (threat feeds change within hours). */
class ListUpdateWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result {
        val app = NullRouteApp.from(applicationContext)
        return try {
            val result = app.lists.update()
            if (result.changed) NullRouteVpnService.reload(applicationContext)
            Result.success()
        } catch (e: Exception) {
            Log.w("ListUpdateWorker", "update failed", e)
            if (runAttemptCount < 3) Result.retry() else Result.failure()
        }
    }

    companion object {
        private const val NAME = "list-update"

        fun schedule(context: Context, enabled: Boolean) {
            val wm = WorkManager.getInstance(context)
            if (!enabled) {
                wm.cancelUniqueWork(NAME)
                return
            }
            val request = PeriodicWorkRequestBuilder<ListUpdateWorker>(1, TimeUnit.DAYS)
                .setConstraints(
                    Constraints.Builder()
                        .setRequiredNetworkType(NetworkType.UNMETERED)
                        .setRequiresBatteryNotLow(true)
                        .build()
                )
                .build()
            wm.enqueueUniquePeriodicWork(NAME, ExistingPeriodicWorkPolicy.UPDATE, request)
        }
    }
}
