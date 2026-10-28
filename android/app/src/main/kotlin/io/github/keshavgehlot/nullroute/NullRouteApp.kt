package io.github.keshavgehlot.nullroute

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import io.github.keshavgehlot.nullroute.data.AppResolver
import io.github.keshavgehlot.nullroute.data.BlocklistRepository
import io.github.keshavgehlot.nullroute.data.ListUpdateWorker
import io.github.keshavgehlot.nullroute.data.Settings
import io.github.keshavgehlot.nullroute.core.QueryLog
import kotlinx.coroutines.flow.MutableStateFlow

sealed interface VpnState {
    data object Stopped : VpnState
    data object Starting : VpnState
    data object Running : VpnState
    data class Failed(val message: String) : VpnState
}

/** Process-wide singletons. The VPN service and UI run in the same process. */
class NullRouteApp : Application() {
    lateinit var settings: Settings; private set
    lateinit var lists: BlocklistRepository; private set
    lateinit var apps: AppResolver; private set
    val queryLog = QueryLog(capacity = 500)
    val vpnState = MutableStateFlow<VpnState>(VpnState.Stopped)

    /** Bumped (throttled) whenever the query log changes so Compose can refresh. */
    val logVersion = MutableStateFlow(0L)

    override fun onCreate() {
        super.onCreate()
        settings = Settings(this)
        lists = BlocklistRepository(this, settings)
        apps = AppResolver(this)
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(CHANNEL_STATUS, getString(R.string.channel_status), NotificationManager.IMPORTANCE_LOW).apply {
                description = getString(R.string.channel_status_desc)
                setShowBadge(false)
            }
        )
        ListUpdateWorker.schedule(this, settings.current.autoUpdate)
    }

    companion object {
        const val CHANNEL_STATUS = "status"
        fun from(context: Context) = context.applicationContext as NullRouteApp
    }
}
