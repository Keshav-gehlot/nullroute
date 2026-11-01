package io.github.keshavgehlot.nullroute.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import io.github.keshavgehlot.nullroute.NullRouteApp
import io.github.keshavgehlot.nullroute.R
import io.github.keshavgehlot.nullroute.VpnState
import io.github.keshavgehlot.nullroute.ui.MainActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

/**
 * Restores protection after a reboot or app update if it was on before.
 * VpnService.prepare() returns null only when consent was already granted,
 * so this never starts a VPN the user didn't approve.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED && intent.action != Intent.ACTION_MY_PACKAGE_REPLACED) return
        val app = NullRouteApp.from(context)
        if (app.settings.vpnWanted && VpnService.prepare(context) == null) {
            // Boot receivers get a short background-start allowance; if the OS
            // still refuses, always-on VPN (Settings > VPN) is the reliable path.
            runCatching { context.startService(NullRouteVpnService.startIntent(context)) }
        }
    }
}

/** Quick Settings tile: one tap to toggle protection. */
class ToggleTileService : TileService() {
    private var job: Job? = null

    override fun onStartListening() {
        val app = NullRouteApp.from(this)
        job = CoroutineScope(Dispatchers.Main).launch {
            app.vpnState.collectLatest { render(it) }
        }
    }

    override fun onStopListening() {
        job?.cancel()
    }

    override fun onClick() {
        val app = NullRouteApp.from(this)
        if (app.vpnState.value == VpnState.Running || app.vpnState.value == VpnState.Starting) {
            startService(NullRouteVpnService.stopIntent(this))
            return
        }
        if (VpnService.prepare(this) == null) {
            startService(NullRouteVpnService.startIntent(this))
        } else {
            // First run: consent dialog needs an activity.
            val intent = Intent(this, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                .putExtra(MainActivity.EXTRA_REQUEST_START, true)
            if (Build.VERSION.SDK_INT >= 34) {
                startActivityAndCollapse(
                    android.app.PendingIntent.getActivity(this, 0, intent, android.app.PendingIntent.FLAG_IMMUTABLE)
                )
            } else {
                startActivityAndCollapseLegacy(intent)
            }
        }
    }

    // Only reached below API 34, where the Intent overload is the supported one.
    @android.annotation.SuppressLint("StartActivityAndCollapseDeprecated")
    @Suppress("DEPRECATION")
    private fun startActivityAndCollapseLegacy(intent: Intent) = startActivityAndCollapse(intent)

    private fun render(state: VpnState) {
        val tile = qsTile ?: return
        tile.state = when (state) {
            VpnState.Running -> Tile.STATE_ACTIVE
            else -> Tile.STATE_INACTIVE
        }
        tile.label = getString(R.string.app_name)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle = getString(if (state == VpnState.Running) R.string.tile_on else R.string.tile_off)
        }
        tile.updateTile()
    }
}
