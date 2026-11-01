package io.github.keshavgehlot.nullroute.ui

import android.Manifest
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ListAlt
import androidx.compose.material.icons.outlined.Public
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.core.content.ContextCompat
import io.github.keshavgehlot.nullroute.NullRouteApp
import io.github.keshavgehlot.nullroute.VpnState
import io.github.keshavgehlot.nullroute.vpn.NullRouteVpnService

class MainActivity : ComponentActivity() {
    private val app by lazy { NullRouteApp.from(this) }

    private val vpnConsent = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == RESULT_OK) startVpn()
        else app.vpnState.value = VpnState.Failed("VPN permission is needed to filter DNS")
    }
    private val notificationPermission = registerForActivityResult(ActivityResultContracts.RequestPermission()) { }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        if (intent?.getBooleanExtra(EXTRA_REQUEST_START, false) == true) requestStart()
        setContent {
            NullRouteTheme {
                var tab by rememberSaveable { mutableStateOf(0) }
                Scaffold(
                    bottomBar = {
                        NavigationBar {
                            listOf(
                                Triple("Protection", Icons.Outlined.Shield, 0),
                                Triple("Browse", Icons.Outlined.Public, 1),
                                Triple("Activity", Icons.Outlined.ListAlt, 2),
                                Triple("Settings", Icons.Outlined.Settings, 3),
                            ).forEach { (label, icon, i) ->
                                NavigationBarItem(
                                    selected = tab == i,
                                    onClick = { tab = i },
                                    icon = { Icon(icon, contentDescription = null) },
                                    label = { Text(label) },
                                )
                            }
                        }
                    },
                ) { padding ->
                    val mod = Modifier.padding(padding)
                    when (tab) {
                        0 -> HomeScreen(app, mod, onStart = ::requestStart, onStop = ::stopVpn)
                        1 -> BrowserScreen(app, mod)
                        2 -> ActivityScreen(app, mod)
                        else -> SettingsScreen(app, mod)
                    }
                }
            }
        }
    }

    private fun requestStart() {
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
        val consent = VpnService.prepare(this)
        if (consent != null) vpnConsent.launch(consent) else startVpn()
    }

    private fun startVpn() {
        app.vpnState.value = VpnState.Starting
        startService(NullRouteVpnService.startIntent(this))
    }

    private fun stopVpn() {
        startService(NullRouteVpnService.stopIntent(this))
    }

    companion object {
        const val EXTRA_REQUEST_START = "request_start"
    }
}
