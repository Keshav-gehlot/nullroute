package io.github.keshavgehlot.nullroute.ui

import android.content.Intent
import android.provider.Settings as AndroidSettings
import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.keshavgehlot.nullroute.NullRouteApp
import io.github.keshavgehlot.nullroute.VpnState
import io.github.keshavgehlot.nullroute.vpn.NullRouteVpnService
import kotlinx.coroutines.launch
import java.text.DateFormat
import java.text.NumberFormat
import java.util.Date

@Composable
fun HomeScreen(app: NullRouteApp, modifier: Modifier, onStart: () -> Unit, onStop: () -> Unit) {
    val state by app.vpnState.collectAsState()
    val settings by app.settings.state.collectAsState()
    val logVersion by app.logVersion.collectAsState()
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var updateMessage by remember { mutableStateOf<String?>(null) }
    var updating by remember { mutableStateOf(false) }
    val nf = remember { NumberFormat.getIntegerInstance() }

    val running = state == VpnState.Running
    val busy = state == VpnState.Starting
    val dot by animateColorAsState(
        if (running) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.tertiary, label = "dot",
    )

    // Read on each log tick so the counters stay live while the screen is open.
    val blockedToday = remember(logVersion, running) { app.settings.blockedToday() }
    val blockedTotal = remember(logVersion, running) { app.settings.blockedTotal() }
    val (_, sessionQueries) = remember(logVersion) { app.queryLog.counts() }
    val privateDnsMode = remember(running) {
        AndroidSettings.Global.getString(context.contentResolver, "private_dns_mode")
    }

    Column(
        modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp, vertical = 24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("NullRoute", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.SemiBold)

        // ---- the switch -------------------------------------------------------
        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
            Column(Modifier.padding(20.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(Modifier.size(10.dp).clip(CircleShape).background(dot))
                    Spacer(Modifier.width(10.dp))
                    Text(
                        when (state) {
                            VpnState.Running -> "Blocking ads and trackers"
                            VpnState.Starting -> "Starting…"
                            VpnState.Stopped -> "Protection is off"
                            is VpnState.Failed -> "Couldn't start"
                        },
                        style = MaterialTheme.typography.titleMedium,
                    )
                }
                (state as? VpnState.Failed)?.let {
                    Text(it.message, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(top = 6.dp))
                }
                Spacer(Modifier.height(20.dp))
                Text(
                    nf.format(blockedToday),
                    fontSize = 56.sp, fontWeight = FontWeight.Bold, lineHeight = 56.sp,
                    color = if (running) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text("blocked today", color = MaterialTheme.colorScheme.onSurfaceVariant)
                Spacer(Modifier.height(20.dp))
                if (running || busy) {
                    OutlinedButton(onClick = onStop, enabled = !busy, modifier = Modifier.fillMaxWidth()) { Text("Turn off") }
                } else {
                    Button(onClick = onStart, modifier = Modifier.fillMaxWidth()) { Text("Turn on") }
                }
            }
        }

        // ---- warnings that silently defeat DNS filtering ---------------------
        if (privateDnsMode == "hostname") {
            Notice(
                title = "Private DNS is bypassing NullRoute",
                body = "Android sends lookups straight to your Private DNS provider, so nothing can be filtered. " +
                    "Set Private DNS to Off or Automatic.",
                action = "Open network settings",
            ) { context.startActivity(Intent(AndroidSettings.ACTION_WIRELESS_SETTINGS)) }
        }

        // ---- numbers -----------------------------------------------------------
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Stat("All time", nf.format(blockedTotal), Modifier.weight(1f))
            Stat("Lookups this session", nf.format(sessionQueries), Modifier.weight(1f))
        }

        // ---- list freshness -------------------------------------------------------
        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
            Column(Modifier.padding(20.dp)) {
                Text("Blocklist", style = MaterialTheme.typography.titleMedium)
                val updated = if (settings.listsUpdatedAt > 0)
                    "updated " + DateFormat.getDateInstance(DateFormat.MEDIUM).format(Date(settings.listsUpdatedAt))
                else "bundled with this version"
                val count = app.lists.domainCount
                Text(
                    (if (count > 0) "${nf.format(count)} domains, " else "") + updated,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    "EasyList, EasyPrivacy and StevenBlack hosts, compiled for DNS.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 4.dp),
                )
                updateMessage?.let { Text(it, modifier = Modifier.padding(top = 8.dp)) }
                TextButton(
                    enabled = !updating,
                    onClick = {
                        updating = true
                        scope.launch {
                            updateMessage = try {
                                val r = app.lists.update()
                                if (r.changed) {
                                    NullRouteVpnService.reload(context)
                                    "Updated to ${nf.format(r.domains)} domains"
                                } else "Already up to date"
                            } catch (e: Exception) {
                                "Update failed: ${e.message}"
                            }
                            updating = false
                        }
                    },
                    modifier = Modifier.padding(top = 4.dp),
                ) { Text(if (updating) "Checking…" else "Check for updates") }
            }
        }

        Text(
            "Only DNS lookups pass through NullRoute's local VPN. Your other traffic never touches it, " +
                "and nothing leaves your phone except the lookups your apps already make.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Start,
        )
    }
}

@Composable
private fun Stat(label: String, value: String, modifier: Modifier) {
    Card(modifier, colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(Modifier.padding(16.dp)) {
            Text(value, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.SemiBold)
            Text(label, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
fun Notice(title: String, body: String, action: String?, onAction: () -> Unit = {}) {
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.tertiaryContainer)) {
        Column(Modifier.padding(16.dp)) {
            Text(title, style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.onTertiaryContainer)
            Text(body, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onTertiaryContainer,
                modifier = Modifier.padding(top = 4.dp))
            if (action != null) TextButton(onClick = onAction) { Text(action) }
        }
    }
}
