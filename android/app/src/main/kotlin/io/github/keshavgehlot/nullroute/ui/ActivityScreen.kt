package io.github.keshavgehlot.nullroute.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.github.keshavgehlot.nullroute.NullRouteApp
import io.github.keshavgehlot.nullroute.core.DnsQuery
import io.github.keshavgehlot.nullroute.core.QueryEvent
import io.github.keshavgehlot.nullroute.core.Verdict
import io.github.keshavgehlot.nullroute.data.UserRule
import io.github.keshavgehlot.nullroute.vpn.NullRouteVpnService
import java.text.DateFormat
import java.util.Date

private enum class Filter(val label: String) { ALL("All"), BLOCKED("Blocked"), ALLOWED("Allowed") }

@Composable
fun ActivityScreen(app: NullRouteApp, modifier: Modifier) {
    val version by app.logVersion.collectAsState()
    val settings by app.settings.state.collectAsState()
    var filter by remember { mutableStateOf(Filter.ALL) }
    var selected by remember { mutableStateOf<QueryEvent?>(null) }
    val context = LocalContext.current
    val events = remember(version, filter) {
        app.queryLog.snapshot().filter {
            when (filter) {
                Filter.ALL -> true
                Filter.BLOCKED -> it.verdict.blocked
                Filter.ALLOWED -> !it.verdict.blocked
            }
        }
    }
    val blockedColor = if (isSystemInDarkTheme()) BlockedColorDark else BlockedColorLight
    val timeFormat = remember { DateFormat.getTimeInstance(DateFormat.MEDIUM) }

    Column(modifier.fillMaxSize()) {
        Column(Modifier.padding(start = 20.dp, end = 20.dp, top = 24.dp)) {
            Text("Activity", style = MaterialTheme.typography.headlineMedium)
            Text(
                "Recent lookups from your apps. Kept in memory only, never written to storage, and cleared each time protection starts.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 4.dp),
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(vertical = 12.dp)) {
                Filter.entries.forEach { f ->
                    FilterChip(selected = filter == f, onClick = { filter = f }, label = { Text(f.label) })
                }
            }
        }
        if (events.isEmpty()) {
            Text(
                "Nothing yet. Turn protection on and use your phone — lookups will appear here.",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(20.dp),
            )
        }
        LazyColumn(Modifier.fillMaxSize()) {
            // No stable key: identical lookups can repeat within the same millisecond.
            items(events) { e ->
                Row(
                    Modifier.fillMaxWidth().clickable { selected = e }.padding(horizontal = 20.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(Modifier.weight(1f)) {
                        Text(
                            e.name, fontFamily = FontFamily.Monospace, maxLines = 1, overflow = TextOverflow.Ellipsis,
                            color = if (e.verdict.blocked) blockedColor else MaterialTheme.colorScheme.onSurface,
                        )
                        Text(
                            "${app.apps.label(e.uid)} · ${DnsQuery.typeName(e.type)} · ${timeFormat.format(Date(e.timeMillis))}",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1, overflow = TextOverflow.Ellipsis,
                        )
                    }
                    Text(
                        if (e.suspicious) "Suspicious" else verdictLabel(e.verdict),
                        style = MaterialTheme.typography.labelMedium,
                        color = if (e.verdict.blocked || e.suspicious) blockedColor else MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                HorizontalDivider(color = MaterialTheme.colorScheme.outline)
            }
        }
    }

    selected?.let { e ->
        val domain = e.name
        val rule = when (domain) {
            in settings.userAllowed -> UserRule.ALLOW
            in settings.userBlocked -> UserRule.BLOCK
            else -> null
        }
        AlertDialog(
            onDismissRequest = { selected = null },
            title = { Text(domain, fontFamily = FontFamily.Monospace) },
            text = {
                Text(
                    when (e.verdict) {
                        Verdict.BLOCKED_BY_LIST -> "Blocked by a filter list. Allow it if an app or site is broken."
                        Verdict.BLOCKED_BY_USER -> "Blocked by your own rule."
                        Verdict.ALLOWED_BY_USER -> "Allowed by your own rule."
                        Verdict.ALLOWED_BY_LIST -> "Explicitly allowed by a filter list."
                        Verdict.ALLOWED -> "Not on any blocklist."
                        Verdict.BLOCKED_BY_CNAME ->
                            "This looks like part of the site, but it secretly points to the tracker " +
                                "${e.cnameTarget ?: "a tracker"} (CNAME cloaking). Allow it if the site breaks."
                        Verdict.BLOCKED_BY_HEURISTIC ->
                            "This name is on no list, but it looks machine-generated — a pattern used by " +
                                "malware and throwaway tracking domains. You turned on blocking for these."
                        Verdict.BLOCKED_BY_REPUTATION ->
                            "${e.reputationMatch ?: "This domain"} is on a phishing, scam or malware feed " +
                                "(HaGeZi Threat Intelligence / Phishing.Database). Only allow it if you're sure it's safe."
                        Verdict.BLOCKED_BY_SNI ->
                            "An app connected to this site without a normal DNS lookup (its own resolver or a " +
                                "hard-coded address). NullRoute read the site name from the connection and blocked it."
                        Verdict.ALLOWED_FOR_COMPAT ->
                            "This is an ad loader that sites and video players check for to detect ad blockers, so " +
                                "NullRoute let it through. The ads it would fetch are still blocked. " +
                                "Change this under Settings › Ad-blocker detection."
                        Verdict.DOH_CANARY ->
                            "Firefox checks this name to decide whether to bypass system DNS. " +
                                "NullRoute answers \"doesn't exist\" so Firefox stays filtered."
                    } + (if (e.suspicious) " Its name looks machine-generated, a pattern used by malware " +
                        "and throwaway tracking domains, so it's worth a second look." else "") +
                        " Requested by ${app.apps.label(e.uid)}."
                )
            },
            confirmButton = {
                val next = if (e.verdict.blocked) UserRule.ALLOW else UserRule.BLOCK
                TextButton(onClick = {
                    app.settings.setUserRule(domain, if (rule == next) null else next)
                    NullRouteVpnService.reload(context)
                    selected = null
                }) { Text(if (next == UserRule.ALLOW) "Always allow" else "Always block") }
            },
            dismissButton = {
                if (rule != null) TextButton(onClick = {
                    app.settings.setUserRule(domain, null)
                    NullRouteVpnService.reload(context)
                    selected = null
                }) { Text("Remove my rule") }
                else TextButton(onClick = { selected = null }) { Text("Close") }
            },
        )
    }
}

private fun verdictLabel(v: Verdict) = when (v) {
    Verdict.BLOCKED_BY_LIST -> "Blocked"
    Verdict.BLOCKED_BY_CNAME -> "Blocked (cloaked)"
    Verdict.DOH_CANARY -> "DoH check"
    Verdict.BLOCKED_BY_HEURISTIC -> "Blocked (generated)"
    Verdict.BLOCKED_BY_USER -> "Blocked (you)"
    Verdict.BLOCKED_BY_REPUTATION -> "Blocked (dangerous)"
    Verdict.BLOCKED_BY_SNI -> "Blocked (connection)"
    Verdict.ALLOWED_FOR_COMPAT -> "Allowed (anti-detection)"
    Verdict.ALLOWED_BY_USER -> "Allowed (you)"
    Verdict.ALLOWED_BY_LIST, Verdict.ALLOWED -> "Allowed"
}
