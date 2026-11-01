package io.github.keshavgehlot.nullroute.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmap
import io.github.keshavgehlot.nullroute.BuildConfig
import io.github.keshavgehlot.nullroute.core.CompatMode
import io.github.keshavgehlot.nullroute.NullRouteApp
import io.github.keshavgehlot.nullroute.core.DomainMatcher
import io.github.keshavgehlot.nullroute.data.AppInfo
import io.github.keshavgehlot.nullroute.data.ListUpdateWorker
import io.github.keshavgehlot.nullroute.data.Upstream
import io.github.keshavgehlot.nullroute.data.UserRule
import io.github.keshavgehlot.nullroute.vpn.NullRouteVpnService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

private enum class Page { MAIN, APPS, COMPAT_APPS, RULES }

@Composable
fun SettingsScreen(app: NullRouteApp, modifier: Modifier) {
    var page by remember { mutableStateOf(Page.MAIN) }
    BackHandler(enabled = page != Page.MAIN) { page = Page.MAIN }
    when (page) {
        Page.MAIN -> MainSettings(app, modifier) { page = it }
        Page.APPS -> AppPicker(
            app, modifier, "Apps that skip NullRoute",
            "Excluded apps use your normal DNS with no blocking. Changes apply instantly.",
            selected = { it.excludedApps },
            onToggle = { pkg, on -> app.settings.setExcluded(pkg, on); NullRouteVpnService.restart(app) },
        ) { page = Page.MAIN }
        Page.COMPAT_APPS -> AppPicker(
            app, modifier, "Avoid detection in these apps",
            "These apps can load ad loader scripts, so they don't notice the ad blocker. " +
                "Ads and trackers stay blocked for them.",
            selected = { it.compatApps },
            onToggle = { pkg, on -> app.settings.setCompatApp(pkg, on); NullRouteVpnService.reload(app) },
        ) { page = Page.MAIN }
        Page.RULES -> MyRules(app, modifier) { page = Page.MAIN }
    }
}

@Composable
private fun MainSettings(app: NullRouteApp, modifier: Modifier, open: (Page) -> Unit) {
    val s by app.settings.state.collectAsState()
    val context = LocalContext.current
    Column(modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(vertical = 24.dp)) {
        Text("Settings", style = MaterialTheme.typography.headlineMedium, modifier = Modifier.padding(horizontal = 20.dp))

        Section("DNS resolver")
        Text(
            "Where allowed lookups are sent. \"Network default\" uses your Wi-Fi or carrier's resolver.",
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(horizontal = 20.dp),
        )
        Upstream.entries.forEach { u ->
            Row(
                Modifier.fillMaxWidth()
                    .selectable(selected = s.upstream == u, role = Role.RadioButton, onClick = { app.settings.setUpstream(u) })
                    .padding(horizontal = 12.dp, vertical = 2.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                RadioButton(selected = s.upstream == u, onClick = null)
                Spacer(Modifier.width(8.dp))
                Text(u.label)
            }
        }

        Section("Exceptions")
        NavRow("Apps that skip NullRoute", "${s.excludedApps.size} excluded — use for apps that break") { open(Page.APPS) }
        NavRow("My blocked & allowed domains", "${s.userBlocked.size} blocked, ${s.userAllowed.size} allowed") { open(Page.RULES) }

        Section("Ad-blocker detection")
        Text(
            "Some sites and video players refuse to play, or ask you to turn off your ad blocker, when " +
                "their ad loader script is missing. NullRoute can let just those loaders through: the ads " +
                "they'd fetch and all trackers stay blocked.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(horizontal = 20.dp, vertical = 4.dp),
        )
        for ((mode, label) in listOf(
            CompatMode.EVERYWHERE to "Avoid detection everywhere (recommended)",
            CompatMode.SELECTED_APPS to "Only in apps I choose",
            CompatMode.OFF to "Off — block loaders too (strictest)",
        )) {
            Row(
                Modifier.fillMaxWidth()
                    .selectable(selected = s.compatMode == mode, role = Role.RadioButton, onClick = {
                        app.settings.setCompatMode(mode)
                        NullRouteVpnService.reload(context)
                    })
                    .padding(horizontal = 12.dp, vertical = 2.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                RadioButton(selected = s.compatMode == mode, onClick = null)
                Spacer(Modifier.width(8.dp))
                Text(label)
            }
        }
        if (s.compatMode == CompatMode.SELECTED_APPS) {
            NavRow("Choose apps", "${s.compatApps.size} chosen — add your video and streaming apps") { open(Page.COMPAT_APPS) }
        }

        Section("Unlisted domains")
        ToggleRow(
            "Phishing & malware protection",
            "Checks sites against ~2.4 million known phishing, scam and malware domains. Names are " +
                "checked on your phone; only when one looks like a match is a small, anonymous batch of " +
                "hashes downloaded to confirm it — the site you visit is never sent anywhere.",
            s.reputation,
        ) {
            app.settings.setReputation(it)
            NullRouteVpnService.reload(context)
        }
        ToggleRow(
            "Block machine-generated-looking domains",
            "Catches some brand-new malware and tracker domains that aren't on any list yet. " +
                "About 1 in 700 normal sites may be blocked by mistake — tap it in Activity to allow it. " +
                "Suspicious names are always marked in Activity, even with this off.",
            s.blockSuspicious,
        ) {
            app.settings.setBlockSuspicious(it)
            NullRouteVpnService.reload(context)
        }

        Section("Advanced")
        ToggleRow(
            "Inspect all connections",
            "Routes all traffic through NullRoute and blocks connections by the site name inside " +
                "HTTPS (SNI) and HTTP requests. Catches apps that skip system DNS with their own resolver " +
                "or hard-coded IPs. Uses more battery and may slow downloads; QUIC is turned off so " +
                "browsers fall back to inspectable HTTPS.",
            s.fullTunnel,
        ) {
            app.settings.setFullTunnel(it)
            NullRouteVpnService.restart(context)
        }

        Section("Filter lists")
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f)) {
                Text("Update automatically")
                Text("Daily, on Wi-Fi only", style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Switch(checked = s.autoUpdate, onCheckedChange = {
                app.settings.setAutoUpdate(it)
                ListUpdateWorker.schedule(context, it)
            })
        }

        Section("About")
        Text(
            "NullRoute ${BuildConfig.VERSION_NAME}\n\nFilter lists: EasyList and EasyPrivacy (GPLv3 / CC BY-SA 3.0), " +
                "StevenBlack hosts (MIT). Lists are verified by SHA-256 before every update.\n\n" +
                "For protection that survives reboots and app restarts, turn on Always-on VPN for NullRoute in " +
                "Settings › Network & internet › VPN.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(horizontal = 20.dp),
        )
    }
}

@Composable
private fun Section(title: String) {
    Text(
        title, style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(start = 20.dp, end = 20.dp, top = 28.dp, bottom = 8.dp),
    )
}

@Composable
private fun NavRow(title: String, subtitle: String, onClick: () -> Unit) {
    Column(Modifier.fillMaxWidth().clickable(onClick = onClick).padding(horizontal = 20.dp, vertical = 12.dp)) {
        Text(title)
        Text(subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun SubPageHeader(title: String, onBack: () -> Unit) {
    Row(Modifier.padding(start = 4.dp, top = 16.dp, end = 20.dp), verticalAlignment = Alignment.CenterVertically) {
        IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Outlined.ArrowBack, contentDescription = "Back") }
        Text(title, style = MaterialTheme.typography.titleLarge)
    }
}

@Composable
private fun AppPicker(
    app: NullRouteApp,
    modifier: Modifier,
    title: String,
    description: String,
    selected: (io.github.keshavgehlot.nullroute.data.SettingsSnapshot) -> Set<String>,
    onToggle: (String, Boolean) -> Unit,
    onBack: () -> Unit,
) {
    val s by app.settings.state.collectAsState()
    val chosen = selected(s)
    var apps by remember { mutableStateOf<List<AppInfo>?>(null) }
    var query by remember { mutableStateOf("") }
    LaunchedEffect(Unit) { apps = withContext(Dispatchers.IO) { app.apps.launchableApps() } }
    val shown = apps.orEmpty().filter { query.isBlank() || it.label.contains(query, true) || it.packageName.contains(query, true) }
        .sortedByDescending { it.packageName in chosen }

    Column(modifier.fillMaxSize()) {
        SubPageHeader(title, onBack)
        Text(
            description,
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(horizontal = 20.dp),
        )
        OutlinedTextField(
            value = query, onValueChange = { query = it }, singleLine = true, placeholder = { Text("Search apps") },
            modifier = Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 12.dp),
        )
        if (apps == null) Text("Loading apps…", modifier = Modifier.padding(20.dp))
        LazyColumn {
            items(shown, key = { it.packageName }) { a ->
                val on = a.packageName in chosen
                Row(
                    Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    val bitmap = remember(a.packageName) { a.icon?.toBitmap(96, 96)?.asImageBitmap() }
                    if (bitmap != null) Image(bitmap, contentDescription = null, modifier = Modifier.size(36.dp))
                    else Spacer(Modifier.size(36.dp))
                    Column(Modifier.weight(1f).padding(horizontal = 12.dp)) {
                        Text(a.label)
                        Text(a.packageName, style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    Switch(checked = on, onCheckedChange = { onToggle(a.packageName, it) })
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun MyRules(app: NullRouteApp, modifier: Modifier, onBack: () -> Unit) {
    val s by app.settings.state.collectAsState()
    val context = LocalContext.current
    var input by remember { mutableStateOf("") }
    var kind by remember { mutableStateOf(UserRule.BLOCK) }
    var error by remember { mutableStateOf<String?>(null) }
    val rules = s.userBlocked.map { it to UserRule.BLOCK } + s.userAllowed.map { it to UserRule.ALLOW }

    Column(modifier.fillMaxSize()) {
        SubPageHeader("My domains", onBack)
        Column(Modifier.padding(horizontal = 20.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("Your rules win over the filter lists and cover all subdomains.",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                listOf(UserRule.BLOCK to "Block", UserRule.ALLOW to "Allow").forEachIndexed { i, (r, label) ->
                    SegmentedButton(selected = kind == r, onClick = { kind = r },
                        shape = SegmentedButtonDefaults.itemShape(i, 2)) { Text(label) }
                }
            }
            val err = error
            OutlinedTextField(
                value = input, onValueChange = { input = it; error = null }, singleLine = true,
                placeholder = { Text("example.com") }, isError = err != null,
                supportingText = if (err != null) { { Text(err) } } else null,
                modifier = Modifier.fillMaxWidth(),
            )
            Button(onClick = {
                val d = DomainMatcher.normalize(input)
                if (d == null) error = "Enter a domain like ads.example.com"
                else {
                    app.settings.setUserRule(d, kind)
                    NullRouteVpnService.reload(context)
                    input = ""
                }
            }, modifier = Modifier.fillMaxWidth()) { Text(if (kind == UserRule.BLOCK) "Block domain" else "Allow domain") }
        }
        Spacer(Modifier.size(12.dp))
        if (rules.isEmpty()) Text(
            "No rules yet. You can also add them by tapping a lookup on the Activity tab.",
            color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(20.dp),
        )
        LazyColumn {
            items(rules.sortedBy { it.first }, key = { it.first }) { (domain, rule) ->
                Row(Modifier.fillMaxWidth().padding(start = 20.dp, end = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(domain, fontFamily = FontFamily.Monospace)
                        Text(if (rule == UserRule.BLOCK) "Blocked" else "Allowed",
                            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    IconButton(onClick = {
                        app.settings.setUserRule(domain, null)
                        NullRouteVpnService.reload(context)
                    }) { Icon(Icons.Outlined.Close, contentDescription = "Remove $domain") }
                }
                HorizontalDivider(color = MaterialTheme.colorScheme.outline)
            }
        }
    }
}

@Composable
private fun ToggleRow(title: String, body: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(title)
            Text(body, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Spacer(Modifier.width(12.dp))
        Switch(checked = checked, onCheckedChange = onChange)
    }
}
