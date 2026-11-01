package io.github.keshavgehlot.nullroute.data

import android.content.Context
import android.content.SharedPreferences
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.time.LocalDate

enum class Upstream(val label: String, val servers: List<String>) {
    SYSTEM("Network default", emptyList()),
    CLOUDFLARE("Cloudflare (1.1.1.1)", listOf("1.1.1.1", "1.0.0.1", "2606:4700:4700::1111")),
    QUAD9("Quad9 (9.9.9.9)", listOf("9.9.9.9", "149.112.112.112", "2620:fe::fe")),
    GOOGLE("Google (8.8.8.8)", listOf("8.8.8.8", "8.8.4.4", "2001:4860:4860::8888")),
}

data class SettingsSnapshot(
    val upstream: Upstream,
    val excludedApps: Set<String>,
    val userBlocked: Set<String>,
    val userAllowed: Set<String>,
    val autoUpdate: Boolean,
    val blockSuspicious: Boolean,
    /** Check unlisted names against phishing/malware feeds via hash-prefix lookups. */
    val reputation: Boolean,
    /** Route all traffic through the tunnel and block by TLS SNI / HTTP Host (more battery). */
    val fullTunnel: Boolean,
    val listsUpdatedAt: Long,
    val listsVersion: String?,
)

/** SharedPreferences-backed settings exposed as a StateFlow for Compose. */
class Settings(context: Context) {
    private val prefs: SharedPreferences = context.getSharedPreferences("nullroute", Context.MODE_PRIVATE)
    private val _state = MutableStateFlow(read())
    val state: StateFlow<SettingsSnapshot> = _state.asStateFlow()
    val current get() = _state.value

    private fun read() = SettingsSnapshot(
        upstream = runCatching { Upstream.valueOf(prefs.getString("upstream", null)!!) }.getOrDefault(Upstream.SYSTEM),
        excludedApps = prefs.getStringSet("excluded_apps", emptySet())!!.toSet(),
        userBlocked = prefs.getStringSet("user_blocked", emptySet())!!.toSet(),
        userAllowed = prefs.getStringSet("user_allowed", emptySet())!!.toSet(),
        autoUpdate = prefs.getBoolean("auto_update", true),
        blockSuspicious = prefs.getBoolean("block_suspicious", false),
        reputation = prefs.getBoolean("reputation", true),
        fullTunnel = prefs.getBoolean("full_tunnel", false),
        listsUpdatedAt = prefs.getLong("lists_updated_at", 0L),
        listsVersion = prefs.getString("lists_version", null),
    )

    private inline fun edit(block: SharedPreferences.Editor.() -> Unit) {
        prefs.edit().apply(block).apply()
        _state.value = read()
    }

    fun setUpstream(u: Upstream) = edit { putString("upstream", u.name) }
    fun setAutoUpdate(on: Boolean) = edit { putBoolean("auto_update", on) }
    fun setBlockSuspicious(on: Boolean) = edit { putBoolean("block_suspicious", on) }
    fun setReputation(on: Boolean) = edit { putBoolean("reputation", on) }
    fun setFullTunnel(on: Boolean) = edit { putBoolean("full_tunnel", on) }
    fun setExcluded(pkg: String, excluded: Boolean) = edit {
        putStringSet("excluded_apps", current.excludedApps.toMutableSet().apply { if (excluded) add(pkg) else remove(pkg) })
    }

    /** Adding a domain to one user list removes it from the other. */
    fun setUserRule(domain: String, rule: UserRule?) = edit {
        val blocked = current.userBlocked.toMutableSet().apply { remove(domain) }
        val allowed = current.userAllowed.toMutableSet().apply { remove(domain) }
        when (rule) {
            UserRule.BLOCK -> blocked.add(domain)
            UserRule.ALLOW -> allowed.add(domain)
            null -> Unit
        }
        putStringSet("user_blocked", blocked)
        putStringSet("user_allowed", allowed)
    }

    fun setListsUpdated(at: Long, version: String?) = edit {
        putLong("lists_updated_at", at)
        putString("lists_version", version)
    }

    // ---- service bookkeeping (not part of the UI snapshot) -------------------
    var vpnWanted: Boolean
        get() = prefs.getBoolean("vpn_wanted", false)
        set(v) = prefs.edit().putBoolean("vpn_wanted", v).apply()

    /** Adds to the persisted counters, resetting "today" at local midnight. */
    fun addBlocked(n: Long) {
        if (n == 0L) return
        val today = LocalDate.now().toEpochDay()
        val sameDay = prefs.getLong("blocked_day", -1) == today
        prefs.edit()
            .putLong("blocked_day", today)
            .putLong("blocked_today", (if (sameDay) prefs.getLong("blocked_today", 0) else 0) + n)
            .putLong("blocked_total", prefs.getLong("blocked_total", 0) + n)
            .apply()
    }

    fun blockedToday(): Long =
        if (prefs.getLong("blocked_day", -1) == LocalDate.now().toEpochDay()) prefs.getLong("blocked_today", 0) else 0

    fun blockedTotal(): Long = prefs.getLong("blocked_total", 0)
}

enum class UserRule { BLOCK, ALLOW }
