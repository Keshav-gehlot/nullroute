package io.github.keshavgehlot.nullroute.data

import android.content.Context
import io.github.keshavgehlot.nullroute.BuildConfig
import io.github.keshavgehlot.nullroute.core.DomainMatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

/**
 * Provides the domain matcher used by the VPN.
 *
 * Lists ship inside the APK (assets/lists) so blocking works offline from the
 * first launch. Updates are fetched from the project's `lists` branch, which
 * CI rebuilds from EasyList/EasyPrivacy/StevenBlack. Every download is checked
 * against the SHA-256 published in report.json before it replaces the
 * current list, so a truncated or tampered file is never loaded.
 */
class BlocklistRepository(private val context: Context, private val settings: Settings) {
    private val dir = File(context.filesDir, "lists").apply { mkdirs() }
    private val mutex = Mutex()
    private var blocked: Set<String>? = null
    private var allowed: Set<String> = emptySet()
    private var cnameTargets: Set<String> = emptySet()

    val domainCount: Int get() = blocked?.size ?: 0

    suspend fun matcher(): DomainMatcher = mutex.withLock {
        val b = blocked ?: load().also { blocked = it }
        val s = settings.current
        DomainMatcher(b, allowed, s.userBlocked, s.userAllowed, cnameTargets)
    }

    private suspend fun load(): Set<String> = withContext(Dispatchers.IO) {
        allowed = open("allowlist.txt")?.use { DomainMatcher.readList(it.bufferedReader()) } ?: emptySet()
        // Trackers that hide behind CNAME aliases; consulted only for answers' CNAME targets.
        cnameTargets = open("cname_targets.txt")?.use { DomainMatcher.readList(it.bufferedReader()) } ?: emptySet()
        open("blocklist.txt")?.use { DomainMatcher.readList(it.bufferedReader()) }
            ?: throw IOException("No blocklist bundled with the app")
    }

    private fun open(name: String) = File(dir, name).takeIf { it.length() > 0 }?.inputStream()
        ?: runCatching { context.assets.open("lists/$name") }.getOrNull()

    data class UpdateResult(val changed: Boolean, val domains: Int, val version: String)

    /** Downloads newer lists if available. Safe to call from a worker or the UI. */
    suspend fun update(): UpdateResult = withContext(Dispatchers.IO) {
        val base = BuildConfig.LISTS_BASE_URL
        val report = JSONObject(String(fetch(base.removeSuffix("dns/") + "report.json")))
        val version = report.getString("generatedAt")
        val files = report.getJSONObject("files")
        if (version == settings.current.listsVersion && File(dir, "blocklist.txt").exists()) {
            return@withContext UpdateResult(false, domainCount, version)
        }
        for (name in listOf("blocklist.txt", "allowlist.txt", "cname_targets.txt")) {
            val expected = files.optString("dns/$name").ifEmpty { null } ?: continue
            val bytes = fetch(base + name)
            val actual = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
            if (!actual.equals(expected, ignoreCase = true)) throw IOException("Checksum mismatch for $name")
            val tmp = File(dir, "$name.tmp")
            tmp.writeBytes(bytes)
            if (name == "blocklist.txt") {
                val count = tmp.bufferedReader().use { DomainMatcher.readList(it).size }
                if (count < 10_000) throw IOException("Downloaded list looks incomplete ($count domains)")
            }
            if (!tmp.renameTo(File(dir, name))) throw IOException("Could not save $name")
        }
        mutex.withLock { blocked = null }
        val count = matcher().size
        settings.setListsUpdated(System.currentTimeMillis(), version)
        UpdateResult(true, count, version)
    }

    private fun fetch(url: String): ByteArray {
        val conn = URL(url).openConnection() as HttpURLConnection
        conn.connectTimeout = 15_000
        conn.readTimeout = 30_000
        conn.setRequestProperty("User-Agent", "NullRoute-Android/${BuildConfig.VERSION_NAME}")
        try {
            if (conn.responseCode != 200) throw IOException("HTTP ${conn.responseCode} for $url")
            return conn.inputStream.use { it.readBytes() }
        } finally {
            conn.disconnect()
        }
    }
}
