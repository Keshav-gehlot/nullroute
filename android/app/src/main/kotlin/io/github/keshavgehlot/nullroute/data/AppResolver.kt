package io.github.keshavgehlot.nullroute.data

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import android.os.Process
import java.util.concurrent.ConcurrentHashMap

data class AppInfo(val packageName: String, val label: String, val icon: Drawable?, val system: Boolean)

/** Maps the UIDs reported by the VPN to human-readable app names. */
class AppResolver(private val context: Context) {
    private val pm: PackageManager = context.packageManager
    private val labels = ConcurrentHashMap<Int, String>()

    fun label(uid: Int): String {
        if (uid < 0) return "Unknown app"
        return labels.getOrPut(uid) {
            when {
                uid == Process.SYSTEM_UID || uid == 1051 /* netd/dns */ -> "Android system"
                else -> pm.getPackagesForUid(uid)?.firstOrNull()?.let { pkg ->
                    runCatching { pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString() }.getOrDefault(pkg)
                } ?: "UID $uid"
            }
        }
    }

    /** Launchable apps (visible via the <queries> declaration in the manifest). */
    fun launchableApps(): List<AppInfo> {
        val intent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        return pm.queryIntentActivities(intent, 0)
            .map { it.activityInfo.applicationInfo }
            .distinctBy { it.packageName }
            .filter { it.packageName != context.packageName }
            .map {
                AppInfo(
                    packageName = it.packageName,
                    label = pm.getApplicationLabel(it).toString(),
                    icon = runCatching { pm.getApplicationIcon(it) }.getOrNull(),
                    system = it.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM != 0,
                )
            }
            .sortedBy { it.label.lowercase() }
    }
}
