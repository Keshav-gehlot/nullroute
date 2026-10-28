package io.github.keshavgehlot.nullroute.vpn

import android.app.Notification
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.OsConstants
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import io.github.keshavgehlot.nullroute.NullRouteApp
import io.github.keshavgehlot.nullroute.R
import io.github.keshavgehlot.nullroute.VpnState
import io.github.keshavgehlot.nullroute.core.Decision
import io.github.keshavgehlot.nullroute.core.DnsForwarder
import io.github.keshavgehlot.nullroute.core.DnsPacketProcessor
import io.github.keshavgehlot.nullroute.core.QueryEvent
import io.github.keshavgehlot.nullroute.core.TunnelLoop
import io.github.keshavgehlot.nullroute.core.UdpPacket
import io.github.keshavgehlot.nullroute.data.Upstream
import io.github.keshavgehlot.nullroute.ui.MainActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * Local DNS sinkhole built on VpnService.
 *
 * The tunnel routes ONLY two host addresses (a fake IPv4 and IPv6 DNS server)
 * and announces them as the device's DNS servers. All other traffic keeps
 * using the normal network, untouched and at full speed; we only ever see DNS
 * queries. Blocked names get 0.0.0.0 / :: back immediately; everything else is
 * relayed to the real resolver over a socket protected from the tunnel.
 */
class NullRouteVpnService : VpnService() {
    private val app by lazy { NullRouteApp.from(this) }
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val connectivity by lazy { getSystemService(ConnectivityManager::class.java) }

    private var tun: ParcelFileDescriptor? = null
    private var tunOut: FileOutputStream? = null
    private var loop: TunnelLoop? = null
    private var loopThread: Thread? = null
    private var forwarder: DnsForwarder? = null
    private var processor: DnsPacketProcessor? = null

    /** DNS servers of the real (non-VPN) networks, kept fresh by a callback. */
    private val networkDns = ConcurrentHashMap<Network, Pair<Boolean, List<InetAddress>>>()
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private val pendingBlocked = AtomicLong()
    private var foreground = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                app.settings.vpnWanted = false
                shutdown()
                return START_NOT_STICKY
            }
            ACTION_RELOAD -> scope.launch { reloadRules() }
            ACTION_RESTART -> scope.launch {
                runCatching { establish() }.onFailure {
                    Log.e(TAG, "restart failed", it)
                    app.vpnState.value = VpnState.Failed(it.message ?: "Restart failed")
                    shutdown(keepState = true)
                }
            }
            // null action = started by the system (always-on VPN) or our own START
            else -> if (tun == null) scope.launch { start() }
        }
        return START_STICKY
    }

    private suspend fun start() {
        app.vpnState.value = VpnState.Starting
        try {
            app.settings.vpnWanted = true
            app.queryLog.clear()
            trackUnderlyingNetworks()
            processor = DnsPacketProcessor(
                app.lists.matcher(), listOf(VIRTUAL_DNS_V4.address, VIRTUAL_DNS_V6.address),
                dga = app.lists.dgaDetector(), blockSuspicious = app.settings.current.blockSuspicious,
            )
            forwarder = DnsForwarder(
                upstreams = ::upstreams,
                openSocket = { DatagramSocket().also { protect(it) } },
                writeToTunnel = ::writePacket,
                onEvent = ::record,
            )
            establish()
            goForeground()
            startStatsTicker()
            app.vpnState.value = VpnState.Running
        } catch (e: Exception) {
            Log.e(TAG, "start failed", e)
            app.vpnState.value = VpnState.Failed(e.message ?: e.javaClass.simpleName)
            shutdown(keepState = true)
        }
    }

    /** (Re)creates the tun interface; also used to apply excluded-app changes. */
    @Synchronized
    private fun establish() {
        val builder = Builder()
            .setSession(getString(R.string.app_name))
            .setMtu(1500)
            .setBlocking(true)
            .addAddress(TUN_V4, 24)
            .addDnsServer(VIRTUAL_DNS_V4)
            .addRoute(VIRTUAL_DNS_V4, 32)
            .addAddress(TUN_V6, 64)
            .addDnsServer(VIRTUAL_DNS_V6)
            .addRoute(VIRTUAL_DNS_V6, 128)
            .setConfigureIntent(
                PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
            )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) builder.setMetered(false) // follow the real network
        for (pkg in app.settings.current.excludedApps) {
            try {
                builder.addDisallowedApplication(pkg)
            } catch (_: PackageManager.NameNotFoundException) {
                // app was uninstalled; ignore
            }
        }
        val newTun = builder.establish() ?: throw IllegalStateException("VPN permission was revoked")

        // Swap in the new interface, then stop the old reader.
        val oldTun = tun
        val oldLoop = loop
        tun = newTun
        tunOut = FileOutputStream(newTun.fileDescriptor)
        val newLoop = TunnelLoop(FileInputStream(newTun.fileDescriptor), processor!!, ::handle)
        loop = newLoop
        loopThread = Thread({
            try {
                newLoop.run()
            } catch (e: Exception) {
                Log.w(TAG, "tunnel loop ended", e)
            }
        }, "nullroute-tun").apply { start() }
        oldLoop?.stop()
        runCatching { oldTun?.close() }
    }

    private fun writePacket(packet: ByteArray) {
        val out = tunOut ?: return
        synchronized(out) {
            try {
                out.write(packet)
            } catch (e: Exception) {
                Log.w(TAG, "tun write failed", e)
            }
        }
    }

    private fun record(event: QueryEvent) {
        app.queryLog.add(event)
        if (event.verdict.blocked) pendingBlocked.incrementAndGet()
    }

    /** Attribute the query to an app (Android 10+, VPN apps only). */
    private fun attribute(request: UdpPacket, event: QueryEvent) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return
        event.uid = runCatching {
            connectivity.getConnectionOwnerUid(
                OsConstants.IPPROTO_UDP,
                InetSocketAddress(request.sourceAddress, request.sourcePort),
                InetSocketAddress(request.destinationAddress, request.destinationPort),
            )
        }.getOrDefault(-1)
    }

    // Wrap the processor so every decision gets app attribution before execution.
    private fun handle(decision: Decision) {
        when (decision) {
            is Decision.Respond -> attribute(decision.request, decision.event)
            is Decision.Forward -> attribute(decision.request, decision.event)
            Decision.Drop -> Unit
        }
        forwarder?.handle(decision)
    }

    private suspend fun reloadRules() {
        try {
            processor?.matcher = app.lists.matcher()
            processor?.dga = app.lists.dgaDetector()
            processor?.blockSuspicious = app.settings.current.blockSuspicious
        } catch (e: Exception) {
            Log.e(TAG, "reload failed", e)
        }
    }

    // ---- upstream resolvers -------------------------------------------------
    private fun upstreams(): List<InetSocketAddress> {
        val choice = app.settings.current.upstream
        val servers: List<InetAddress> = if (choice == Upstream.SYSTEM) {
            // Prefer Wi-Fi/Ethernet over cellular, IPv4 first for reachability.
            networkDns.values.sortedByDescending { it.first }.flatMap { it.second }
                .filterNot { it.isAnyLocalAddress || it == VIRTUAL_DNS_V4 || it == VIRTUAL_DNS_V6 }
                .sortedBy { if (it is Inet4Address) 0 else 1 }
                .ifEmpty { Upstream.CLOUDFLARE.servers.map(InetAddress::getByName) }
        } else {
            choice.servers.map(InetAddress::getByName)
        }
        return servers.distinct().take(4).map { InetSocketAddress(it, 53) }
    }

    private fun trackUnderlyingNetworks() {
        if (networkCallback != null) return
        // NetworkRequest excludes VPNs by default (NOT_VPN capability), so this
        // only sees the real networks underneath us.
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) {
                val caps = connectivity.getNetworkCapabilities(network)
                val unmetered = caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true ||
                    caps?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true
                networkDns[network] = unmetered to lp.dnsServers
            }

            override fun onLost(network: Network) {
                networkDns.remove(network)
            }
        }
        connectivity.registerNetworkCallback(request, cb)
        networkCallback = cb
    }

    // ---- foreground notification & stats -----------------------------------
    private fun goForeground() {
        val notification = buildNotification()
        // Android 14+ requires a type; VPN apps qualify for systemExempted once the
        // VPN is configured, with specialUse as a fallback on stricter builds.
        val types = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            listOf(ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else listOf(0)
        for (type in types) {
            try {
                ServiceCompat.startForeground(this, NOTIFICATION_ID, notification, type)
                foreground = true
                return
            } catch (e: Exception) {
                Log.w(TAG, "startForeground(type=$type) failed", e)
            }
        }
        // The system keeps a bound VpnService alive regardless; carry on without.
    }

    private fun buildNotification(): Notification {
        val today = app.settings.blockedToday()
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val stop = PendingIntent.getService(this, 1, stopIntent(this), PendingIntent.FLAG_IMMUTABLE)
        return NotificationCompat.Builder(this, NullRouteApp.CHANNEL_STATUS)
            .setSmallIcon(R.drawable.ic_stat_nullroute)
            .setContentTitle(getString(R.string.notif_title))
            .setContentText(resources.getQuantityString(R.plurals.notif_blocked_today, today.toInt(), today))
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setShowWhen(false)
            .setContentIntent(open)
            .addAction(0, getString(R.string.action_turn_off), stop)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .build()
    }

    private fun startStatsTicker() = scope.launch {
        var lastLog = -1L
        while (isActive) {
            delay(1_000)
            val (_, total) = app.queryLog.counts()
            if (total != lastLog) { lastLog = total; app.logVersion.value = total }
            val n = pendingBlocked.getAndSet(0)
            if (n > 0) {
                app.settings.addBlocked(n)
                if (foreground) runCatching {
                    getSystemService(android.app.NotificationManager::class.java).notify(NOTIFICATION_ID, buildNotification())
                }
            }
        }
    }

    // ---- teardown -------------------------------------------------------------
    private fun shutdown(keepState: Boolean = false) {
        loop?.stop()
        runCatching { tun?.close() }
        tun = null
        tunOut = null
        loop = null
        forwarder?.shutdown()
        forwarder = null
        app.settings.addBlocked(pendingBlocked.getAndSet(0))
        networkCallback?.let { runCatching { connectivity.unregisterNetworkCallback(it) } }
        networkCallback = null
        networkDns.clear()
        if (!keepState) app.vpnState.value = VpnState.Stopped
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        foreground = false
        stopSelf()
    }

    override fun onRevoke() {
        // Another VPN took over, or the user revoked permission in Settings.
        app.settings.vpnWanted = false
        shutdown()
    }

    override fun onDestroy() {
        if (tun != null) shutdown()
        scope.cancel()
        super.onDestroy()
    }

    companion object {
        private const val TAG = "NullRouteVpn"
        private const val NOTIFICATION_ID = 1
        const val ACTION_START = "io.github.keshavgehlot.nullroute.START"
        const val ACTION_STOP = "io.github.keshavgehlot.nullroute.STOP"
        const val ACTION_RELOAD = "io.github.keshavgehlot.nullroute.RELOAD"
        const val ACTION_RESTART = "io.github.keshavgehlot.nullroute.RESTART"

        // RFC 1918 / ULA addresses that only exist inside our tunnel.
        private const val TUN_V4 = "10.111.222.1"
        private const val TUN_V6 = "fd00:6e72:6f75:7465::1"
        val VIRTUAL_DNS_V4: InetAddress = InetAddress.getByName("10.111.222.2")
        val VIRTUAL_DNS_V6: InetAddress = InetAddress.getByName("fd00:6e72:6f75:7465::2")

        fun startIntent(c: Context) = Intent(c, NullRouteVpnService::class.java).setAction(ACTION_START)
        fun stopIntent(c: Context) = Intent(c, NullRouteVpnService::class.java).setAction(ACTION_STOP)

        /** Applies changed user rules or a list update without dropping the tunnel. */
        fun reload(c: Context) {
            if (NullRouteApp.from(c).vpnState.value == VpnState.Running) {
                c.startService(Intent(c, NullRouteVpnService::class.java).setAction(ACTION_RELOAD))
            }
        }

        /** Rebuilds the tunnel, e.g. after the excluded-apps list changes. */
        fun restart(c: Context) {
            if (NullRouteApp.from(c).vpnState.value == VpnState.Running) {
                c.startService(Intent(c, NullRouteVpnService::class.java).setAction(ACTION_RESTART))
            }
        }
    }
}
