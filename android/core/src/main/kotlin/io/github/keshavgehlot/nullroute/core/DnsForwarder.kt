package io.github.keshavgehlot.nullroute.core

import java.io.IOException
import java.io.InputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Executes [Decision]s: writes sinkhole answers straight back to the tunnel and
 * relays allowed queries to the real resolver.
 *
 * @param upstreams resolvers to try in order (re-read per query, so network
 *   changes take effect immediately).
 * @param openSocket creates the UDP socket for one upstream exchange. On
 *   Android this calls VpnService.protect() so the query bypasses the tunnel.
 * @param writeToTunnel must be thread-safe; called from worker threads.
 */
class DnsForwarder(
    private val upstreams: () -> List<InetSocketAddress>,
    private val openSocket: () -> DatagramSocket,
    private val writeToTunnel: (ByteArray) -> Unit,
    private val onEvent: (QueryEvent) -> Unit = {},
    private val timeoutMs: Int = 4000,
    /** How long an answer may wait for a pending reputation shard before failing open. */
    private val reputationWaitMs: Long = 2500,
    threads: Int = 8,
    queueSize: Int = 256,
) {
    private val pool = ThreadPoolExecutor(
        threads, threads, 30, TimeUnit.SECONDS, ArrayBlockingQueue(queueSize),
    ) { r -> Thread(r, "nullroute-dns").apply { isDaemon = true } }.apply { allowCoreThreadTimeOut(true) }

    private val reputationPool = Executors.newFixedThreadPool(2) { r ->
        Thread(r, "nullroute-rep").apply { isDaemon = true }
    }

    fun handle(decision: Decision) {
        when (decision) {
            Decision.Drop -> Unit
            is Decision.Respond -> {
                writeToTunnel(decision.packet)
                onEvent(decision.event)
            }
            is Decision.Forward -> try {
                pool.execute { forward(decision) }
            } catch (_: RejectedExecutionException) {
                // Overloaded (or shutting down): fail fast rather than queue forever.
                writeToTunnel(decision.failure())
            }
        }
    }

    private fun forward(d: Decision.Forward) {
        val rep = d.reputationCheck?.let { CompletableFuture.supplyAsync(it, reputationPool) }
        val answer = exchange(d)
        if (rep != null) {
            when (val r = runCatching { rep.get(reputationWaitMs, TimeUnit.MILLISECONDS) }
                .getOrDefault(ReputationChecker.Result.Unavailable)) {
                is ReputationChecker.Result.Listed -> {
                    d.event.verdict = Verdict.BLOCKED_BY_REPUTATION
                    d.event.reputationMatch = r.expression
                    writeToTunnel(d.blocked())
                    onEvent(d.event)
                    return
                }
                ReputationChecker.Result.Unavailable -> d.event.reputationUnavailable = true
                ReputationChecker.Result.Clean -> Unit
            }
        }
        writeToTunnel(answer ?: d.failure())
        onEvent(d.event)
    }

    /** Relays the query; returns the reply packet, or null if every resolver failed. */
    private fun exchange(d: Decision.Forward): ByteArray? {
        for (upstream in upstreams()) {
            try {
                openSocket().use { socket ->
                    socket.soTimeout = timeoutMs
                    socket.send(DatagramPacket(d.query, d.query.size, upstream))
                    val buf = ByteArray(4096)
                    val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs.toLong())
                    while (System.nanoTime() < deadline) {
                        val resp = DatagramPacket(buf, buf.size)
                        socket.receive(resp)
                        if (resp.socketAddress != upstream) continue   // not from our resolver
                        return d.reply(buf.copyOf(resp.length)) ?: continue // wrong id
                    }
                }
            } catch (_: SocketTimeoutException) {
                // try the next resolver
            } catch (_: IOException) {
                // network unreachable etc.; try the next resolver
            }
        }
        return null
    }

    fun shutdown() {
        pool.shutdownNow()
        reputationPool.shutdownNow()
    }
}

/**
 * Reads packets from the tunnel until [stop] is called or the stream closes.
 * Closing the tun file descriptor is what unblocks the read on Android.
 *
 * In full-tunnel mode ([relay] set) every UDP packet to port 53 still goes to
 * the DNS processor; everything else is handed to the TCP/UDP relay.
 */
class TunnelLoop(
    private val input: InputStream,
    private val processor: DnsPacketProcessor,
    private val handle: (Decision) -> Unit,
    private val relay: FlowRelay? = null,
    mtu: Int = 32767,
) {
    private val running = AtomicBoolean(true)
    private val buf = ByteArray(mtu)

    fun run() {
        while (running.get()) {
            val n = try {
                input.read(buf)
            } catch (e: IOException) {
                if (running.get()) throw e else return
            }
            if (n < 0) return
            if (n == 0) continue
            val r = relay
            if (r == null || isDns(buf, n)) handle(processor.process(buf, n)) else r.submit(buf, n)
        }
    }

    fun stop() {
        running.set(false)
    }

    companion object {
        /** UDP to port 53, IPv4 or IPv6 (no extension headers). */
        fun isDns(b: ByteArray, n: Int): Boolean {
            val ip = IpHeader.parse(b, n) ?: return false
            return ip.protocol == IpHeader.PROTO_UDP && ip.end - ip.payloadOffset >= 8 &&
                UdpPacket.u16(b, ip.payloadOffset + 2) == 53
        }
    }
}
