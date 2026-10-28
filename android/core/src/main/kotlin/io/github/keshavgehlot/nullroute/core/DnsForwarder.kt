package io.github.keshavgehlot.nullroute.core

import java.io.IOException
import java.io.InputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.util.concurrent.ArrayBlockingQueue
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
    threads: Int = 8,
    queueSize: Int = 256,
) {
    private val pool = ThreadPoolExecutor(
        threads, threads, 30, TimeUnit.SECONDS, ArrayBlockingQueue(queueSize),
    ) { r -> Thread(r, "nullroute-dns").apply { isDaemon = true } }.apply { allowCoreThreadTimeOut(true) }

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
                        val packet = d.reply(buf.copyOf(resp.length)) ?: continue // wrong id
                        writeToTunnel(packet)
                        onEvent(d.event)
                        return
                    }
                }
            } catch (_: SocketTimeoutException) {
                // try the next resolver
            } catch (_: IOException) {
                // network unreachable etc.; try the next resolver
            }
        }
        writeToTunnel(d.failure())
        onEvent(d.event)
    }

    fun shutdown() {
        pool.shutdownNow()
    }
}

/**
 * Reads packets from the tunnel until [stop] is called or the stream closes.
 * Closing the tun file descriptor is what unblocks the read on Android.
 */
class TunnelLoop(
    private val input: InputStream,
    private val processor: DnsPacketProcessor,
    private val handle: (Decision) -> Unit,
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
            handle(processor.process(buf, n))
        }
    }

    fun stop() {
        running.set(false)
    }
}
