package io.github.keshavgehlot.nullroute.core

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.SocketChannel
import java.security.SecureRandom
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Userspace TCP/UDP relay for full-tunnel mode.
 *
 * Android's VpnService gives us raw IP packets but no way to send raw packets
 * out, so every TCP connection is terminated here and re-originated from a
 * normal socket that [protect] excludes from the tunnel (the approach NetGuard
 * and other no-root firewalls use). That makes us an endpoint of the app's
 * TCP connection, so we can read the first bytes it sends — the TLS
 * ClientHello or HTTP request — and refuse the connection by server name
 * before any data reaches the server.
 *
 * The TCP side is deliberately small: the tun link is local and loss-free in
 * practice, so it implements in-order delivery, flow control against the
 * app's advertised window, go-back-N retransmission on a timer, and orderly
 * close. No window scaling or SACK is offered, so peers fall back to plain
 * 64 KB windows. Everything runs on one selector thread; no locks.
 *
 * QUIC (UDP 443) is dropped so browsers fall back to TCP, where SNI is visible.
 */
class FlowRelay(
    private val writeToTunnel: (ByteArray) -> Unit,
    /** VpnService.protect for the outgoing sockets; a no-op off Android. */
    private val protectTcp: (Socket) -> Boolean,
    private val protectUdp: (DatagramSocket) -> Boolean,
    /** Returns true if a connection to this server name must be refused. */
    private val isBlocked: (String) -> Boolean,
    private val onBlocked: (ConnectionEvent) -> Unit = {},
    private val inspectPorts: Set<Int> = setOf(80, 443, 853),
    private val dropUdpPorts: Set<Int> = setOf(443),
    private val clock: () -> Long = System::currentTimeMillis,
) {
    class ConnectionEvent(val host: String, val version: Int, val source: ByteArray, val sourcePort: Int,
                          val destination: ByteArray, val destinationPort: Int, val ech: Boolean)

    private val selector: Selector = Selector.open()
    private val inbox = ConcurrentLinkedQueue<ByteArray>()
    private val running = AtomicBoolean(false)
    private var thread: Thread? = null
    private val tcp = HashMap<FlowKey, TcpSession>()
    private val udp = HashMap<FlowKey, UdpFlow>()
    private val random = SecureRandom()
    private val readBuf = ByteBuffer.allocateDirect(65536)
    private var lastTick = 0L

    val tcpSessions: Int get() = tcp.size
    val udpFlows: Int get() = udp.size

    data class FlowKey(val version: Int, val src: InetSocketAddress, val dst: InetSocketAddress)

    fun start() {
        if (!running.compareAndSet(false, true)) return
        thread = Thread(::loop, "nullroute-relay").apply { isDaemon = true; start() }
    }

    fun stop() {
        running.set(false)
        selector.wakeup()
        thread?.join(2000)
        tcp.values.toList().forEach { it.close() }
        udp.values.toList().forEach { runCatching { it.channel.close() } }
        runCatching { selector.close() }
    }

    /** Hands a non-DNS packet from the tun reader thread to the relay thread. */
    fun submit(packet: ByteArray, length: Int) {
        inbox.add(packet.copyOf(length))
        selector.wakeup()
    }

    private fun loop() {
        while (running.get()) {
            try {
                selector.select(100)
                while (true) handlePacket(inbox.poll() ?: break)
                val it = selector.selectedKeys().iterator()
                while (it.hasNext()) {
                    val key = it.next(); it.remove()
                    if (!key.isValid) continue
                    when (val a = key.attachment()) {
                        is TcpSession -> a.onReady(key)
                        is UdpFlow -> a.onReadable()
                    }
                }
                val now = clock()
                if (now - lastTick >= 100) { lastTick = now; tick(now) }
            } catch (e: java.nio.channels.ClosedSelectorException) {
                return
            } catch (e: Exception) {
                // A single bad packet or channel must never take the whole relay down.
            }
        }
    }

    private fun handlePacket(p: ByteArray) {
        val ip = IpHeader.parse(p, p.size) ?: return
        when (ip.protocol) {
            IpHeader.PROTO_TCP -> TcpSegment.parse(p, p.size)?.let(::onTcp)
            IpHeader.PROTO_UDP -> UdpPacket.parse(p, p.size)?.let(::onUdp)
        }
    }

    private fun key(v: Int, src: ByteArray, sp: Int, dst: ByteArray, dp: Int) =
        FlowKey(v, InetSocketAddress(InetAddress.getByAddress(src), sp), InetSocketAddress(InetAddress.getByAddress(dst), dp))

    // ---- TCP --------------------------------------------------------------------------------

    private fun onTcp(s: TcpSegment) {
        val k = key(s.version, s.source, s.sourcePort, s.destination, s.destinationPort)
        val session = tcp[k]
        if (session == null) {
            if (s.has(TcpSegment.RST)) return
            if (s.has(TcpSegment.SYN) && !s.has(TcpSegment.ACK)) {
                if (tcp.size >= MAX_TCP) evictIdle()
                tcp[k] = TcpSession(k, s).also { it.connect() }
            } else {
                // Unknown connection (e.g. after a restart): tell the app to give up.
                val ack = TcpSegment.seqAdd(s.seq, s.payload.size.toLong() + (if (s.has(TcpSegment.FIN)) 1 else 0))
                writeToTunnel(TcpSegment.build(s.version, s.destination, s.source, s.destinationPort, s.sourcePort,
                    if (s.has(TcpSegment.ACK)) s.ack else 0, ack, TcpSegment.RST or TcpSegment.ACK, 0))
            }
            return
        }
        session.onSegment(s)
    }

    private fun evictIdle() {
        tcp.values.minByOrNull { it.lastActivity }?.reset()
    }

    private fun tick(now: Long) {
        for (s in tcp.values.toList()) s.onTimer(now)
        for (f in udp.values.toList()) if (now - f.lastActivity > UDP_IDLE_MS) f.close()
    }

    private enum class State { CONNECTING, SYN_ACK_SENT, ESTABLISHED, CLOSED }

    private inner class TcpSession(val key: FlowKey, syn: TcpSegment) {
        val v = syn.version
        val app = syn.source; val appPort = syn.sourcePort
        val server = syn.destination; val serverPort = syn.destinationPort
        var state = State.CONNECTING
        val channel: SocketChannel = SocketChannel.open()
        var selKey: SelectionKey? = null
        var lastActivity = clock()
        val createdAt = lastActivity

        // receive side (app -> us)
        var rcvNext = TcpSegment.seqAdd(syn.seq, 1)
        val toServer = ByteArrayOutputStream()
        var toServerPos = 0
        var appFin = false
        var outputShut = false

        // send side (us -> app)
        val iss = random.nextInt().toLong() and 0xffffffffL
        var sndUna = iss
        var sndNxt = TcpSegment.seqAdd(iss, 1)
        var appWindow = syn.window
        val mss = minOf(syn.mss ?: 536, if (v == 4) 1460 else 1440)
        var sendBuf = ByteArray(16 * 1024)
        var sendLen = 0                 // bytes from sndUna (not yet acknowledged)
        var serverEof = false
        var finSent = false
        var finAcked = false
        var lastSend = 0L
        var rto = 1000L

        // inspection
        var inspecting = serverPort in inspectPorts
        val hello = ByteArrayOutputStream()

        fun connect() {
            try {
                channel.configureBlocking(false)
                if (!protectTcp(channel.socket())) throw IOException("protect failed")
                channel.connect(InetSocketAddress(InetAddress.getByAddress(server), serverPort))
                selKey = channel.register(selector, SelectionKey.OP_CONNECT, this)
            } catch (e: IOException) {
                reset()
            }
        }

        fun onReady(k: SelectionKey) {
            try {
                if (k.isConnectable && channel.finishConnect()) {
                    k.interestOps(SelectionKey.OP_READ)
                    state = State.SYN_ACK_SENT
                    send(TcpSegment.SYN or TcpSegment.ACK, iss, mss = if (v == 4) 1460 else 1440)
                    return
                }
                if (k.isValid && k.isWritable) flushToServer()
                if (k.isValid && k.isReadable) readFromServer()
            } catch (e: IOException) {
                reset()
            }
        }

        fun onSegment(s: TcpSegment) {
            lastActivity = clock()
            if (s.has(TcpSegment.RST)) { close(); return }
            if (s.has(TcpSegment.SYN)) {
                // retransmitted SYN while we're still connecting/handshaking
                if (state == State.SYN_ACK_SENT) send(TcpSegment.SYN or TcpSegment.ACK, iss, mss = mss)
                return
            }
            if (s.has(TcpSegment.ACK)) onAck(s)
            if (state != State.ESTABLISHED) return
            val len = s.payload.size
            val fin = s.has(TcpSegment.FIN)
            if (len == 0 && !fin) return
            if (s.seq != rcvNext) {
                ackNow()          // duplicate or out of order: re-announce what we expect
                return
            }
            if (len > 0) {
                rcvNext = TcpSegment.seqAdd(rcvNext, len.toLong())
                if (inspecting) inspect(s.payload) else toServer.write(s.payload)
            }
            if (fin) {
                rcvNext = TcpSegment.seqAdd(rcvNext, 1)
                appFin = true
                if (inspecting && state != State.CLOSED) {
                    // The app closed before sending a full ClientHello: nothing to judge, pass it on.
                    inspecting = false
                    toServer.write(hello.toByteArray())
                }
            }
            if (state == State.CLOSED) return
            flushToServer()
            ackNow()
            maybeFinish()
        }

        private fun inspect(data: ByteArray) {
            hello.write(data)
            val bytes = hello.toByteArray()
            // Decide by content, not port: TLS on any inspected port, plain HTTP otherwise.
            val name = TlsSni.parse(bytes).let { if (it == ServerName.None) HttpHost.parse(bytes) else it }
            when (name) {
                ServerName.NeedMore -> if (bytes.size < TlsSni.MAX_HELLO) return
                is ServerName.Found -> if (isBlocked(name.host)) {
                    onBlocked(ConnectionEvent(name.host, v, app, appPort, server, serverPort, name.ech))
                    reset()
                    return
                }
                ServerName.None -> Unit
            }
            inspecting = false
            toServer.write(bytes)
        }

        private fun onAck(s: TcpSegment) {
            appWindow = s.window
            if (state == State.SYN_ACK_SENT && s.ack == TcpSegment.seqAdd(iss, 1)) {
                state = State.ESTABLISHED
                sndUna = s.ack
            }
            val acked = TcpSegment.seqDiff(s.ack, sndUna)
            val outstanding = TcpSegment.seqDiff(sndNxt, sndUna)
            if (acked <= 0 || acked > outstanding) { transmit(); return }
            var dataAcked = acked
            if (finSent && s.ack == sndNxt) { finAcked = true; dataAcked -= 1 }
            dataAcked = minOf(dataAcked, sendLen.toLong())
            if (dataAcked > 0) {
                System.arraycopy(sendBuf, dataAcked.toInt(), sendBuf, 0, sendLen - dataAcked.toInt())
                sendLen -= dataAcked.toInt()
            }
            sndUna = s.ack
            rto = 1000
            lastSend = clock()
            updateInterest()
            transmit()
            maybeFinish()
        }

        private fun flushToServer() {
            val data = toServer.toByteArray()
            if (toServerPos < data.size) {
                val n = channel.write(ByteBuffer.wrap(data, toServerPos, data.size - toServerPos))
                toServerPos += n
                if (toServerPos == data.size) { toServer.reset(); toServerPos = 0 }
            }
            if (appFin && toServer.size() == 0 && !outputShut) {
                outputShut = true
                runCatching { channel.shutdownOutput() }
            }
            updateInterest()
        }

        private fun readFromServer() {
            val space = MAX_SEND_BUF - sendLen
            if (space <= 0) { updateInterest(); return }
            readBuf.clear().limit(minOf(space, readBuf.capacity()))
            val n = channel.read(readBuf)
            if (n < 0) {
                serverEof = true
            } else if (n > 0) {
                if (sendLen + n > sendBuf.size) sendBuf = sendBuf.copyOf(maxOf(sendBuf.size * 2, sendLen + n))
                readBuf.flip()
                readBuf.get(sendBuf, sendLen, n)
                sendLen += n
            }
            lastActivity = clock()
            updateInterest()
            transmit()
        }

        private fun updateInterest() {
            val k = selKey ?: return
            if (!k.isValid || state == State.CONNECTING) return
            var ops = 0
            if (!serverEof && sendLen < MAX_SEND_BUF) ops = ops or SelectionKey.OP_READ
            if (toServer.size() > toServerPos) ops = ops or SelectionKey.OP_WRITE
            k.interestOps(ops)
        }

        /** Sends as much unsent data as the app's window allows, then FIN if the server is done. */
        fun transmit() {
            if (state != State.ESTABLISHED) return
            while (true) {
                val inFlight = dataInFlight()
                val unsent = sendLen - inFlight
                val window = appWindow - inFlight
                if (unsent <= 0 || window <= 0) break
                val n = minOf(unsent, window, mss)
                send(TcpSegment.ACK or TcpSegment.PSH, sndNxt, sendBuf, inFlight, n)
                sndNxt = TcpSegment.seqAdd(sndNxt, n.toLong())
            }
            if (serverEof && !finSent && dataInFlight() == sendLen) {
                send(TcpSegment.FIN or TcpSegment.ACK, sndNxt)
                sndNxt = TcpSegment.seqAdd(sndNxt, 1)
                finSent = true
            }
            maybeFinish()
        }

        /** Data bytes sent but not yet acknowledged (the FIN occupies one sequence number). */
        private fun dataInFlight(): Int =
            TcpSegment.seqDiff(sndNxt, sndUna).toInt() - (if (finSent && !finAcked) 1 else 0)

        fun onTimer(now: Long) {
            when (state) {
                State.CONNECTING -> if (now - createdAt > CONNECT_TIMEOUT_MS) reset()
                State.CLOSED -> Unit
                else -> {
                    if (now - lastActivity > TCP_IDLE_MS) { reset(); return }
                    val outstanding = TcpSegment.seqDiff(sndNxt, sndUna)
                    if (state == State.SYN_ACK_SENT && now - lastSend > rto) {
                        send(TcpSegment.SYN or TcpSegment.ACK, iss, mss = mss)
                        rto = minOf(rto * 2, MAX_RTO)
                    } else if (outstanding > 0 && now - lastSend > rto) {
                        // go-back-N: resend everything from the oldest unacknowledged byte
                        sndNxt = sndUna
                        finSent = false
                        rto = minOf(rto * 2, MAX_RTO)
                        transmit()
                    } else if (outstanding == 0L && sendLen > 0 && appWindow == 0 && now - lastSend > rto) {
                        // zero-window probe: one byte, so the app's ACK reopens the window
                        send(TcpSegment.ACK, sndNxt, sendBuf, 0, 1)
                        rto = minOf(rto * 2, MAX_RTO)
                    }
                }
            }
        }

        private fun maybeFinish() {
            if (appFin && finAcked) close()
        }

        private fun ackNow() = send(TcpSegment.ACK, sndNxt)

        private fun send(flags: Int, seq: Long, data: ByteArray = EMPTY, off: Int = 0, len: Int = 0, mss: Int? = null) {
            val window = maxOf(0, minOf(65535, MAX_TO_SERVER - (toServer.size() - toServerPos)))
            writeToTunnel(TcpSegment.build(v, server, app, serverPort, appPort, seq, rcvNext, flags, window, data, off, len, mss))
            lastSend = clock()
        }

        /** Abort: RST to the app, close the upstream socket. */
        fun reset() {
            if (state != State.CLOSED) {
                writeToTunnel(TcpSegment.build(v, server, app, serverPort, appPort, sndNxt, rcvNext,
                    TcpSegment.RST or TcpSegment.ACK, 0))
            }
            close()
        }

        fun close() {
            state = State.CLOSED
            runCatching { selKey?.cancel() }
            runCatching { channel.close() }
            tcp.remove(key)
        }
    }

    // ---- UDP --------------------------------------------------------------------------------

    private fun onUdp(p: UdpPacket) {
        if (p.destinationPort in dropUdpPorts) return
        val k = key(p.version, p.source, p.sourcePort, p.destination, p.destinationPort)
        val flow = udp[k] ?: run {
            if (udp.size >= MAX_UDP) udp.values.minByOrNull { it.lastActivity }?.close()
            try {
                UdpFlow(k, p).also { udp[k] = it }
            } catch (e: IOException) {
                return
            }
        }
        flow.lastActivity = clock()
        runCatching { flow.channel.write(ByteBuffer.wrap(p.payload)) }
    }

    private inner class UdpFlow(val key: FlowKey, first: UdpPacket) {
        val v = first.version
        val app = first.source; val appPort = first.sourcePort
        val server = first.destination; val serverPort = first.destinationPort
        val channel: DatagramChannel = DatagramChannel.open()
        var lastActivity = clock()

        init {
            channel.configureBlocking(false)
            if (!protectUdp(channel.socket())) { channel.close(); throw IOException("protect failed") }
            channel.connect(InetSocketAddress(InetAddress.getByAddress(server), serverPort))
            channel.register(selector, SelectionKey.OP_READ, this)
        }

        fun onReadable() {
            readBuf.clear()
            val n = try { channel.read(readBuf) } catch (e: IOException) { close(); return }
            if (n <= 0) return
            val data = ByteArray(n)
            readBuf.flip(); readBuf.get(data)
            lastActivity = clock()
            writeToTunnel(UdpPacket.build(v, server, app, serverPort, appPort, data))
        }

        fun close() {
            runCatching { channel.close() }
            udp.remove(key)
        }
    }

    companion object {
        private val EMPTY = ByteArray(0)
        private const val MAX_TCP = 1024
        private const val MAX_UDP = 512
        private const val MAX_SEND_BUF = 256 * 1024
        private const val MAX_TO_SERVER = 64 * 1024
        private const val CONNECT_TIMEOUT_MS = 10_000L
        private const val TCP_IDLE_MS = 10 * 60_000L
        private const val UDP_IDLE_MS = 60_000L
        private const val MAX_RTO = 8_000L
    }
}
