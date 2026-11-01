package io.github.keshavgehlot.nullroute.core

import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.ByteBuffer
import java.util.Collections
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngineResult
import kotlin.random.Random
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** A real TLS ClientHello from the JDK's own TLS stack, independent of our parser. */
internal fun clientHello(host: String): ByteArray {
    val engine = SSLContext.getInstance("TLS").apply { init(null, null, null) }.createSSLEngine(host, 443)
    engine.useClientMode = true
    engine.sslParameters = engine.sslParameters.apply { serverNames = listOf(SNIHostName(host)) }
    val out = ByteBuffer.allocate(engine.session.packetBufferSize)
    engine.beginHandshake()
    val r = engine.wrap(ByteBuffer.allocate(0), out)
    check(r.status == SSLEngineResult.Status.OK)
    out.flip()
    return ByteArray(out.remaining()).also { out.get(it) }
}

class TlsSniTest {
    @Test
    fun readsSniFromRealClientHelloAtEverySplitPoint() {
        val hello = clientHello("ads.example.com")
        assertEquals(ServerName.Found("ads.example.com"), TlsSni.parse(hello))
        for (cut in 0 until hello.size) assertEquals(ServerName.NeedMore, TlsSni.parse(hello, cut), "cut at $cut")
    }

    @Test
    fun clientHelloSplitAcrossTwoTlsRecords() {
        val hello = clientHello("tracker.example.net")
        val body = hello.copyOfRange(5, hello.size)
        val half = body.size / 2
        fun record(part: ByteArray) = byteArrayOf(22, 3, 1, (part.size ushr 8).toByte(), part.size.toByte()) + part
        val twoRecords = record(body.copyOfRange(0, half)) + record(body.copyOfRange(half, body.size))
        assertEquals(ServerName.Found("tracker.example.net"), TlsSni.parse(twoRecords))
    }

    @Test
    fun echAndNonTls() {
        // Minimal ClientHello with server_name=public.example and an ECH (0xfe0d) extension.
        val sni = "public.example".toByteArray()
        val sniExt = byteArrayOf(0, 0) + u16(sni.size + 5) + u16(sni.size + 3) + byteArrayOf(0) + u16(sni.size) + sni
        val echExt = byteArrayOf(0xfe.toByte(), 0x0d) + u16(4) + byteArrayOf(0, 1, 2, 3)
        val exts = sniExt + echExt
        val body = byteArrayOf(3, 3) + ByteArray(32) + byteArrayOf(0) + u16(2) + byteArrayOf(0x13, 0x01) +
            byteArrayOf(1, 0) + u16(exts.size) + exts
        val hs = byteArrayOf(1, 0) + u16(body.size) + body
        val rec = byteArrayOf(22, 3, 1) + u16(hs.size) + hs
        assertEquals(ServerName.Found("public.example", ech = true), TlsSni.parse(rec))
        assertEquals(ServerName.None, TlsSni.parse("SSH-2.0-OpenSSH_9.6\r\n".toByteArray()))
        assertEquals(ServerName.None, TlsSni.parse(byteArrayOf(23, 3, 3, 0, 5, 1, 2, 3, 4, 5)))
    }

    @Test
    fun httpHostHeader() {
        val req = "GET /pixel.gif HTTP/1.1\r\nUser-Agent: x\r\nHost: Pixel.Tracker.COM:8080\r\n\r\n".toByteArray()
        assertEquals(ServerName.Found("pixel.tracker.com"), HttpHost.parse(req))
        assertEquals(ServerName.NeedMore, HttpHost.parse(req, 30))
        assertEquals(ServerName.NeedMore, HttpHost.parse("GE".toByteArray()))
        assertEquals(ServerName.None, HttpHost.parse("\u0016\u0003\u0001".toByteArray()))
        assertEquals(ServerName.None, HttpHost.parse("GET / HTTP/1.0\r\n\r\n".toByteArray()))
    }

    private fun u16(v: Int) = byteArrayOf((v ushr 8).toByte(), v.toByte())
}

/**
 * Drives the relay with a minimal TCP client written against the packet
 * format (standing in for an Android app behind the tun device) and real
 * sockets on the other side.
 */
class FlowRelayTest {
    private val appIp = byteArrayOf(10, 111, 222.toByte(), 1)
    private val loop = InetAddress.getLoopbackAddress().address
    private val fromRelay = LinkedBlockingQueue<ByteArray>()
    private val blockedEvents = Collections.synchronizedList(mutableListOf<FlowRelay.ConnectionEvent>())

    private fun relay(blocked: Set<String> = emptySet(), inspect: Set<Int>, dropUdp: Set<Int> = emptySet()) =
        FlowRelay({ fromRelay.add(it) }, { true }, { true }, { it in blocked }, { blockedEvents.add(it) },
            inspectPorts = inspect, dropUdpPorts = dropUdp).also { it.start() }

    /** The app side of one connection. */
    private inner class App(val relay: FlowRelay, val serverPort: Int, val appPort: Int = 40000 + Random.nextInt(20000)) {
        var seq = Random.nextLong(0, 0xffffffffL)
        var rcvNext = 0L
        val received = ByteArrayOutputStream()
        var finReceived = false
        var window = 65535

        fun send(flags: Int, data: ByteArray = ByteArray(0)) {
            val p = TcpSegment.build(4, appIp, loop, appPort, serverPort, seq, rcvNext, flags, window, data,
                mss = if (flags and TcpSegment.SYN != 0) 1460 else null)
            relay.submit(p, p.size)
            seq = TcpSegment.seqAdd(seq, data.size.toLong() + (if (flags and (TcpSegment.SYN or TcpSegment.FIN) != 0) 1 else 0))
        }

        fun next(timeoutMs: Long = 5000): TcpSegment? {
            while (true) {
                val p = fromRelay.poll(timeoutMs, TimeUnit.MILLISECONDS) ?: return null
                val s = TcpSegment.parse(p, p.size) ?: continue
                if (s.destinationPort != appPort) { fromRelay.add(p); continue }
                // every segment from the relay must carry a valid checksum
                assertEquals(0, Checksum.transport(6, s.source, s.destination, p, 20, p.size - 20), "bad TCP checksum")
                return s
            }
        }

        fun handshake() {
            send(TcpSegment.SYN)
            val synAck = assertNotNull(next(), "no SYN-ACK")
            assertTrue(synAck.has(TcpSegment.SYN) && synAck.has(TcpSegment.ACK))
            assertEquals(seq, synAck.ack)
            assertNotNull(synAck.mss)
            rcvNext = TcpSegment.seqAdd(synAck.seq, 1)
            send(TcpSegment.ACK)
        }

        /** Reads until [n] bytes or FIN, ACKing in order like a real stack. Drops the first data segment if asked. */
        fun receive(n: Int, dropFirst: Boolean = false): Boolean {
            var dropped = !dropFirst
            while (received.size() < n && !finReceived) {
                val s = next() ?: return false
                if (s.has(TcpSegment.RST)) return false
                if (s.payload.isEmpty() && !s.has(TcpSegment.FIN)) continue
                if (!dropped && s.payload.isNotEmpty()) { dropped = true; continue }
                if (s.seq == rcvNext) {
                    received.write(s.payload)
                    rcvNext = TcpSegment.seqAdd(rcvNext, s.payload.size.toLong())
                    if (s.has(TcpSegment.FIN)) { rcvNext = TcpSegment.seqAdd(rcvNext, 1); finReceived = true }
                }
                send(TcpSegment.ACK)
            }
            return true
        }
    }

    @Test
    fun relaysAllowedTlsConnectionBothWaysAndClosesCleanly() {
        val server = ServerSocket(0, 50, InetAddress.getLoopbackAddress())
        val response = ByteArray(300_000) { (it * 31).toByte() }   // > 4 windows: exercises flow control
        var serverGot = ByteArray(0)
        val hello = clientHello("www.wikipedia.org")
        val t = Thread {
            server.accept().use { c ->
                serverGot = c.getInputStream().readNBytes(hello.size)
                c.getOutputStream().write(response)
                c.shutdownOutput()
                c.getInputStream().read()   // wait for the app's FIN
            }
        }.apply { start() }
        val r = relay(inspect = setOf(server.localPort))
        val app = App(r, server.localPort)
        app.handshake()
        // ClientHello split across two segments, as large post-quantum hellos are
        app.send(TcpSegment.ACK or TcpSegment.PSH, hello.copyOfRange(0, 100))
        app.send(TcpSegment.ACK or TcpSegment.PSH, hello.copyOfRange(100, hello.size))
        assertTrue(app.receive(response.size + 1))
        assertContentEquals(response, app.received.toByteArray())
        assertTrue(app.finReceived)
        app.send(TcpSegment.FIN or TcpSegment.ACK)
        t.join(5000)
        assertContentEquals(hello, serverGot, "server must receive the exact ClientHello bytes")
        Thread.sleep(300)
        assertEquals(0, r.tcpSessions, "session must be cleaned up after both FINs")
        r.stop(); server.close()
        assertTrue(blockedEvents.isEmpty())
    }

    @Test
    fun blockedSniGetsResetAndServerSeesNoData() {
        val server = ServerSocket(0, 50, InetAddress.getLoopbackAddress())
        var serverRead = -2
        val t = Thread { server.accept().use { c -> serverRead = c.getInputStream().read() } }.apply { start() }
        val r = relay(blocked = setOf("ads.doubleclick.net"), inspect = setOf(server.localPort))
        val app = App(r, server.localPort)
        app.handshake()
        app.send(TcpSegment.ACK or TcpSegment.PSH, clientHello("ads.doubleclick.net"))
        var rst: TcpSegment? = null
        while (rst == null) { val s = assertNotNull(app.next(), "no RST"); if (s.has(TcpSegment.RST)) rst = s }
        t.join(5000)
        assertEquals(-1, serverRead, "the server must see EOF, never the ClientHello")
        assertEquals("ads.doubleclick.net", blockedEvents.single().host)
        assertEquals(0, r.tcpSessions)
        r.stop(); server.close()
    }

    @Test
    fun blockedHttpHostAndAllowedPlainHttp() {
        val server = ServerSocket(0, 50, InetAddress.getLoopbackAddress())
        val got = Collections.synchronizedList(mutableListOf<String>())
        Thread {
            repeat(2) {
                runCatching {
                    server.accept().use { c ->
                        val b = ByteArray(4096); val n = c.getInputStream().read(b)
                        got.add(if (n < 0) "EOF" else String(b, 0, n))
                    }
                }
            }
        }.apply { isDaemon = true; start() }
        val r = relay(blocked = setOf("pixel.tracker.com"), inspect = setOf(server.localPort))
        val bad = App(r, server.localPort)
        bad.handshake()
        bad.send(TcpSegment.ACK or TcpSegment.PSH, "GET /p.gif HTTP/1.1\r\nHost: pixel.tracker.com\r\n\r\n".toByteArray())
        var s = assertNotNull(bad.next()); while (!s.has(TcpSegment.RST)) s = assertNotNull(bad.next())
        val good = App(r, server.localPort)
        good.handshake()
        val req = "GET / HTTP/1.1\r\nHost: example.org\r\n\r\n"
        good.send(TcpSegment.ACK or TcpSegment.PSH, req.toByteArray())
        val deadline = System.currentTimeMillis() + 5000
        while (got.size < 2 && System.currentTimeMillis() < deadline) Thread.sleep(20)
        assertEquals(listOf("EOF", req), got)
        assertEquals("pixel.tracker.com", blockedEvents.single().host)
        r.stop(); server.close()
    }

    @Test
    fun retransmitsWhenTheAppMissesASegment() {
        val server = ServerSocket(0, 50, InetAddress.getLoopbackAddress())
        val payload = ByteArray(5000) { it.toByte() }
        Thread { server.accept().use { c -> c.getInputStream().readNBytes(5); c.getOutputStream().write(payload); c.getInputStream().read() } }
            .apply { isDaemon = true; start() }
        val r = relay(inspect = emptySet())
        val app = App(r, server.localPort)
        app.handshake()
        app.send(TcpSegment.ACK or TcpSegment.PSH, "hello".toByteArray())
        assertTrue(app.receive(payload.size, dropFirst = true))
        assertContentEquals(payload, app.received.toByteArray().copyOf(payload.size))
        r.stop(); server.close()
    }

    @Test
    fun refusedConnectionIsReset() {
        val closedPort = ServerSocket(0).let { val p = it.localPort; it.close(); p }
        val r = relay(inspect = emptySet())
        val app = App(r, closedPort)
        app.send(TcpSegment.SYN)
        val s = assertNotNull(app.next())
        assertTrue(s.has(TcpSegment.RST))
        r.stop()
    }

    @Test
    fun unknownConnectionIsReset() {
        val r = relay(inspect = emptySet())
        val app = App(r, 9)
        app.send(TcpSegment.ACK, "stray".toByteArray())
        assertTrue(assertNotNull(app.next()).has(TcpSegment.RST))
        r.stop()
    }

    @Test
    fun relaysUdpAndDropsQuic() {
        val echo = DatagramSocket(0, InetAddress.getLoopbackAddress())
        Thread {
            val buf = ByteArray(1500)
            while (!echo.isClosed) {
                val p = DatagramPacket(buf, buf.size)
                try { echo.receive(p) } catch (_: Exception) { return@Thread }
                echo.send(DatagramPacket(("re:" + String(buf, 0, p.length)).toByteArray(), 3 + p.length, p.socketAddress))
            }
        }.apply { isDaemon = true; start() }
        val r = relay(inspect = emptySet(), dropUdp = setOf(443))
        val pkt = UdpPacket.build(4, appIp, loop, 50000, echo.localPort, "ping".toByteArray())
        r.submit(pkt, pkt.size)
        val reply = UdpPacket.parse(assertNotNull(fromRelay.poll(5, TimeUnit.SECONDS)))!!
        assertEquals("re:ping", String(reply.payload))
        assertContentEquals(loop, reply.source)
        assertEquals(echo.localPort, reply.sourcePort)
        assertEquals(50000, reply.destinationPort)
        val quic = UdpPacket.build(4, appIp, loop, 50001, 443, ByteArray(1200))
        r.submit(quic, quic.size)
        assertNull(fromRelay.poll(500, TimeUnit.MILLISECONDS), "QUIC must be dropped")
        assertEquals(1, r.udpFlows)
        r.stop(); echo.close()
    }

    @Test
    fun parsesSegmentsBuiltByOurselvesIncludingIpv6() {
        val v6a = InetAddress.getByName("fd00::1").address
        val v6b = InetAddress.getByName("2001:db8::2").address
        val p = TcpSegment.build(6, v6a, v6b, 1234, 443, 0xfffffff0L, 7, TcpSegment.SYN, 65535, mss = 1440)
        val s = assertIs<TcpSegment>(TcpSegment.parse(p, p.size))
        assertEquals(0xfffffff0L, s.seq); assertEquals(1440, s.mss); assertEquals(443, s.destinationPort)
        assertEquals(0, Checksum.transport(6, v6a, v6b, p, 40, p.size - 40))
        assertEquals(0x10L, TcpSegment.seqAdd(0xfffffff0L, 0x20))
        assertEquals(0x20L, TcpSegment.seqDiff(0x10L, 0xfffffff0L))
    }

    @Suppress("unused") private val keepSocketImport = Socket::class
}

class FullTunnelDnsTest {
    private fun query(dst: ByteArray, name: String): ByteArray {
        val labels = name.split('.').flatMap { listOf(it.length.toByte()) + it.toByteArray().toList() } + listOf(0.toByte())
        val dns = byteArrayOf(0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0) + labels.toByteArray() + byteArrayOf(0, 1, 0, 1)
        return UdpPacket.build(4, byteArrayOf(10, 111, 222.toByte(), 1), dst, 41000, 53, dns)
    }

    @Test
    fun hardCodedResolverIsFilteredOnlyInFullTunnelMode() {
        val google = byteArrayOf(8, 8, 8, 8)
        val p = DnsPacketProcessor(DomainMatcher(setOf("doubleclick.net")), listOf(byteArrayOf(10, 111, 222.toByte(), 2)))
        val q = query(google, "ads.doubleclick.net")
        assertEquals(Decision.Drop, p.process(q, q.size))
        p.anyResolver = true
        val d = assertIs<Decision.Respond>(p.process(q, q.size))
        val reply = UdpPacket.parse(d.packet)!!
        assertContentEquals(google, reply.source, "the answer must appear to come from the resolver the app asked")
        assertTrue(TunnelLoop.isDns(q, q.size))
        val tcp = TcpSegment.build(4, byteArrayOf(10, 0, 0, 1), google, 40000, 53, 1, 0, TcpSegment.SYN, 1000)
        assertTrue(!TunnelLoop.isDns(tcp, tcp.size), "DNS over TCP goes to the relay")
    }
}
