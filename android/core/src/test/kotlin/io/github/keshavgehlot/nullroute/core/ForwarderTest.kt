package io.github.keshavgehlot.nullroute.core

import org.junit.jupiter.api.Test
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Runs the real forwarding path over real UDP sockets against a tiny local
 * DNS responder, with a pipe standing in for the tun device.
 */
class ForwarderTest {
    private fun hex(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    // scapy-generated IPv4 query for "example.com" A, src 10.111.222.1:40000 -> 10.111.222.2:53
    private fun query(name: String, id: Int): ByteArray {
        val labels = name.split('.').flatMap { listOf(it.length.toByte()) + it.toByteArray().toList() } + listOf(0.toByte())
        val dns = byteArrayOf((id ushr 8).toByte(), id.toByte(), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0) +
            labels.toByteArray() + byteArrayOf(0, 1, 0, 1)
        return UdpPacket.build(4, byteArrayOf(10, 111, 222.toByte(), 1), byteArrayOf(10, 111, 222.toByte(), 2), 40000, 53, dns)
    }

    /** Answers every A query with 93.184.216.34; optionally sends a spoofed answer first. */
    private fun startResponder(spoofFirst: Boolean = false): Pair<DatagramSocket, Thread> {
        val sock = DatagramSocket(0, InetAddress.getLoopbackAddress())
        val t = Thread {
            val buf = ByteArray(512)
            while (!sock.isClosed) {
                val p = DatagramPacket(buf, buf.size)
                try { sock.receive(p) } catch (_: Exception) { return@Thread }
                val q = DnsQuery.parse(buf.copyOf(p.length)) ?: continue
                val ans = q.blockedResponse().also { it[it.size - 4] = 93; it[it.size - 3] = 184.toByte(); it[it.size - 2] = 216.toByte(); it[it.size - 1] = 34 }
                if (spoofFirst) {
                    val spoof = ans.copyOf().also { UdpPacket.put16(it, 0, q.id xor 0xffff) }
                    sock.send(DatagramPacket(spoof, spoof.size, p.socketAddress))
                }
                sock.send(DatagramPacket(ans, ans.size, p.socketAddress))
            }
        }.apply { isDaemon = true; start() }
        return sock to t
    }

    private fun runLoop(upstreams: List<InetSocketAddress>, packets: List<ByteArray>, expect: Int,
                        timeoutMs: Int = 4000): List<ByteArray> {
        val out = Collections.synchronizedList(mutableListOf<ByteArray>())
        val done = CountDownLatch(expect)
        val processor = DnsPacketProcessor(DomainMatcher(setOf("doubleclick.net")), listOf(byteArrayOf(10, 111, 222.toByte(), 2)))
        val forwarder = DnsForwarder({ upstreams }, { DatagramSocket() }, { out.add(it); done.countDown() }, timeoutMs = timeoutMs)
        val pipeOut = PipedOutputStream()
        val pipeIn = PipedInputStream(pipeOut, 65536)
        val loop = TunnelLoop(BoundaryInputStream(pipeIn, packets.map { it.size }), processor, forwarder::handle)
        val th = Thread { loop.run() }.apply { start() }
        packets.forEach { pipeOut.write(it) }
        pipeOut.flush()
        assertTrue(done.await(15, TimeUnit.SECONDS), "expected $expect replies, got ${out.size}")
        loop.stop(); pipeOut.close(); th.join(2000); forwarder.shutdown()
        return out
    }

    @Test
    fun forwardsAllowedAndSinkholesBlockedOverRealUdp() {
        val (resp, _) = startResponder()
        val upstream = InetSocketAddress(InetAddress.getLoopbackAddress(), resp.localPort)
        val replies = runLoop(listOf(upstream), listOf(query("example.com", 0x1111), query("ads.doubleclick.net", 0x2222)), 2)
        val byId = replies.associateBy { UdpPacket.u16(UdpPacket.parse(it)!!.payload, 0) }
        val ok = UdpPacket.parse(byId.getValue(0x1111))!!
        assertContentEquals(byteArrayOf(93, 184.toByte(), 216.toByte(), 34), ok.payload.copyOfRange(ok.payload.size - 4, ok.payload.size))
        assertEquals(40000, ok.destinationPort)
        val blocked = UdpPacket.parse(byId.getValue(0x2222))!!
        assertContentEquals(ByteArray(4), blocked.payload.copyOfRange(blocked.payload.size - 4, blocked.payload.size))
        resp.close()
    }

    @Test
    fun ignoresSpoofedAnswersWithWrongId() {
        val (resp, _) = startResponder(spoofFirst = true)
        val upstream = InetSocketAddress(InetAddress.getLoopbackAddress(), resp.localPort)
        val replies = runLoop(listOf(upstream), listOf(query("example.org", 0x3333)), 1)
        assertEquals(0x3333, UdpPacket.u16(UdpPacket.parse(replies.single())!!.payload, 0))
        assertEquals(0, UdpPacket.parse(replies.single())!!.payload[3].toInt() and 0x0f) // NOERROR, not the spoof
        resp.close()
    }

    @Test
    fun fallsBackToNextResolverThenServfail() {
        val dead = DatagramSocket(0, InetAddress.getLoopbackAddress()) // never answers
        val (resp, _) = startResponder()
        val live = InetSocketAddress(InetAddress.getLoopbackAddress(), resp.localPort)
        val deadAddr = InetSocketAddress(InetAddress.getLoopbackAddress(), dead.localPort)
        val ok = runLoop(listOf(deadAddr, live), listOf(query("example.net", 0x4444)), 1, timeoutMs = 500)
        assertEquals(0, UdpPacket.parse(ok.single())!!.payload[3].toInt() and 0x0f)
        val fail = runLoop(listOf(deadAddr), listOf(query("example.net", 0x5555)), 1, timeoutMs = 300)
        assertEquals(2, UdpPacket.parse(fail.single())!!.payload[3].toInt() and 0x0f, "SERVFAIL when no resolver answers")
        dead.close(); resp.close()
    }
}

/** Mimics a tun fd: each read() returns exactly one packet. */
private class BoundaryInputStream(private val inner: PipedInputStream, sizes: List<Int>) : java.io.InputStream() {
    private val sizes = ArrayDeque(sizes)
    override fun read(): Int = inner.read()
    override fun read(b: ByteArray, off: Int, len: Int): Int {
        val want = sizes.removeFirstOrNull() ?: return inner.read(b, off, len)
        var got = 0
        while (got < want) {
            val n = inner.read(b, off + got, want - got)
            if (n < 0) return if (got == 0) -1 else got
            got += n
        }
        return got
    }
}
