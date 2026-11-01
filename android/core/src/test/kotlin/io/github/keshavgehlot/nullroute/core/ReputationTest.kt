package io.github.keshavgehlot.nullroute.core

import org.junit.jupiter.api.Test
import java.io.File
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Uses the real compiled reputation data (dist/rep, ~2.4M phishing/malware
 * domains) produced by the Python compiler, so the Kotlin decoder and hashing
 * are checked against the format as actually shipped.
 */
class ReputationTest {
    private val dist = File("../../dist/rep")
    private val prefixes by lazy { PrefixSet.decode(File(dist, "prefixes.rice").readBytes()) }
    private val fetched = AtomicInteger()
    private fun checker(fetch: (String) -> ByteArray? = { fetched.incrementAndGet(); File(dist, "shards/$it.bin").readBytes() }) =
        ReputationChecker(prefixes, fetch)

    @Test
    fun decodesTheShippedPrefixSet() {
        val meta = File(dist, "meta.json").readText()
        val expected = Regex("\"prefixes\":\\s*(\\d+)").find(meta)!!.groupValues[1].toInt()
        assertEquals(expected, prefixes.size)
    }

    @Test
    fun expressionsMatchCompiler() {
        assertEquals(listOf("a.b.evil.com", "b.evil.com", "evil.com"), ReputationChecker.expressions("A.b.Evil.com."))
        assertEquals(emptyList(), ReputationChecker.expressions("localhost"))
    }

    @Test
    fun findsRealFeedEntriesAndTheirSubdomains() {
        val feed = File("../../compiler/.cache/rep-1.txt").readLines()
            .filter { it.isNotBlank() && !it.startsWith("#") }.take(3000).filterIndexed { i, _ -> i % 50 == 0 }
        val c = checker()
        val found = feed.count { c.check(it) is ReputationChecker.Result.Listed }
        assertTrue(found >= feed.size * 9 / 10, "found $found of ${feed.size}")
        val sub = assertIs<ReputationChecker.Result.Listed>(c.check("login.secure." + feed.first { c.check(it) is ReputationChecker.Result.Listed }))
        assertFalse(sub.expression.startsWith("login."), "a listed parent covers its subdomains")
    }

    @Test
    fun essentialDomainsAreCleanAndMostNeverLeaveTheDevice() {
        val canaries = File("../../compiler/data/canaries.txt").readText().split(Regex("\\s+")).filter { it.isNotBlank() }
        val c = checker()
        fetched.set(0)
        for (name in canaries) assertEquals(ReputationChecker.Result.Clean, c.check(name), name)
        // Expected local false hits: ~3 expressions x 2.4M/2^32 per name, i.e. well under 1 for 70 names.
        assertTrue(fetched.get() <= 2, "clean names should almost never trigger a shard fetch, got ${fetched.get()}")
    }

    @Test
    fun tamperedOrMissingShardFailsOpen() {
        val name = File("../../compiler/.cache/rep-1.txt").readLines().first { it.isNotBlank() && !it.startsWith("#") }
        val truncated = checker { File(dist, "shards/$it.bin").readBytes().let { b -> b.copyOf(b.size - 3) } }
        assertEquals(ReputationChecker.Result.Unavailable, truncated.check(name))
        val wrongBucket = checker { File(dist, "shards/" + "%03x".format((it.toInt(16) + 1) % 4096) + ".bin").readBytes() }
        assertEquals(ReputationChecker.Result.Unavailable, wrongBucket.check(name))
        assertEquals(ReputationChecker.Result.Unavailable, checker { null }.check(name))
    }

    @Test
    fun shardsAreCachedAcrossLookups() {
        val name = File("../../compiler/.cache/rep-1.txt").readLines().first { it.isNotBlank() && !it.startsWith("#") }
        val c = checker()
        fetched.set(0)
        repeat(5) { assertIs<ReputationChecker.Result.Listed>(c.check(name)) }
        assertTrue(fetched.get() in 1..3)
    }

    // ---- end to end through the processor and forwarder, over real UDP ---------
    private fun query(name: String, id: Int): ByteArray {
        val labels = name.split('.').flatMap { listOf(it.length.toByte()) + it.toByteArray().toList() } + listOf(0.toByte())
        val dns = byteArrayOf((id ushr 8).toByte(), id.toByte(), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0) + labels.toByteArray() + byteArrayOf(0, 1, 0, 1)
        return UdpPacket.build(4, byteArrayOf(10, 111, 222.toByte(), 1), byteArrayOf(10, 111, 222.toByte(), 2), 40000, 53, dns)
    }

    @Test
    fun phishingDomainSinkholedWhileCleanNameResolves() {
        val responder = DatagramSocket(0, InetAddress.getLoopbackAddress())
        Thread {
            val buf = ByteArray(512)
            while (!responder.isClosed) {
                val p = DatagramPacket(buf, buf.size)
                try { responder.receive(p) } catch (_: Exception) { return@Thread }
                val q = DnsQuery.parse(buf.copyOf(p.length)) ?: continue
                val ans = q.blockedResponse().also { it[it.size - 4] = 93; it[it.size - 1] = 34 }
                responder.send(DatagramPacket(ans, ans.size, p.socketAddress))
            }
        }.apply { isDaemon = true; start() }
        val phish = File("../../compiler/.cache/rep-1.txt").readLines().first { it.isNotBlank() && !it.startsWith("#") }
        val events = Collections.synchronizedList(mutableListOf<QueryEvent>())
        val out = Collections.synchronizedList(mutableListOf<ByteArray>())
        val done = CountDownLatch(2)
        val processor = DnsPacketProcessor(DomainMatcher(emptySet()), listOf(byteArrayOf(10, 111, 222.toByte(), 2)), reputation = checker())
        val forwarder = DnsForwarder({ listOf(InetSocketAddress(InetAddress.getLoopbackAddress(), responder.localPort)) },
            { DatagramSocket() }, { out.add(it) }, onEvent = { events.add(it); done.countDown() })
        for ((n, id) in listOf(phish to 0x0101, "wikipedia.org" to 0x0202)) {
            val q = query(n, id)
            forwarder.handle(processor.process(q, q.size))
        }
        assertTrue(done.await(10, TimeUnit.SECONDS))
        forwarder.shutdown(); responder.close()
        val byName = events.associateBy { it.name }
        assertEquals(Verdict.BLOCKED_BY_REPUTATION, byName.getValue(phish).verdict)
        assertTrue(phish.endsWith(byName.getValue(phish).reputationMatch!!))
        assertEquals(Verdict.ALLOWED, byName.getValue("wikipedia.org").verdict)
        assertNull(byName.getValue("wikipedia.org").reputationMatch)
        val byId = out.associateBy { UdpPacket.u16(UdpPacket.parse(it)!!.payload, 0) }
        val blocked = UdpPacket.parse(byId.getValue(0x0101))!!.payload
        assertContentEquals(ByteArray(4), blocked.copyOfRange(blocked.size - 4, blocked.size))
        val ok = UdpPacket.parse(byId.getValue(0x0202))!!.payload
        assertEquals(93, ok[ok.size - 4].toInt())
    }
}
