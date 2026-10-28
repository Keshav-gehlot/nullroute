package io.github.keshavgehlot.nullroute.core

import org.junit.jupiter.api.Test
import java.io.BufferedReader
import java.io.StringReader
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

private fun hex(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
private fun ip(vararg b: Int) = ByteArray(b.size) { b[it].toByte() }

// Packets produced by scapy (an independent implementation), not by our encoder.
private val V4_QUERY = hex(
    "4500004c109200004011992d0a6fde010a6fde029cbb003500385cbbbeef01000001000000000001" +
        "034164730b446f75626c65436c69636b036e657400000100010000291000000080000000"
)
private val V6_QUERY = hex(
    "6000000000251140fd000001fd000001fd000001fd000001fd000001fd000001fd000001fd000002" +
        "c738003500255384123401000001000000000000076578616d706c6503636f6d00001c0001"
)
private val RESOLVER_V4 = ip(10, 111, 222, 2)
private val RESOLVER_V6 = hex("fd000001fd000001fd000001fd000002")

class PacketTest {
    @Test
    fun parsesIpv4UdpFromScapy() {
        val p = assertNotNull(UdpPacket.parse(V4_QUERY))
        assertEquals(4, p.version)
        assertEquals(40123, p.sourcePort)
        assertEquals(53, p.destinationPort)
        assertContentEquals(RESOLVER_V4, p.destination)
    }

    @Test
    fun parsesIpv6UdpFromScapy() {
        val p = assertNotNull(UdpPacket.parse(V6_QUERY))
        assertEquals(6, p.version)
        assertEquals(51000, p.sourcePort)
        assertContentEquals(RESOLVER_V6, p.destination)
    }

    @Test
    fun ourChecksumsMatchScapy() {
        // Rebuilding scapy's packet with our encoder must reproduce it byte for byte
        // apart from the IP id/flags fields we set differently.
        val p = UdpPacket.parse(V6_QUERY)!!
        val rebuilt = UdpPacket.build(6, p.source, p.destination, p.sourcePort, p.destinationPort, p.payload)
        assertContentEquals(V6_QUERY, rebuilt)
    }

    @Test
    fun builtIpv4PacketsVerify() {
        val p = UdpPacket.parse(V4_QUERY)!!
        val reply = p.reply(byteArrayOf(1, 2, 3))
        assertEquals(0, Checksum.of(reply, 0, 20), "IPv4 header checksum must verify to zero")
        val back = assertNotNull(UdpPacket.parse(reply))
        assertContentEquals(p.source, back.destination)
        assertEquals(40123, back.destinationPort)
        assertEquals(53, back.sourcePort)
        // Recompute the UDP checksum with the field zeroed; it must equal what we wrote.
        val stored = UdpPacket.u16(reply, 26)
        val zeroed = reply.copyOf().also { it[26] = 0; it[27] = 0 }
        assertEquals(stored, Checksum.udp(back.source, back.destination, zeroed, 20, 11))
        assertTrue(stored != 0)
    }

    @Test
    fun rejectsGarbageAndNonUdp() {
        assertNull(UdpPacket.parse(byteArrayOf()))
        assertNull(UdpPacket.parse(ByteArray(10)))
        val tcp = V4_QUERY.copyOf().also { it[9] = 6 }
        assertNull(UdpPacket.parse(tcp))
        val truncated = V4_QUERY.copyOf(30)
        assertNull(UdpPacket.parse(truncated))
        val fragment = V4_QUERY.copyOf().also { it[6] = 0x20 } // MF flag
        assertNull(UdpPacket.parse(fragment))
    }
}

class DnsTest {
    private val v4Payload = UdpPacket.parse(V4_QUERY)!!.payload

    @Test
    fun parsesQuestionCaseInsensitively() {
        val q = assertNotNull(DnsQuery.parse(v4Payload))
        assertEquals("ads.doubleclick.net", q.name)
        assertEquals(DnsQuery.TYPE_A, q.type)
        assertEquals(0xBEEF, q.id)
    }

    @Test
    fun blockedAResponseIsWellFormed() {
        val q = DnsQuery.parse(v4Payload)!!
        val r = q.blockedResponse(ttl = 60)
        assertEquals(0xBEEF, UdpPacket.u16(r, 0))
        assertEquals(0x81, r[2].toInt() and 0xff, "QR=1, RD echoed")
        assertEquals(0x80, r[3].toInt() and 0xff, "RA=1, NOERROR")
        assertEquals(1, UdpPacket.u16(r, 4)); assertEquals(1, UdpPacket.u16(r, 6))
        assertEquals(0, UdpPacket.u16(r, 10), "EDNS OPT record dropped")
        val ans = q.questionEnd
        assertEquals(0xC00C, UdpPacket.u16(r, ans))
        assertEquals(DnsQuery.TYPE_A, UdpPacket.u16(r, ans + 2))
        assertEquals(4, UdpPacket.u16(r, ans + 10))
        assertContentEquals(ByteArray(4), r.copyOfRange(ans + 12, ans + 16))
        assertEquals(ans + 16, r.size)
    }

    @Test
    fun blockedAaaaAndOtherTypes() {
        val aaaa = DnsQuery.parse(UdpPacket.parse(V6_QUERY)!!.payload)!!
        val r = aaaa.blockedResponse()
        assertEquals(16, UdpPacket.u16(r, aaaa.questionEnd + 10))
        // HTTPS (type 65) record: NODATA, so browsers can't learn an alternative endpoint
        val https = v4Payload.copyOf().also { val q = DnsQuery.parse(it)!!; UdpPacket.put16(it, q.questionEnd - 4, 65) }
        val hq = DnsQuery.parse(https)!!
        val hr = hq.blockedResponse()
        assertEquals(0, UdpPacket.u16(hr, 6))
        assertEquals(hq.questionEnd, hr.size)
    }

    @Test
    fun servfail() {
        val q = DnsQuery.parse(v4Payload)!!
        val r = q.failureResponse()
        assertEquals(2, r[3].toInt() and 0x0f)
        assertEquals(0, UdpPacket.u16(r, 6))
    }

    @Test
    fun rejectsResponsesAndMalformedQueries() {
        val resp = v4Payload.copyOf().also { it[2] = (it[2].toInt() or 0x80).toByte() }
        assertNull(DnsQuery.parse(resp))
        val twoQuestions = v4Payload.copyOf().also { UdpPacket.put16(it, 4, 2) }
        assertNull(DnsQuery.parse(twoQuestions))
        val pointer = v4Payload.copyOf().also { it[12] = 0xC0.toByte() }
        assertNull(DnsQuery.parse(pointer))
        val runaway = v4Payload.copyOf().also { it[12] = 60 } // label longer than packet
        assertNull(DnsQuery.parse(runaway))
    }
}

class MatcherTest {
    private val m = DomainMatcher(
        listBlocked = setOf("doubleclick.net", "tracker.io"),
        listAllowed = setOf("ok.tracker.io"),
        userBlocked = setOf("social.example"),
        userAllowed = setOf("ads.doubleclick.net"),
    )

    @Test
    fun suffixMatchingAndPrecedence() {
        assertEquals(Verdict.BLOCKED_BY_LIST, m.verdict("doubleclick.net"))
        assertEquals(Verdict.BLOCKED_BY_LIST, m.verdict("x.y.doubleclick.net"))
        assertEquals(Verdict.ALLOWED, m.verdict("notdoubleclick.net"))
        assertEquals(Verdict.ALLOWED_BY_USER, m.verdict("ads.doubleclick.net"))
        assertEquals(Verdict.ALLOWED_BY_USER, m.verdict("a.ads.doubleclick.net"))
        assertEquals(Verdict.ALLOWED_BY_LIST, m.verdict("ok.tracker.io"))
        assertEquals(Verdict.BLOCKED_BY_USER, m.verdict("cdn.social.example"))
        assertEquals(Verdict.ALLOWED, m.verdict(""))
    }

    @Test
    fun readsCompiledListsAndHostsFiles() {
        val text = """
            # NullRoute DNS blocklist
            ads.example.com
            0.0.0.0 tracker.example.net  # hosts style
            127.0.0.1 localhost
            not a domain!
            UPPER.Example.ORG.
        """.trimIndent()
        val set = DomainMatcher.readList(BufferedReader(StringReader(text)))
        assertEquals(setOf("ads.example.com", "tracker.example.net", "upper.example.org"), set)
    }

    @Test
    fun normalizesUserInput() {
        assertEquals("example.com", DomainMatcher.normalize(" https://Example.com/path?q=1 "))
        assertEquals("cdn.example.com", DomainMatcher.normalize("*.cdn.example.com"))
        assertNull(DomainMatcher.normalize("localhost"))
        assertNull(DomainMatcher.normalize("http://"))
    }
}

class ProcessorTest {
    private val processor = DnsPacketProcessor(
        DomainMatcher(setOf("doubleclick.net")), listOf(RESOLVER_V4, RESOLVER_V6), clock = { 1000L },
    )

    @Test
    fun blocksListedDomainWithReplyPacket() {
        val d = assertIs<Decision.Respond>(processor.process(V4_QUERY, V4_QUERY.size))
        assertEquals("ads.doubleclick.net", d.event.name)
        assertTrue(d.event.verdict.blocked)
        val reply = UdpPacket.parse(d.packet)!!
        assertContentEquals(RESOLVER_V4, reply.source)
        assertEquals(40123, reply.destinationPort)
        val dns = reply.payload
        assertEquals(0xBEEF, UdpPacket.u16(dns, 0))
        assertEquals(1, UdpPacket.u16(dns, 6))
    }

    @Test
    fun forwardsAllowedDomainAndValidatesAnswerId() {
        val d = assertIs<Decision.Forward>(processor.process(V6_QUERY, V6_QUERY.size))
        assertFalse(d.event.verdict.blocked)
        assertEquals("example.com", d.parsed.name)
        val goodAnswer = d.query.copyOf().also { it[2] = (it[2].toInt() or 0x80).toByte() }
        val wrapped = assertNotNull(d.reply(goodAnswer))
        assertEquals(6, UdpPacket.parse(wrapped)!!.version)
        val spoofed = goodAnswer.copyOf().also { UdpPacket.put16(it, 0, 0x9999) }
        assertNull(d.reply(spoofed), "answer with a different id must be dropped")
        assertEquals(2, UdpPacket.parse(d.failure())!!.payload[3].toInt() and 0x0f)
    }

    @Test
    fun dropsTrafficNotForTheVirtualResolver() {
        val otherDst = V4_QUERY.copyOf().also { it[19] = 9 }
        assertIs<Decision.Drop>(processor.process(otherDst, otherDst.size))
        val otherPort = V4_QUERY.copyOf().also { UdpPacket.put16(it, 22, 853) }
        assertIs<Decision.Drop>(processor.process(otherPort, otherPort.size))
        assertIs<Decision.Drop>(processor.process(ByteArray(100), 100))
    }

    @Test
    fun matcherCanBeSwappedLive() {
        processor.matcher = DomainMatcher(emptySet())
        assertIs<Decision.Forward>(processor.process(V4_QUERY, V4_QUERY.size))
    }
}

class QueryLogTest {
    @Test
    fun ringBufferKeepsNewestAndCounts() {
        val log = QueryLog(capacity = 3)
        repeat(5) { i -> log.add(QueryEvent(i.toLong(), "d$i.com", 1, if (i % 2 == 0) Verdict.BLOCKED_BY_LIST else Verdict.ALLOWED)) }
        assertEquals(listOf("d4.com", "d3.com", "d2.com"), log.snapshot().map { it.name })
        assertEquals(3L to 5L, log.counts())
    }
}
