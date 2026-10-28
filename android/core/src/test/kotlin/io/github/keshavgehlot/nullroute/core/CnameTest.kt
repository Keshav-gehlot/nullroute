package io.github.keshavgehlot.nullroute.core

import org.junit.jupiter.api.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * CNAME uncloaking (Dimova et al., "The CNAME of the Game", PoPETs 2021):
 * a first-party name that aliases to a tracker must be blocked even though the
 * queried name itself is on no list. Responses below were produced by dnslib,
 * which uses name compression exactly like production resolvers.
 */
class CnameTest {
    private fun hex(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    // metrics.shop.com CNAME shop.cdn.example.net CNAME shop.eulerian.net A 93.184.216.34
    private val cloaked = hex(
        "222281800001000300000000076d6574726963730473686f7003636f6d0000010001c00c000500010000012c0016" +
            "0473686f700363646e076578616d706c65036e657400c02e000500010000012c00100473686f700865756c657269" +
            "616ec03fc050000100010000012c00045db8d822"
    )
    // www.shop.com CNAME shop.com.cdn.cloudflare.net A 93.184.216.34
    private val benign = hex(
        "333381800001000200000000037777770473686f7003636f6d0000010001c00c000500010000012c001d0473686f70" +
            "03636f6d0363646e0a636c6f7564666c617265036e657400c02a000100010000012c00045db8d822"
    )

    private fun queryPacket(name: String, id: Int): ByteArray {
        val labels = name.split('.').flatMap { listOf(it.length.toByte()) + it.toByteArray().toList() } + listOf(0.toByte())
        val dns = byteArrayOf((id ushr 8).toByte(), id.toByte(), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0) +
            labels.toByteArray() + byteArrayOf(0, 1, 0, 1)
        return UdpPacket.build(4, byteArrayOf(10, 111, 222.toByte(), 1), byteArrayOf(10, 111, 222.toByte(), 2), 40000, 53, dns)
    }

    private val resolver = listOf(byteArrayOf(10, 111, 222.toByte(), 2))

    @Test
    fun extractsCompressedCnameChain() {
        assertEquals(listOf("shop.cdn.example.net", "shop.eulerian.net"), DnsQuery.cnameTargets(cloaked))
        assertEquals(listOf("shop.com.cdn.cloudflare.net"), DnsQuery.cnameTargets(benign))
    }

    @Test
    fun rejectsPointerLoopsAndTruncation() {
        val loop = cloaked.copyOf().also { it[it.size - 4 - 10 - 2] = 0xC0.toByte() } // corrupt into a self-loop region
        DnsQuery.cnameTargets(loop) // must terminate (hop limit), result may be null
        assertNull(DnsQuery.cnameTargets(cloaked.copyOf(40)))
        val selfPointer = cloaked.copyOf().also { it[0x3f] = 0xC0.toByte(); it[0x40] = 0x3f }
        DnsQuery.cnameTargets(selfPointer) // terminates instead of spinning forever
    }

    @Test
    fun blocksLookupWhoseAnswerAliasesToTracker() {
        val matcher = DomainMatcher(listBlocked = setOf("doubleclick.net"), cnameTargets = setOf("eulerian.net"))
        val p = DnsPacketProcessor(matcher, resolver)
        val q = queryPacket("metrics.shop.com", 0x2222)
        val d = assertIs<Decision.Forward>(p.process(q, q.size), "queried name is on no list")
        val wrapped = UdpPacket.parse(d.reply(cloaked)!!)!!
        assertEquals(Verdict.BLOCKED_BY_CNAME, d.event.verdict)
        assertEquals("shop.eulerian.net", d.event.cnameTarget)
        // The client receives a sinkhole answer, not the tracker's address.
        val dns = wrapped.payload
        assertEquals(1, UdpPacket.u16(dns, 6))
        assertContentEquals(ByteArray(4), dns.copyOfRange(dns.size - 4, dns.size))
    }

    @Test
    fun cnameTargetOnRegularBlocklistAlsoCounts() {
        // No dedicated CNAME-target list: a target on the ordinary blocklist is enough.
        val matcher = DomainMatcher(listBlocked = setOf("eulerian.net"))
        val q = queryPacket("metrics.shop.com", 0x2222)
        val f = assertIs<Decision.Forward>(DnsPacketProcessor(matcher, resolver).process(q, q.size))
        f.reply(cloaked)
        assertEquals(Verdict.BLOCKED_BY_CNAME, f.event.verdict)
    }

    @Test
    fun benignCdnAliasPassesThroughUnchanged() {
        val matcher = DomainMatcher(listBlocked = setOf("doubleclick.net"), cnameTargets = setOf("eulerian.net"))
        val q = queryPacket("www.shop.com", 0x3333)
        val d = assertIs<Decision.Forward>(DnsPacketProcessor(matcher, resolver).process(q, q.size))
        val wrapped = UdpPacket.parse(d.reply(benign)!!)!!
        assertContentEquals(benign, wrapped.payload)
        assertEquals(Verdict.ALLOWED, d.event.verdict)
    }

    @Test
    fun userAllowWinsOverUncloaking() {
        // Allowing the site itself, or the tracker, disables the CNAME block.
        for (m in listOf(
            DomainMatcher(setOf(), userAllowed = setOf("shop.com"), cnameTargets = setOf("eulerian.net")),
            DomainMatcher(setOf(), userAllowed = setOf("eulerian.net"), cnameTargets = setOf("eulerian.net")),
        )) {
            val q = queryPacket("metrics.shop.com", 0x2222)
            val d = assertIs<Decision.Forward>(DnsPacketProcessor(m, resolver).process(q, q.size))
            d.reply(cloaked)
            assertTrue(!d.event.verdict.blocked)
        }
    }

    @Test
    fun firefoxDohCanaryGetsNxdomain() {
        val q = queryPacket("use-application-dns.net", 0x4444)
        val d = assertIs<Decision.Respond>(DnsPacketProcessor(DomainMatcher(emptySet()), resolver).process(q, q.size))
        assertEquals(Verdict.DOH_CANARY, d.event.verdict)
        assertEquals(3, UdpPacket.parse(d.packet)!!.payload[3].toInt() and 0x0f, "RCODE NXDOMAIN")
    }
}
