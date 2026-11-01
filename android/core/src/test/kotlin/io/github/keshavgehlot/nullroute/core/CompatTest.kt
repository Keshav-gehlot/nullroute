package io.github.keshavgehlot.nullroute.core

import org.junit.jupiter.api.Test
import java.io.File
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** "Avoid ad-blocker detection": loader hosts get through, ad servers and trackers don't. */
class CompatTest {
    private val compat = File("../../dist/dns/compat.txt").bufferedReader().use { DomainMatcher.readList(it) }
    private val matcher = DomainMatcher(
        setOf("googlesyndication.com", "doubleclick.net", "fundingchoicesmessages.google.com", "googleapis.com"),
        compat = compat,
    )
    private val resolver = listOf(byteArrayOf(10, 111, 222.toByte(), 2))

    private fun query(name: String, type: Int = 1): ByteArray {
        val labels = name.split('.').flatMap { listOf(it.length.toByte()) + it.toByteArray().toList() } + listOf(0.toByte())
        val dns = byteArrayOf(0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0) + labels.toByteArray() + byteArrayOf(0, type.toByte(), 0, 1)
        return UdpPacket.build(4, byteArrayOf(10, 111, 222.toByte(), 1), byteArrayOf(10, 111, 222.toByte(), 2), 40000, 53, dns)
    }

    @Test
    fun shippedListHoldsTheVideoAndAdLoaders() {
        assertTrue("imasdk.googleapis.com" in compat && "pagead2.googlesyndication.com" in compat)
        assertTrue("fundingchoicesmessages.google.com" !in compat, "Google's adblock nag stays blocked")
    }

    @Test
    fun offBlocksEverythingAsBefore() {
        val p = DnsPacketProcessor(matcher, resolver)
        val q = query("imasdk.googleapis.com")
        assertNull(assertIs<Decision.Respond>(p.process(q, q.size)).compatFallback)
    }

    @Test
    fun everywhereLetsOnlyExactLoaderHostsThrough() {
        val p = DnsPacketProcessor(matcher, resolver, compatMode = CompatMode.EVERYWHERE)
        for (loader in listOf("imasdk.googleapis.com", "pagead2.googlesyndication.com", "securepubads.g.doubleclick.net")) {
            val q = query(loader)
            assertEquals(Verdict.ALLOWED_FOR_COMPAT, assertIs<Decision.Forward>(p.process(q, q.size)).event.verdict, loader)
        }
        // Ad servers, trackers and Google's "turn off your ad blocker" prompt stay blocked.
        for (blocked in listOf("tpc.googlesyndication.com", "googleads.g.doubleclick.net", "pubads.g.doubleclick.net",
            "x.pagead2.googlesyndication.com", "fundingchoicesmessages.google.com")) {
            val q = query(blocked)
            assertIs<Decision.Respond>(p.process(q, q.size), blocked)
        }
    }

    @Test
    fun selectedAppsDefersTheChoiceToTheCaller() {
        val p = DnsPacketProcessor(matcher, resolver, compatMode = CompatMode.SELECTED_APPS)
        val q = query("imasdk.googleapis.com")
        val d = assertIs<Decision.Respond>(p.process(q, q.size))
        assertEquals(Verdict.BLOCKED_BY_LIST, d.event.verdict)
        val fallback = assertNotNull(d.compatFallback)
        assertEquals(Verdict.ALLOWED_FOR_COMPAT, fallback.event.verdict)
    }

    @Test
    fun userBlockStillWinsAndLoaderIsNotReblockedByItsCname() {
        val strict = DnsPacketProcessor(DomainMatcher(setOf("googlesyndication.com", "doubleclick.net"),
            userBlocked = setOf("pagead2.googlesyndication.com"), compat = compat), resolver, compatMode = CompatMode.EVERYWHERE)
        val q = query("pagead2.googlesyndication.com")
        assertEquals(Verdict.BLOCKED_BY_USER, assertIs<Decision.Respond>(strict.process(q, q.size)).event.verdict)

        // pagead2.googlesyndication.com -> pagead46.l.doubleclick.net: the CNAME check must not undo the compat allow.
        val p = DnsPacketProcessor(matcher, resolver, compatMode = CompatMode.EVERYWHERE)
        val fwd = assertIs<Decision.Forward>(p.process(q, q.size))
        val answer = cnameAnswer(fwd.parsed, "pagead2.googlesyndication.com", "pagead46.l.doubleclick.net")
        val reply = assertNotNull(fwd.reply(answer))
        assertEquals(Verdict.ALLOWED_FOR_COMPAT, fwd.event.verdict)
        assertContentEquals(answer, UdpPacket.parse(reply)!!.payload)
    }

    private fun name(n: String) = n.split('.').flatMap { listOf(it.length.toByte()) + it.toByteArray().toList() } + listOf(0.toByte())

    /** A response with one CNAME and one A record. */
    private fun cnameAnswer(q: DnsQuery, owner: String, target: String): ByteArray {
        val qname = name(owner)
        val header = listOf(0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0).map { it.toByte() }
        val question = qname + listOf<Byte>(0, 1, 0, 1)
        val tname = name(target)
        val cname = qname + listOf<Byte>(0, 5, 0, 1, 0, 0, 0, 60, 0, tname.size.toByte()) + tname
        val a = tname + listOf<Byte>(0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 142.toByte(), 250.toByte(), 1, 1)
        check(q.id == 0x1234)
        return (header + question + cname + a).toByteArray()
    }
}
