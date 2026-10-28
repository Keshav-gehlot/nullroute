package io.github.keshavgehlot.nullroute.core

import org.junit.jupiter.api.Test
import java.io.File
import kotlin.math.abs
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Uses the real model the compiler ships (dist/dns/dga_model.txt). Reference
 * scores come from the Python implementation that produced the evaluation
 * numbers (compiler/nullroute_compiler/dga.py), so the shipped Kotlin detector
 * is provably the same model that was evaluated.
 */
class DgaTest {
    private val detector = DgaDetector.read(File("../../dist/dns/dga_model.txt").bufferedReader())

    @Test
    fun scoresMatchPythonReference() {
        val reference = mapOf(
            "7x9qaz83mpr2v.com" to -4.8979,
            "cvyh1po636avyrsxebwbkn7.ddns.net" to -4.6076,   // dynamic-DNS label is the site
            "wikipedia.org" to -2.7939,
            "flipkart.com" to -2.9113,
            "instagram.com" to -2.5682,
            "d1a2b3c4e5f6.cloudfront.net" to -2.7237,        // judged as "cloudfront"
            "qzwxkjhvbn.net" to -5.1981,
            "brothernerveplacebringconsult.com" to -2.6728,  // dictionary DGA: not detectable
        )
        for ((name, expected) in reference) {
            val got = detector.score(name)!!
            assertTrue(abs(got - expected) < 1e-3, "$name: kotlin $got vs python $expected")
        }
    }

    @Test
    fun levels() {
        assertEquals(DgaDetector.Level.BLOCK, detector.assess("qzwxkjhvbn.net"))
        assertEquals(DgaDetector.Level.BLOCK, detector.assess("cvyh1po636avyrsxebwbkn7.ddns.net"))
        for (ok in listOf("wikipedia.org", "flipkart.com", "r4---sn-ab5l6nrz.googlevideo.com",
            "d1a2b3c4e5f6.cloudfront.net", "keshavgehlot.dev", "srmist.edu.in")) {
            assertEquals(DgaDetector.Level.NONE, detector.assess(ok), ok)
        }
    }

    @Test
    fun unjudgeableNames() {
        assertNull(detector.score("swiggy.com"), "short labels carry too little signal")
        assertNull(detector.score("xn--80ak6aa92e.com"), "punycode IDNs are skipped")
        assertNull(detector.score("1.0.168.192.in-addr.arpa"))
        assertNull(detector.score("printer.local"))
        assertNull(detector.score("localhost"))
    }

    private fun query(name: String): ByteArray {
        val labels = name.split('.').flatMap { listOf(it.length.toByte()) + it.toByteArray().toList() } + listOf(0.toByte())
        val dns = byteArrayOf(0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0) + labels.toByteArray() + byteArrayOf(0, 1, 0, 1)
        return UdpPacket.build(4, byteArrayOf(10, 111, 222.toByte(), 1), byteArrayOf(10, 111, 222.toByte(), 2), 40000, 53, dns)
    }

    private val resolver = listOf(byteArrayOf(10, 111, 222.toByte(), 2))

    @Test
    fun flagOnlyByDefaultBlockWhenOptedIn() {
        val p = DnsPacketProcessor(DomainMatcher(setOf("doubleclick.net")), resolver, dga = detector)
        val q = query("qzwxkjhvbn.net")
        val flagged = assertIs<Decision.Forward>(p.process(q, q.size), "default: never block on a heuristic")
        assertTrue(flagged.event.suspicious)
        assertEquals(Verdict.ALLOWED, flagged.event.verdict)

        p.blockSuspicious = true
        val blocked = assertIs<Decision.Respond>(p.process(q, q.size))
        assertEquals(Verdict.BLOCKED_BY_HEURISTIC, blocked.event.verdict)

        val normal = query("wikipedia.org")
        assertFalse(assertIs<Decision.Forward>(p.process(normal, normal.size)).event.suspicious)
    }

    @Test
    fun userAllowAndListsTakePrecedence() {
        val p = DnsPacketProcessor(DomainMatcher(emptySet(), userAllowed = setOf("qzwxkjhvbn.net")), resolver,
            dga = detector, blockSuspicious = true)
        val q = query("qzwxkjhvbn.net")
        val d = assertIs<Decision.Forward>(p.process(q, q.size))
        assertEquals(Verdict.ALLOWED_BY_USER, d.event.verdict)
        assertFalse(d.event.suspicious, "user-allowed names are never second-guessed")
    }
}
