package io.github.keshavgehlot.nullroute.core

/** What to do with one packet read from the tunnel. */
sealed interface Decision {
    /** Not a DNS query for our virtual resolver; drop it. */
    data object Drop : Decision

    /** Answer immediately by writing [packet] back to the tunnel. */
    class Respond(val packet: ByteArray, val request: UdpPacket, val event: QueryEvent) : Decision

    /** Send [query] upstream; wrap the answer with [reply] and write it back. */
    class Forward(
        val query: ByteArray,
        val request: UdpPacket,
        val parsed: DnsQuery,
        val event: QueryEvent,
        private val matcher: DomainMatcher? = null,
    ) : Decision {
        fun reply(answer: ByteArray): ByteArray? {
            // Only accept the answer to *this* query (guards against spoofing).
            if (DnsQuery.responseId(answer) != parsed.id) return null
            // CNAME uncloaking: metrics.shop.com -> shop.tracker.net. The queried
            // name passed the lists, so inspect where the answer actually points.
            val m = matcher
            if (m != null && event.verdict != Verdict.ALLOWED_BY_USER && event.verdict != Verdict.ALLOWED_BY_LIST) {
                val blockedTarget = DnsQuery.cnameTargets(answer)?.firstOrNull(m::blocksCnameTarget)
                if (blockedTarget != null) {
                    event.verdict = Verdict.BLOCKED_BY_CNAME
                    event.cnameTarget = blockedTarget
                    return request.reply(parsed.blockedResponse())
                }
            }
            return request.reply(answer)
        }
        fun failure(): ByteArray = request.reply(parsed.failureResponse())
    }
}

data class QueryEvent(
    val timeMillis: Long,
    val name: String,
    val type: Int,
    var verdict: Verdict,
    var uid: Int = -1,
    var cnameTarget: String? = null,
)

/**
 * Pure decision logic for the VPN's packet loop. Holds no sockets and does no
 * I/O, so it is fully unit-testable on the JVM.
 *
 * @param resolverAddresses the fake DNS server IPs announced to Android. Only
 *   UDP packets addressed to one of these, on port 53, are handled.
 */
class DnsPacketProcessor(
    @Volatile var matcher: DomainMatcher,
    private val resolverAddresses: List<ByteArray>,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    fun process(buf: ByteArray, length: Int): Decision {
        val pkt = UdpPacket.parse(buf, length) ?: return Decision.Drop
        if (pkt.destinationPort != 53) return Decision.Drop
        if (resolverAddresses.none { it.contentEquals(pkt.destination) }) return Decision.Drop
        val query = DnsQuery.parse(pkt.payload) ?: return Decision.Drop
        if (query.name == DOH_CANARY) {
            // Firefox disables its built-in DoH when this name doesn't resolve,
            // which keeps its lookups visible to the filter.
            return Decision.Respond(pkt.reply(query.nxdomainResponse()), pkt,
                QueryEvent(clock(), query.name, query.type, Verdict.DOH_CANARY))
        }
        val m = matcher
        val verdict = m.verdict(query.name)
        val event = QueryEvent(clock(), query.name, query.type, verdict)
        return if (verdict.blocked) {
            Decision.Respond(pkt.reply(query.blockedResponse()), pkt, event)
        } else {
            Decision.Forward(pkt.payload, pkt, query, event, m)
        }
    }

    companion object {
        const val DOH_CANARY = "use-application-dns.net"
    }
}
