package io.github.keshavgehlot.nullroute.core

/** What to do with one packet read from the tunnel. */
sealed interface Decision {
    /** Not a DNS query for our virtual resolver; drop it. */
    data object Drop : Decision

    /**
     * Answer immediately by writing [packet] back to the tunnel.
     * [compatFallback] is set when the block may be lifted for the requesting app
     * (ad-blocker detection compat in "selected apps" mode): the caller knows the
     * app, the processor doesn't.
     */
    class Respond(
        val packet: ByteArray,
        val request: UdpPacket,
        val event: QueryEvent,
        val compatFallback: Forward? = null,
    ) : Decision

    /** Send [query] upstream; wrap the answer with [reply] and write it back. */
    class Forward(
        val query: ByteArray,
        val request: UdpPacket,
        val parsed: DnsQuery,
        val event: QueryEvent,
        private val matcher: DomainMatcher? = null,
        /** Set when the name hit the local reputation prefix set; runs in parallel with the upstream query. */
        val reputationCheck: (() -> ReputationChecker.Result)? = null,
    ) : Decision {
        fun reply(answer: ByteArray): ByteArray? {
            // Only accept the answer to *this* query (guards against spoofing).
            if (DnsQuery.responseId(answer) != parsed.id) return null
            // CNAME uncloaking: metrics.shop.com -> shop.tracker.net. The queried
            // name passed the lists, so inspect where the answer actually points.
            val m = matcher
            if (m != null && event.verdict !in NO_UNCLOAK) {
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

        private companion object {
            // Explicitly allowed names are never second-guessed by their CNAME chain
            // (a compat loader such as pagead2.googlesyndication.com aliases into doubleclick.net).
            val NO_UNCLOAK = setOf(Verdict.ALLOWED_BY_USER, Verdict.ALLOWED_BY_LIST, Verdict.ALLOWED_FOR_COMPAT)
        }
        fun blocked(): ByteArray = request.reply(parsed.blockedResponse())
    }
}

data class QueryEvent(
    val timeMillis: Long,
    val name: String,
    val type: Int,
    var verdict: Verdict,
    var uid: Int = -1,
    var cnameTarget: String? = null,
    /** On no list, but looks machine-generated (shown as a warning; blocked only if opted in). */
    var suspicious: Boolean = false,
    /** The listed domain that matched, for BLOCKED_BY_REPUTATION. */
    var reputationMatch: String? = null,
    /** The name hit the local prefix set but the shard couldn't be checked (allowed). */
    var reputationUnavailable: Boolean = false,
)

/** "Avoid ad-blocker detection": whether loader hosts in compat.txt are let through. */
enum class CompatMode { OFF, SELECTED_APPS, EVERYWHERE }

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
    @Volatile var dga: DgaDetector? = null,
    @Volatile var blockSuspicious: Boolean = false,
    @Volatile var reputation: ReputationChecker? = null,
    /**
     * Full-tunnel mode: answer DNS queries sent to *any* address, so apps with
     * hard-coded resolvers (8.8.8.8 etc.) are filtered too. The reply comes back
     * from the address the app asked, so it can't tell.
     */
    @Volatile var anyResolver: Boolean = false,
    @Volatile var compatMode: CompatMode = CompatMode.OFF,
) {
    fun process(buf: ByteArray, length: Int): Decision {
        val pkt = UdpPacket.parse(buf, length) ?: return Decision.Drop
        if (pkt.destinationPort != 53) return Decision.Drop
        if (!anyResolver && resolverAddresses.none { it.contentEquals(pkt.destination) }) return Decision.Drop
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
        // Zero-day heuristic: only for names no list or user rule has decided.
        if (verdict == Verdict.ALLOWED) {
            when (dga?.assess(query.name)) {
                DgaDetector.Level.BLOCK -> if (blockSuspicious) {
                    event.verdict = Verdict.BLOCKED_BY_HEURISTIC
                    return Decision.Respond(pkt.reply(query.blockedResponse()), pkt, event)
                } else event.suspicious = true
                DgaDetector.Level.FLAG -> event.suspicious = true
                else -> Unit
            }
        }
        if (verdict == Verdict.BLOCKED_BY_LIST && compatMode != CompatMode.OFF && m.isCompat(query.name)) {
            val allowed = QueryEvent(event.timeMillis, query.name, query.type, Verdict.ALLOWED_FOR_COMPAT)
            val forward = Decision.Forward(pkt.payload, pkt, query, allowed, m)
            if (compatMode == CompatMode.EVERYWHERE) return forward
            return Decision.Respond(pkt.reply(query.blockedResponse()), pkt, event, compatFallback = forward)
        }
        if (verdict.blocked) return Decision.Respond(pkt.reply(query.blockedResponse()), pkt, event)
        // Reputation: only names no list or user rule has decided. The local
        // prefix check is in-memory; the shard fetch (rare) runs alongside the
        // upstream query in the forwarder, so it adds no latency to clean names.
        val rep = reputation
        val check = if (verdict == Verdict.ALLOWED && rep != null && rep.hasLocalHit(query.name)) {
            { rep.check(query.name) }
        } else null
        return Decision.Forward(pkt.payload, pkt, query, event, m, check)
    }

    companion object {
        const val DOH_CANARY = "use-application-dns.net"
    }
}
