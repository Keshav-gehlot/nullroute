package io.github.keshavgehlot.nullroute.core

/**
 * The parts of a DNS query (RFC 1035) needed to decide on and answer it.
 * Answers are built from the original query bytes so the transaction id,
 * flags and question are echoed exactly.
 */
class DnsQuery private constructor(
    val raw: ByteArray,
    val id: Int,
    val name: String,       // lower-case, no trailing dot
    val type: Int,
    val questionEnd: Int,   // offset just past QTYPE/QCLASS
) {
    /**
     * A "sinkhole" answer: A -> 0.0.0.0, AAAA -> ::, anything else (HTTPS,
     * SVCB, TXT…) -> NOERROR with no records. Returning an address instead of
     * NXDOMAIN stops many apps from retrying the lookup in a tight loop.
     */
    fun blockedResponse(ttl: Int = 60): ByteArray {
        val rdata = when (type) {
            TYPE_A -> ByteArray(4)
            TYPE_AAAA -> ByteArray(16)
            else -> null
        }
        val answerLen = if (rdata != null) 12 + rdata.size else 0
        val out = ByteArray(questionEnd + answerLen)
        System.arraycopy(raw, 0, out, 0, questionEnd)
        // QR=1, keep OPCODE and RD, RA=1, AA=0, TC=0, RCODE=NOERROR
        out[2] = (0x80 or (raw[2].toInt() and 0x79)).toByte()
        out[3] = 0x80.toByte()
        UdpPacket.put16(out, 4, 1)                       // QDCOUNT
        UdpPacket.put16(out, 6, if (rdata != null) 1 else 0) // ANCOUNT
        UdpPacket.put16(out, 8, 0)                       // NSCOUNT
        UdpPacket.put16(out, 10, 0)                      // ARCOUNT (EDNS OPT dropped)
        if (rdata != null) {
            var p = questionEnd
            UdpPacket.put16(out, p, 0xC00C); p += 2         // pointer to the question name
            UdpPacket.put16(out, p, type); p += 2
            UdpPacket.put16(out, p, CLASS_IN); p += 2
            out[p++] = (ttl ushr 24).toByte(); out[p++] = (ttl ushr 16).toByte()
            out[p++] = (ttl ushr 8).toByte(); out[p++] = ttl.toByte()
            UdpPacket.put16(out, p, rdata.size); p += 2
            System.arraycopy(rdata, 0, out, p, rdata.size)
        }
        return out
    }

    /** NXDOMAIN — used for the Firefox DoH canary domain. */
    fun nxdomainResponse(): ByteArray {
        val out = raw.copyOf(questionEnd)
        out[2] = (0x80 or (raw[2].toInt() and 0x79)).toByte()
        out[3] = 0x83.toByte() // RA=1, RCODE=3 (NXDOMAIN)
        UdpPacket.put16(out, 4, 1)
        for (i in 6..11) out[i] = 0
        return out
    }

    /** SERVFAIL, used when the upstream resolver can't be reached. */
    fun failureResponse(): ByteArray {
        val out = raw.copyOf(questionEnd)
        out[2] = (0x80 or (raw[2].toInt() and 0x79)).toByte()
        out[3] = 0x82.toByte() // RA=1, RCODE=2 (SERVFAIL)
        UdpPacket.put16(out, 4, 1)
        for (i in 6..11) out[i] = 0
        return out
    }

    companion object {
        const val TYPE_A = 1
        const val TYPE_AAAA = 28
        const val CLASS_IN = 1
        private const val HEADER = 12

        fun parse(msg: ByteArray): DnsQuery? {
            if (msg.size < HEADER + 5) return null
            val flags = UdpPacket.u16(msg, 2)
            if (flags and 0x8000 != 0) return null          // a response, not a query
            if ((flags ushr 11) and 0xf != 0) return null   // OPCODE must be QUERY
            if (UdpPacket.u16(msg, 4) != 1) return null      // exactly one question
            val sb = StringBuilder()
            var p = HEADER
            while (true) {
                if (p >= msg.size) return null
                val len = msg[p].toInt() and 0xff
                if (len == 0) { p++; break }
                if (len and 0xc0 != 0) return null           // compression in a question: refuse
                if (p + 1 + len > msg.size || sb.length + len + 1 > 254) return null
                if (sb.isNotEmpty()) sb.append('.')
                for (i in p + 1..p + len) {
                    val c = msg[i].toInt() and 0xff
                    sb.append(if (c in 'A'.code..'Z'.code) (c + 32).toChar() else c.toChar())
                }
                p += 1 + len
            }
            if (p + 4 > msg.size) return null
            return DnsQuery(msg, UdpPacket.u16(msg, 0), sb.toString(), UdpPacket.u16(msg, p), p + 4)
        }

        fun typeName(t: Int): String = when (t) {
            1 -> "A"; 2 -> "NS"; 5 -> "CNAME"; 6 -> "SOA"; 12 -> "PTR"; 15 -> "MX"
            16 -> "TXT"; 28 -> "AAAA"; 33 -> "SRV"; 64 -> "SVCB"; 65 -> "HTTPS"
            else -> "TYPE$t"
        }

        /**
         * Every CNAME target in a response's answer section, in order. Handles
         * name compression (RFC 1035 §4.1.4) with a hop limit so a malicious
         * pointer loop can't hang the resolver. Returns null if malformed.
         */
        fun cnameTargets(msg: ByteArray): List<String>? {
            if (msg.size < HEADER) return null
            val qd = UdpPacket.u16(msg, 4)
            val an = UdpPacket.u16(msg, 6)
            var p = HEADER
            repeat(qd) {
                p = skipName(msg, p) ?: return null
                p += 4
            }
            val out = ArrayList<String>(2)
            repeat(an) {
                p = skipName(msg, p) ?: return null
                if (p + 10 > msg.size) return null
                val type = UdpPacket.u16(msg, p)
                val rdlen = UdpPacket.u16(msg, p + 8)
                val rdata = p + 10
                if (rdata + rdlen > msg.size) return null
                if (type == TYPE_CNAME) out.add(readName(msg, rdata) ?: return null)
                p = rdata + rdlen
            }
            return out
        }

        private fun skipName(msg: ByteArray, start: Int): Int? {
            var p = start
            while (p < msg.size) {
                val len = msg[p].toInt() and 0xff
                when {
                    len == 0 -> return p + 1
                    len and 0xc0 == 0xc0 -> return if (p + 2 <= msg.size) p + 2 else null
                    len and 0xc0 != 0 -> return null
                    else -> p += 1 + len
                }
            }
            return null
        }

        private fun readName(msg: ByteArray, start: Int): String? {
            val sb = StringBuilder()
            var p = start
            var hops = 0
            while (true) {
                if (p >= msg.size) return null
                val len = msg[p].toInt() and 0xff
                if (len == 0) break
                if (len and 0xc0 == 0xc0) {
                    if (p + 1 >= msg.size || ++hops > 16) return null
                    p = ((len and 0x3f) shl 8) or (msg[p + 1].toInt() and 0xff)
                    continue
                }
                if (len and 0xc0 != 0 || p + 1 + len > msg.size || sb.length + len > 254) return null
                if (sb.isNotEmpty()) sb.append('.')
                for (i in p + 1..p + len) {
                    val c = msg[i].toInt() and 0xff
                    sb.append(if (c in 'A'.code..'Z'.code) (c + 32).toChar() else c.toChar())
                }
                p += 1 + len
            }
            return sb.toString()
        }

        const val TYPE_CNAME = 5

        /** Response id, for matching an upstream answer to its query. */
        fun responseId(msg: ByteArray): Int? = if (msg.size >= HEADER) UdpPacket.u16(msg, 0) else null
    }
}
