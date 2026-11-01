package io.github.keshavgehlot.nullroute.core

/** The IP layer of a packet read from the tun device (full-tunnel mode). */
class IpHeader(
    val version: Int,
    val protocol: Int,
    val source: ByteArray,
    val destination: ByteArray,
    /** Offset of the transport header. */
    val payloadOffset: Int,
    /** End of the IP packet (exclusive). */
    val end: Int,
) {
    companion object {
        const val PROTO_TCP = 6
        const val PROTO_UDP = 17

        fun parse(buf: ByteArray, length: Int): IpHeader? {
            if (length < 1) return null
            return when (buf[0].toInt() ushr 4) {
                4 -> {
                    if (length < 20) return null
                    val ihl = (buf[0].toInt() and 0x0f) * 4
                    val total = UdpPacket.u16(buf, 2)
                    if (ihl < 20 || total > length || total < ihl) return null
                    if ((UdpPacket.u16(buf, 6) and 0x3fff) != 0) return null // fragments
                    IpHeader(4, buf[9].toInt() and 0xff, buf.copyOfRange(12, 16), buf.copyOfRange(16, 20), ihl, total)
                }
                6 -> {
                    if (length < 40) return null
                    val total = 40 + UdpPacket.u16(buf, 4)
                    if (total > length) return null
                    IpHeader(6, buf[6].toInt() and 0xff, buf.copyOfRange(8, 24), buf.copyOfRange(24, 40), 40, total)
                }
                else -> null
            }
        }
    }
}

/** One TCP segment (RFC 9293). Sequence numbers are unsigned 32-bit values held in Longs. */
class TcpSegment(
    val version: Int,
    val source: ByteArray,
    val destination: ByteArray,
    val sourcePort: Int,
    val destinationPort: Int,
    val seq: Long,
    val ack: Long,
    val flags: Int,
    val window: Int,
    /** MSS option, only parsed on SYN segments. */
    val mss: Int?,
    val payload: ByteArray,
) {
    fun has(flag: Int) = flags and flag != 0

    companion object {
        const val FIN = 0x01
        const val SYN = 0x02
        const val RST = 0x04
        const val PSH = 0x08
        const val ACK = 0x10

        fun parse(buf: ByteArray, length: Int): TcpSegment? {
            val ip = IpHeader.parse(buf, length) ?: return null
            if (ip.protocol != IpHeader.PROTO_TCP) return null
            val o = ip.payloadOffset
            if (ip.end - o < 20) return null
            val dataOff = ((buf[o + 12].toInt() and 0xff) ushr 4) * 4
            if (dataOff < 20 || o + dataOff > ip.end) return null
            val flags = buf[o + 13].toInt() and 0x3f
            var mss: Int? = null
            if (flags and SYN != 0) {
                var p = o + 20
                while (p < o + dataOff) {
                    when (val kind = buf[p].toInt() and 0xff) {
                        0 -> break
                        1 -> p++
                        else -> {
                            if (p + 1 >= o + dataOff) break
                            val l = buf[p + 1].toInt() and 0xff
                            if (l < 2) break
                            if (kind == 2 && l == 4) mss = UdpPacket.u16(buf, p + 2)
                            p += l
                        }
                    }
                }
            }
            return TcpSegment(
                ip.version, ip.source, ip.destination,
                UdpPacket.u16(buf, o), UdpPacket.u16(buf, o + 2),
                u32(buf, o + 4), u32(buf, o + 8), flags, UdpPacket.u16(buf, o + 14), mss,
                buf.copyOfRange(o + dataOff, ip.end),
            )
        }

        fun build(
            version: Int, src: ByteArray, dst: ByteArray, srcPort: Int, dstPort: Int,
            seq: Long, ack: Long, flags: Int, window: Int,
            payload: ByteArray = EMPTY, payloadOff: Int = 0, payloadLen: Int = payload.size, mss: Int? = null,
        ): ByteArray {
            val optLen = if (mss != null) 4 else 0
            val tcpLen = 20 + optLen + payloadLen
            val ipLen = if (version == 4) 20 else 40
            val out = ByteArray(ipLen + tcpLen)
            if (version == 4) {
                out[0] = 0x45
                UdpPacket.put16(out, 2, out.size)
                out[6] = 0x40
                out[8] = 64
                out[9] = IpHeader.PROTO_TCP.toByte()
                System.arraycopy(src, 0, out, 12, 4)
                System.arraycopy(dst, 0, out, 16, 4)
                UdpPacket.put16(out, 10, Checksum.of(out, 0, 20))
            } else {
                out[0] = 0x60
                UdpPacket.put16(out, 4, tcpLen)
                out[6] = IpHeader.PROTO_TCP.toByte()
                out[7] = 64
                System.arraycopy(src, 0, out, 8, 16)
                System.arraycopy(dst, 0, out, 24, 16)
            }
            val o = ipLen
            UdpPacket.put16(out, o, srcPort)
            UdpPacket.put16(out, o + 2, dstPort)
            put32(out, o + 4, seq)
            put32(out, o + 8, ack)
            out[o + 12] = (((20 + optLen) / 4) shl 4).toByte()
            out[o + 13] = flags.toByte()
            UdpPacket.put16(out, o + 14, window)
            if (mss != null) {
                out[o + 20] = 2; out[o + 21] = 4
                UdpPacket.put16(out, o + 22, mss)
            }
            System.arraycopy(payload, payloadOff, out, o + 20 + optLen, payloadLen)
            UdpPacket.put16(out, o + 16, Checksum.transport(IpHeader.PROTO_TCP, src, dst, out, o, tcpLen))
            return out
        }

        private val EMPTY = ByteArray(0)

        fun u32(b: ByteArray, i: Int): Long =
            ((b[i].toLong() and 0xff) shl 24) or ((b[i + 1].toLong() and 0xff) shl 16) or
                ((b[i + 2].toLong() and 0xff) shl 8) or (b[i + 3].toLong() and 0xff)

        private fun put32(b: ByteArray, i: Int, v: Long) {
            b[i] = (v ushr 24).toByte(); b[i + 1] = (v ushr 16).toByte(); b[i + 2] = (v ushr 8).toByte(); b[i + 3] = v.toByte()
        }

        /** a + n mod 2^32 */
        fun seqAdd(a: Long, n: Long) = (a + n) and 0xffffffffL
        /** Signed distance b - a in sequence space. */
        fun seqDiff(b: Long, a: Long): Long = ((b - a) and 0xffffffffL).toInt().toLong()
    }
}
