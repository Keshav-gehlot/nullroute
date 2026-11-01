package io.github.keshavgehlot.nullroute.core

import java.net.InetAddress

/**
 * Minimal IPv4/IPv6 + UDP codec for the packets that reach the VPN interface.
 *
 * Only UDP is routed into the tunnel (and only to the fake DNS server
 * address), so this deliberately handles nothing else: anything unexpected
 * is rejected by returning null rather than guessed at.
 */
class UdpPacket(
    val version: Int,
    val source: ByteArray,       // 4 or 16 bytes
    val destination: ByteArray,  // 4 or 16 bytes
    val sourcePort: Int,
    val destinationPort: Int,
    val payload: ByteArray,
) {
    val sourceAddress: InetAddress get() = InetAddress.getByAddress(source)
    val destinationAddress: InetAddress get() = InetAddress.getByAddress(destination)

    /** Builds the reply packet: addresses and ports swapped, new payload. */
    fun reply(replyPayload: ByteArray): ByteArray =
        build(version, destination, source, destinationPort, sourcePort, replyPayload)

    companion object {
        const val PROTO_UDP = 17
        private const val IPV4_HEADER = 20
        private const val IPV6_HEADER = 40
        private const val UDP_HEADER = 8

        /** Parses a raw IP packet read from the tun device. */
        fun parse(buf: ByteArray, length: Int = buf.size): UdpPacket? {
            if (length < 1) return null
            return when (buf[0].toInt() ushr 4) {
                4 -> parseV4(buf, length)
                6 -> parseV6(buf, length)
                else -> null
            }
        }

        private fun parseV4(buf: ByteArray, length: Int): UdpPacket? {
            if (length < IPV4_HEADER + UDP_HEADER) return null
            val ihl = (buf[0].toInt() and 0x0f) * 4
            if (ihl < IPV4_HEADER) return null
            val total = u16(buf, 2)
            if (total > length || total < ihl + UDP_HEADER) return null
            if ((buf[9].toInt() and 0xff) != PROTO_UDP) return null
            // Fragmented datagrams (MF flag or non-zero offset) are not DNS we can answer.
            if ((u16(buf, 6) and 0x3fff) != 0) return null
            return parseUdp(4, buf.copyOfRange(12, 16), buf.copyOfRange(16, 20), buf, ihl, total)
        }

        private fun parseV6(buf: ByteArray, length: Int): UdpPacket? {
            if (length < IPV6_HEADER + UDP_HEADER) return null
            val payloadLength = u16(buf, 4)
            if ((buf[6].toInt() and 0xff) != PROTO_UDP) return null // no extension headers
            val total = IPV6_HEADER + payloadLength
            if (total > length) return null
            return parseUdp(6, buf.copyOfRange(8, 24), buf.copyOfRange(24, 40), buf, IPV6_HEADER, total)
        }

        private fun parseUdp(v: Int, src: ByteArray, dst: ByteArray, buf: ByteArray, off: Int, end: Int): UdpPacket? {
            val udpLen = u16(buf, off + 4)
            if (udpLen < UDP_HEADER || off + udpLen > end) return null
            return UdpPacket(
                version = v,
                source = src,
                destination = dst,
                sourcePort = u16(buf, off),
                destinationPort = u16(buf, off + 2),
                payload = buf.copyOfRange(off + UDP_HEADER, off + udpLen),
            )
        }

        fun build(version: Int, src: ByteArray, dst: ByteArray, srcPort: Int, dstPort: Int, payload: ByteArray): ByteArray {
            val udpLen = UDP_HEADER + payload.size
            return if (version == 4) {
                val out = ByteArray(IPV4_HEADER + udpLen)
                out[0] = 0x45
                put16(out, 2, out.size)
                out[6] = 0x40                   // Don't Fragment
                out[8] = 64                      // TTL
                out[9] = PROTO_UDP.toByte()
                System.arraycopy(src, 0, out, 12, 4)
                System.arraycopy(dst, 0, out, 16, 4)
                put16(out, 10, Checksum.of(out, 0, IPV4_HEADER))
                writeUdp(out, IPV4_HEADER, srcPort, dstPort, payload)
                put16(out, IPV4_HEADER + 6, Checksum.udp(src, dst, out, IPV4_HEADER, udpLen))
                out
            } else {
                val out = ByteArray(IPV6_HEADER + udpLen)
                out[0] = 0x60
                put16(out, 4, udpLen)
                out[6] = PROTO_UDP.toByte()
                out[7] = 64                      // hop limit
                System.arraycopy(src, 0, out, 8, 16)
                System.arraycopy(dst, 0, out, 24, 16)
                writeUdp(out, IPV6_HEADER, srcPort, dstPort, payload)
                put16(out, IPV6_HEADER + 6, Checksum.udp(src, dst, out, IPV6_HEADER, udpLen))
                out
            }
        }

        private fun writeUdp(out: ByteArray, off: Int, srcPort: Int, dstPort: Int, payload: ByteArray) {
            put16(out, off, srcPort)
            put16(out, off + 2, dstPort)
            put16(out, off + 4, UDP_HEADER + payload.size)
            System.arraycopy(payload, 0, out, off + UDP_HEADER, payload.size)
        }

        internal fun u16(b: ByteArray, i: Int) = ((b[i].toInt() and 0xff) shl 8) or (b[i + 1].toInt() and 0xff)
        internal fun put16(b: ByteArray, i: Int, v: Int) {
            b[i] = (v ushr 8).toByte(); b[i + 1] = v.toByte()
        }
    }
}

object Checksum {
    /** RFC 1071 Internet checksum over [off, off+len). */
    fun of(b: ByteArray, off: Int, len: Int, initial: Long = 0): Int = fold(sum(b, off, len, initial))

    /** UDP checksum including the IPv4/IPv6 pseudo-header. Never returns 0 (RFC 768). */
    fun udp(src: ByteArray, dst: ByteArray, packet: ByteArray, udpOff: Int, udpLen: Int): Int {
        val c = transport(UdpPacket.PROTO_UDP, src, dst, packet, udpOff, udpLen)
        return if (c == 0) 0xffff else c
    }

    /** TCP/UDP checksum over the pseudo-header (RFC 793 / RFC 8200 section 8.1) and segment. */
    fun transport(proto: Int, src: ByteArray, dst: ByteArray, packet: ByteArray, off: Int, len: Int): Int {
        var s = sum(src, 0, src.size, 0)
        s = sum(dst, 0, dst.size, s)
        s += proto.toLong()
        s += len.toLong()
        return fold(sum(packet, off, len, s))
    }

    private fun sum(b: ByteArray, off: Int, len: Int, initial: Long): Long {
        var s = initial
        var i = off
        val end = off + len
        while (i + 1 < end) {
            s += (((b[i].toInt() and 0xff) shl 8) or (b[i + 1].toInt() and 0xff)).toLong()
            i += 2
        }
        if (i < end) s += ((b[i].toInt() and 0xff) shl 8).toLong()
        return s
    }

    private fun fold(sum: Long): Int {
        var s = sum
        while (s ushr 16 != 0L) s = (s and 0xffff) + (s ushr 16)
        return (s.inv() and 0xffff).toInt()
    }
}
