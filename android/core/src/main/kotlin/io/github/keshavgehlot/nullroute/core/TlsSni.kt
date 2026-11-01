package io.github.keshavgehlot.nullroute.core

/**
 * Reads the server name a client is connecting to from the first bytes it
 * sends: the SNI extension of a TLS ClientHello (RFC 8446 / RFC 6066), or the
 * Host header of a plain HTTP/1.x request. Used by full-tunnel mode to block
 * connections that never went through our DNS (apps with their own resolver,
 * DNS-over-HTTPS, hard-coded IPs).
 *
 * Parsers are incremental: they return [NeedMore] until enough bytes have
 * arrived, so a ClientHello split across TCP segments (common with
 * post-quantum key shares, ~1.8 KB) is handled.
 */
sealed interface ServerName {
    /** Not enough bytes yet. */
    data object NeedMore : ServerName
    /** Not TLS / HTTP, or carries no name: nothing to judge. */
    data object None : ServerName
    /**
     * @param ech the ClientHello carries an Encrypted Client Hello extension, so
     *   [host] is the outer (public) name, e.g. a CDN's, not the real site.
     */
    data class Found(val host: String, val ech: Boolean = false) : ServerName
}

object TlsSni {
    private const val CONTENT_HANDSHAKE = 22
    private const val HANDSHAKE_CLIENT_HELLO = 1
    private const val EXT_SERVER_NAME = 0x0000
    private const val EXT_ECH = 0xfe0d
    /** A ClientHello larger than this is not something we'll buffer. */
    const val MAX_HELLO = 16 * 1024

    fun parse(b: ByteArray, len: Int = b.size): ServerName {
        if (len < 1) return ServerName.NeedMore
        if ((b[0].toInt() and 0xff) != CONTENT_HANDSHAKE) return ServerName.None
        if (len >= 2 && (b[1].toInt() and 0xff) != 3) return ServerName.None
        // Reassemble the handshake message from one or more TLS records.
        val hs = java.io.ByteArrayOutputStream()
        var pos = 0
        var need = -1
        while (true) {
            if (pos + 5 > len) return ServerName.NeedMore
            if ((b[pos].toInt() and 0xff) != CONTENT_HANDSHAKE) return ServerName.None
            val recLen = u16(b, pos + 3)
            if (recLen == 0 || recLen > 16384 + 256) return ServerName.None
            if (pos + 5 + recLen > len) {
                if (pos + 5 + recLen > MAX_HELLO + 5 * 4) return ServerName.None
                return ServerName.NeedMore
            }
            hs.write(b, pos + 5, recLen)
            pos += 5 + recLen
            val h = hs.toByteArray()
            if (need < 0 && h.size >= 4) {
                if ((h[0].toInt() and 0xff) != HANDSHAKE_CLIENT_HELLO) return ServerName.None
                need = 4 + ((h[1].toInt() and 0xff) shl 16 or u16(h, 2))
                if (need > MAX_HELLO) return ServerName.None
            }
            if (need in 0..h.size) return parseHello(h, need)
        }
    }

    private fun parseHello(h: ByteArray, end: Int): ServerName {
        var p = 4 + 2 + 32                       // header, legacy_version, random
        if (p + 1 > end) return ServerName.None
        p += 1 + (h[p].toInt() and 0xff)         // session id
        if (p + 2 > end) return ServerName.None
        p += 2 + u16(h, p)                       // cipher suites
        if (p + 1 > end) return ServerName.None
        p += 1 + (h[p].toInt() and 0xff)         // compression methods
        if (p + 2 > end) return ServerName.None  // no extensions at all
        val extEnd = p + 2 + u16(h, p)
        if (extEnd > end) return ServerName.None
        p += 2
        var host: String? = null
        var ech = false
        while (p + 4 <= extEnd) {
            val type = u16(h, p)
            val l = u16(h, p + 2)
            val body = p + 4
            if (body + l > extEnd) return ServerName.None
            when (type) {
                EXT_ECH -> ech = true
                EXT_SERVER_NAME -> host = parseSni(h, body, body + l)
            }
            p = body + l
        }
        return host?.let { ServerName.Found(it, ech) } ?: ServerName.None
    }

    private fun parseSni(h: ByteArray, start: Int, end: Int): String? {
        if (start + 2 > end) return null
        var p = start + 2
        val listEnd = minOf(end, p + u16(h, start))
        while (p + 3 <= listEnd) {
            val type = h[p].toInt() and 0xff
            val l = u16(h, p + 1)
            if (p + 3 + l > listEnd) return null
            if (type == 0) return normalizeHost(String(h, p + 3, l, Charsets.US_ASCII))
            p += 3 + l
        }
        return null
    }

    internal fun u16(b: ByteArray, i: Int) = ((b[i].toInt() and 0xff) shl 8) or (b[i + 1].toInt() and 0xff)

    internal fun normalizeHost(raw: String): String? {
        val h = raw.trim().lowercase().trimEnd('.')
        return h.takeIf { DomainMatcher.isValidDomain(it) }
    }
}

object HttpHost {
    private val METHODS = listOf("GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ")
    private const val MAX_HEADERS = 8 * 1024

    fun parse(b: ByteArray, len: Int = b.size): ServerName {
        val head = String(b, 0, minOf(len, MAX_HEADERS), Charsets.ISO_8859_1)
        val method = METHODS.firstOrNull { head.startsWith(it) || it.startsWith(head) } ?: return ServerName.None
        if (head.length < method.length) return ServerName.NeedMore
        val end = head.indexOf("\r\n\r\n")
        if (end < 0) return if (len >= MAX_HEADERS) ServerName.None else ServerName.NeedMore
        for (line in head.substring(0, end).split("\r\n").drop(1)) {
            val colon = line.indexOf(':')
            if (colon > 0 && line.substring(0, colon).trim().equals("host", ignoreCase = true)) {
                var v = line.substring(colon + 1).trim()
                if (v.startsWith("[")) return ServerName.None      // IPv6 literal
                v = v.substringBefore(':')
                return TlsSni.normalizeHost(v)?.let { ServerName.Found(it) } ?: ServerName.None
            }
        }
        return ServerName.None
    }
}
