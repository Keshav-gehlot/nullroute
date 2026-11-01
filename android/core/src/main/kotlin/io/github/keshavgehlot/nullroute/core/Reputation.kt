package io.github.keshavgehlot.nullroute.core

import java.security.MessageDigest

/**
 * Phishing / malware reputation without revealing browsing to a server, in the
 * style of Google Safe Browsing's Update API (format: compiler/nullroute_compiler/reputation.py).
 *
 * Every lookup is first checked against a local set of 32-bit SHA-256 prefixes
 * of ~2.4M listed domains. Only on a local hit (a listed domain, or a ~1-in-1,800
 * coincidence for a clean one) is a shard fetched: the 8-byte hash heads of every
 * listed domain sharing the first 12 bits. The server sees which of 4,096
 * buckets was requested, never the name, and shards are cached.
 *
 * Shards are fetched fresh, so a stale local prefix set still gets current
 * answers, and each one is checked structurally (sorted, all in the bucket)
 * rather than pinned to a hash that would go stale with every list build.
 */
class ReputationChecker(
    private val prefixes: PrefixSet,
    /** Fetches rep/shards/XYZ.bin; null on network failure. Called off the packet thread. */
    private val fetchShard: (String) -> ByteArray?,
    private val clock: () -> Long = System::currentTimeMillis,
    private val shardTtlMs: Long = 6 * 3600_000L,
    private val cacheSize: Int = 256,
) {
    sealed interface Result {
        data object Clean : Result
        data class Listed(val expression: String) : Result
        /** Shard couldn't be fetched or was malformed: fail open, but say so. */
        data object Unavailable : Result
    }

    val size: Int get() = prefixes.size

    private class Cached(val heads: Set<Long>, val at: Long)

    private val cache = object : LinkedHashMap<Int, Cached>(64, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Int, Cached>) = size > cacheSize
    }

    /** Cheap, local, no I/O: does any lookup expression of [name] hit the prefix set? */
    fun hasLocalHit(name: String): Boolean = localHits(name).isNotEmpty()

    /** Full check; may block on one shard fetch per distinct 12-bit bucket. */
    fun check(name: String): Result {
        var unavailable = false
        for ((expr, digest) in localHits(name)) {
            val heads = shard(shardIndex(digest)) ?: run { unavailable = true; null } ?: continue
            if (head64(digest) in heads) return Result.Listed(expr)
        }
        return if (unavailable) Result.Unavailable else Result.Clean
    }

    private fun localHits(name: String): List<Pair<String, ByteArray>> =
        expressions(name).mapNotNull { e ->
            val d = sha256(e)
            if (prefixes.contains(prefix32(d))) e to d else null
        }

    private fun shard(index: Int): Set<Long>? {
        synchronized(cache) {
            cache[index]?.let { if (clock() - it.at < shardTtlMs) return it.heads }
        }
        val name = "%03x".format(index)
        val data = fetchShard(name) ?: return null
        if (data.size % HEAD_BYTES != 0) return null
        val heads = HashSet<Long>(data.size / HEAD_BYTES * 2)
        var prev: Long? = null
        for (i in data.indices step HEAD_BYTES) {
            val h = readLong(data, i)
            // Must be strictly increasing (unsigned) and inside the requested bucket.
            if ((h ushr (64 - SHARD_BITS)).toInt() != index) return null
            if (prev != null && java.lang.Long.compareUnsigned(prev, h) >= 0) return null
            prev = h
            heads.add(h)
        }
        synchronized(cache) { cache[index] = Cached(heads, clock()) }
        return heads
    }

    companion object {
        const val SHARD_BITS = 12
        const val SHARDS = 1 shl SHARD_BITS
        const val HEAD_BYTES = 8

        /** The host and each parent with at least two labels, as the compiler hashes them. */
        fun expressions(host: String): List<String> {
            val h = host.lowercase().trimEnd('.')
            if (!h.contains('.')) return emptyList()
            val out = mutableListOf(h)
            var i = h.indexOf('.')
            while (i != -1) {
                val rest = h.substring(i + 1)
                if (!rest.contains('.')) break
                out.add(rest)
                i = h.indexOf('.', i + 1)
            }
            return out
        }

        fun sha256(s: String): ByteArray = sha256(s.toByteArray(Charsets.US_ASCII))
        fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)
        fun prefix32(d: ByteArray): Int =
            (d[0].toInt() and 0xff shl 24) or (d[1].toInt() and 0xff shl 16) or (d[2].toInt() and 0xff shl 8) or (d[3].toInt() and 0xff)
        fun shardIndex(d: ByteArray): Int = prefix32(d) ushr (32 - SHARD_BITS)
        fun head64(d: ByteArray): Long = readLong(d, 0)
        private fun readLong(b: ByteArray, off: Int): Long {
            var v = 0L
            for (i in 0 until 8) v = (v shl 8) or (b[off + i].toLong() and 0xff)
            return v
        }
    }
}

/** Sorted unsigned 32-bit prefixes, decoded from the compiler's Golomb-Rice format. */
class PrefixSet private constructor(private val sorted: IntArray) {
    val size: Int get() = sorted.size

    // Values are stored with the sign bit flipped so signed order == unsigned order.
    fun contains(prefix: Int): Boolean = java.util.Arrays.binarySearch(sorted, prefix xor Int.MIN_VALUE) >= 0

    companion object {
        private val MAGIC = byteArrayOf('N'.code.toByte(), 'R'.code.toByte(), 'P'.code.toByte(), '1'.code.toByte())

        fun decode(blob: ByteArray): PrefixSet {
            require(blob.size >= 13 && blob.copyOf(4).contentEquals(MAGIC)) { "not a NullRoute prefix set" }
            val count = u32(blob, 4).toInt()
            val k = blob[8].toInt() and 0xff
            require(count >= 0 && k <= 31) { "bad prefix set header" }
            val out = IntArray(count)
            if (count == 0) return PrefixSet(out)
            var cur = u32(blob, 9)
            out[0] = cur.toInt() xor Int.MIN_VALUE
            var pos = 13L * 8
            val total = blob.size.toLong() * 8
            fun bit(): Int {
                require(pos < total) { "truncated prefix set" }
                val b = (blob[(pos ushr 3).toInt()].toInt() ushr (7 - (pos and 7).toInt())) and 1
                pos++
                return b
            }
            for (i in 1 until count) {
                var q = 0L
                while (bit() == 1) q++
                var r = 0L
                repeat(k) { r = (r shl 1) or bit().toLong() }
                cur += (q shl k) or r
                require(cur <= 0xffffffffL) { "prefix overflow" }
                out[i] = cur.toInt() xor Int.MIN_VALUE
            }
            return PrefixSet(out)
        }

        private fun u32(b: ByteArray, off: Int): Long =
            ((b[off].toLong() and 0xff) shl 24) or ((b[off + 1].toLong() and 0xff) shl 16) or
                ((b[off + 2].toLong() and 0xff) shl 8) or (b[off + 3].toLong() and 0xff)
    }
}
