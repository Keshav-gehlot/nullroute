package io.github.keshavgehlot.nullroute.core

import java.io.BufferedReader

enum class Verdict(val blocked: Boolean) {
    ALLOWED(false),
    ALLOWED_BY_LIST(false),  // filter-list exception (@@||domain^)
    ALLOWED_BY_USER(false),
    BLOCKED_BY_LIST(true),
    BLOCKED_BY_USER(true),
    /** The name looked harmless but its answer aliased (CNAME) to a tracker. */
    BLOCKED_BY_CNAME(true),
    /** use-application-dns.net: answered NXDOMAIN so Firefox keeps using system DNS. */
    DOH_CANARY(false),
    /** On no list, but the name looks algorithmically generated (opt-in blocking). */
    BLOCKED_BY_HEURISTIC(true),
    /** On a phishing / malware feed, confirmed by a privacy-preserving hash lookup. */
    BLOCKED_BY_REPUTATION(true),
    /** Blocked by the TLS SNI or HTTP Host of a connection (full-tunnel mode). */
    BLOCKED_BY_SNI(true),
}

/**
 * Suffix matcher: an entry for "example.com" also covers "ads.example.com".
 * Lookup walks the name's parent domains, so cost is O(labels) hash probes
 * regardless of list size (~120k domains).
 *
 * Precedence: user allow > user block > list allow > list block.
 */
class DomainMatcher(
    private val listBlocked: Set<String>,
    private val listAllowed: Set<String> = emptySet(),
    private val userBlocked: Set<String> = emptySet(),
    private val userAllowed: Set<String> = emptySet(),
    private val cnameTargets: Set<String> = emptySet(),
) {
    val size: Int get() = listBlocked.size

    fun verdict(name: String): Verdict {
        if (name.isEmpty()) return Verdict.ALLOWED
        if (matches(name, userAllowed)) return Verdict.ALLOWED_BY_USER
        if (matches(name, userBlocked)) return Verdict.BLOCKED_BY_USER
        if (matches(name, listAllowed)) return Verdict.ALLOWED_BY_LIST
        if (matches(name, listBlocked)) return Verdict.BLOCKED_BY_LIST
        return Verdict.ALLOWED
    }

    fun withUserRules(blocked: Set<String>, allowed: Set<String>) =
        DomainMatcher(listBlocked, listAllowed, blocked, allowed, cnameTargets)

    /**
     * Should a lookup be blocked because its answer aliases to [target]?
     * Uses the normal lists plus trackers known to hide behind CNAMEs, but a
     * user or list allow rule for the target still wins.
     */
    fun blocksCnameTarget(target: String): Boolean {
        val v = verdict(target)
        if (v == Verdict.ALLOWED_BY_USER || v == Verdict.ALLOWED_BY_LIST) return false
        return v.blocked || matches(target, cnameTargets)
    }

    private fun matches(name: String, set: Set<String>): Boolean {
        if (set.isEmpty()) return false
        if (name in set) return true
        var i = name.indexOf('.')
        while (i != -1) {
            if (name.substring(i + 1) in set) return true
            i = name.indexOf('.', i + 1)
        }
        return false
    }

    companion object {
        private val DOMAIN = Regex("^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?:\\.(?!-)[a-z0-9-]{1,63})+$")

        fun isValidDomain(d: String) = DOMAIN.matches(d)

        /**
         * Reads a compiled list: one domain per line, '#' comments. Also accepts
         * hosts-file lines ("0.0.0.0 domain") so users can point at other lists.
         */
        fun readList(reader: BufferedReader): HashSet<String> {
            val out = HashSet<String>(150_000)
            reader.forEachLine { raw ->
                val line = raw.substringBefore('#').trim()
                if (line.isEmpty()) return@forEachLine
                val parts = line.split(' ', '\t').filter { it.isNotEmpty() }
                val d = (if (parts.size >= 2) parts[1] else parts[0]).lowercase().trimEnd('.')
                if (d != "localhost" && isValidDomain(d)) out.add(d)
            }
            return out
        }

        /** Normalises user input such as "https://www.Example.com/path". */
        fun normalize(input: String): String? {
            var s = input.trim().lowercase()
            s = s.substringAfter("://").substringBefore('/').substringBefore(':').trimEnd('.')
            s = s.removePrefix("*.")
            return s.takeIf { isValidDomain(it) }
        }
    }
}
