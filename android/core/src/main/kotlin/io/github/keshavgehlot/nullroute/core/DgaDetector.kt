package io.github.keshavgehlot.nullroute.core

import java.io.BufferedReader

/**
 * Spots algorithmically generated domains (malware DGAs, throwaway tracker
 * domains) that are on no list yet, using a character-bigram model of what real
 * domain names look like. Trained and evaluated in compiler/nullroute_compiler/dga.py:
 * against 25 DGA families it catches ~54% at a 0.5% false-positive rate (flag)
 * and ~35% at 0.1% (block) — roughly 10x the recall of a Shannon-entropy
 * threshold at the same false-positive rate.
 *
 * Only the label the registrant chose is scored, so random-looking CDN hosts
 * (d1a2b3.cloudfront.net, r4---sn-x.googlevideo.com) are judged as
 * "cloudfront" / "googlevideo" and never flagged.
 */
class DgaDetector(
    private val alphabet: String,
    private val table: Array<DoubleArray>,   // rows: '^' + alphabet, cols: alphabet + '$'
    val flagThreshold: Double,
    val blockThreshold: Double,
    private val minLength: Int,
    private val multiPartSuffixes: Set<String>,
) {
    enum class Level { NONE, FLAG, BLOCK }

    fun siteLabel(name: String): String? {
        val parts = name.lowercase().trimEnd('.').split('.')
        if (parts.size < 2) return null
        if (parts.size >= 3 && parts.takeLast(2).joinToString(".") in multiPartSuffixes) return parts[parts.size - 3]
        return parts[parts.size - 2]
    }

    /** Mean log-likelihood per transition, or null when the name can't be judged. */
    fun score(name: String): Double? {
        if (name.endsWith(".arpa") || name.endsWith(".local") || name.endsWith(".lan")) return null
        val label = siteLabel(name) ?: return null
        if (label.length < minLength || label.startsWith("xn--") || label.any { alphabet.indexOf(it) < 0 }) return null
        var sum = 0.0
        var prevRow = 0                                   // '^'
        for (c in label) {
            val col = alphabet.indexOf(c)
            sum += table[prevRow][col]
            prevRow = col + 1
        }
        sum += table[prevRow][alphabet.length]            // '$'
        return sum / (label.length + 1)
    }

    fun assess(name: String): Level {
        val s = score(name) ?: return Level.NONE
        return when {
            s < blockThreshold -> Level.BLOCK
            s < flagThreshold -> Level.FLAG
            else -> Level.NONE
        }
    }

    companion object {
        /** Reads dns/dga_model.txt produced by the compiler. */
        fun read(reader: BufferedReader): DgaDetector {
            val lines = reader.readLines()
            val (flag, block, minLen) = lines[0].trim().split(' ')
            val alphabet = lines[1].trim()
            val suffixes = lines[2].trim().split(' ').filter { it.isNotEmpty() }.toSet()
            val rows = lines.drop(3).filter { it.isNotBlank() }.map { l ->
                l.trim().split(' ').map(String::toDouble).toDoubleArray()
            }
            require(rows.size == alphabet.length + 1 && rows.all { it.size == alphabet.length + 1 }) {
                "Malformed DGA model"
            }
            return DgaDetector(alphabet, rows.toTypedArray(), flag.toDouble(), block.toDouble(), minLen.toInt(), suffixes)
        }
    }
}
