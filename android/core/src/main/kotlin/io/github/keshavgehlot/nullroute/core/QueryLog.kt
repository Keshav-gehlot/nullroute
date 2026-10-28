package io.github.keshavgehlot.nullroute.core

/**
 * Fixed-size ring buffer of recent queries, newest first. Kept in memory only:
 * the app never writes browsing history to disk.
 */
class QueryLog(private val capacity: Int = 500) {
    private val items = ArrayDeque<QueryEvent>(capacity)
    private var blocked = 0L
    private var total = 0L

    @Synchronized
    fun add(e: QueryEvent) {
        if (items.size == capacity) items.removeLast()
        items.addFirst(e)
        total++
        if (e.verdict.blocked) blocked++
    }

    @Synchronized
    fun snapshot(): List<QueryEvent> = items.toList()

    @Synchronized
    fun counts(): Pair<Long, Long> = blocked to total

    @Synchronized
    fun clear() {
        items.clear(); blocked = 0; total = 0
    }
}
