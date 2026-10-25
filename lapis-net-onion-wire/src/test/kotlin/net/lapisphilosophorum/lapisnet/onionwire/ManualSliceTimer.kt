package net.lapisphilosophorum.lapisnet.onionwire

import java.util.PriorityQueue

/**
 * A timer driven by hand together with a [WireTestClock]: tasks run when [advanceTo] passes their time, in order, with
 * the clock set to the task's time while it runs. Counts how many entries are outstanding.
 */
internal class ManualSliceTimer(
    private val clock: WireTestClock,
) : SliceTimer {
    private class Entry(
        val at: Long,
        val seq: Long,
        val task: Runnable,
    ) : Comparable<Entry> {
        @Volatile var cancelled = false

        override fun compareTo(other: Entry): Int = compareValuesBy(this, other, { it.at }, { it.seq })
    }

    private val queue = PriorityQueue<Entry>()
    private var seq = 0L

    /** `true` makes [schedule] return null, like a timer that was shut down. */
    @Volatile var shutdown = false

    @Synchronized
    override fun schedule(
        delayMillis: Long,
        task: Runnable,
    ): Cancellable? {
        if (shutdown) return null
        val e = Entry(clock.millis() + delayMillis, seq++, task)
        queue.add(e)
        return Cancellable { e.cancelled = true }
    }

    @Synchronized
    fun pending(): Int = queue.count { !it.cancelled }

    /** Runs everything due up to [time] (inclusive), advancing the clock. */
    fun advanceTo(time: Long) {
        while (true) {
            val next =
                synchronized(this) {
                    queue.removeAll { it.cancelled }
                    queue.peek()?.takeIf { it.at <= time }?.also { queue.poll() }
                } ?: break
            clock.millis = maxOf(clock.millis, next.at)
            next.task.run()
        }
        clock.millis = maxOf(clock.millis, time)
    }

    fun advanceBy(millis: Long) = advanceTo(clock.millis() + millis)
}
