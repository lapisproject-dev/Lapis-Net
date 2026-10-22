package net.lapisphilosophorum.lapisnet.onionwire

import java.time.Clock
import java.time.Instant
import java.time.ZoneId
import java.time.ZoneOffset

/** A manually advanced clock, starting at the real time so that peers' real-clock checks still agree. */
class WireTestClock(
    @Volatile var millis: Long = System.currentTimeMillis(),
) : Clock() {
    override fun getZone(): ZoneId = ZoneOffset.UTC

    override fun withZone(zone: ZoneId?): Clock = this

    override fun instant(): Instant = Instant.ofEpochMilli(millis)

    override fun millis(): Long = millis

    fun advanceSeconds(seconds: Long) {
        millis += seconds * 1000
    }
}
