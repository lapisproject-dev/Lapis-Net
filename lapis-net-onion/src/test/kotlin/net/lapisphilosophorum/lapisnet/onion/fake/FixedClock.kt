package net.lapisphilosophorum.lapisnet.onion.fake

import java.time.Clock
import java.time.Instant
import java.time.ZoneId

/** A manually advanced clock for deterministic rate-limit, lifetime and expiry tests. */
class FixedClock(
    var millis: Long = START_MILLIS,
) : Clock() {
    override fun getZone(): ZoneId = ZoneId.of("UTC")

    override fun withZone(zone: ZoneId?): Clock = this

    override fun instant(): Instant = Instant.ofEpochMilli(millis)

    override fun millis(): Long = millis

    fun advanceMillis(delta: Long) {
        millis += delta
    }

    companion object {
        const val START_MILLIS = 1_800_000_000_000L
    }
}
