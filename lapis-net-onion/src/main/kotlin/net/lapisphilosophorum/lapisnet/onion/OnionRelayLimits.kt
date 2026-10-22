package net.lapisphilosophorum.lapisnet.onion

import java.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes

/** Hard resource bounds of one [OnionRelay]. Per-circuit memory is constant (two hop ciphers, two
 * table entries, a few counters; roughly 1 KiB), so these limits bound the relay's total memory. */
data class OnionRelayLimits(
    val maxCircuitsTotal: Int = 4096,
    val maxCircuitsPerLink: Int = 256,
    val createsPerSecondPerLink: Int = 20,
    val createsPerSecondTotal: Int = 200,
    val maxPendingExtends: Int = 512,
    val circuitMaxLifetime: Duration = 10.minutes,
    val cellsPerSecondPerCircuit: Int = 2000,
) {
    init {
        require(maxCircuitsTotal > 0 && maxCircuitsPerLink > 0 && maxPendingExtends >= 0) { "limits must be positive" }
        require(createsPerSecondPerLink >= 0 && createsPerSecondTotal >= 0 && cellsPerSecondPerCircuit >= 0) {
            "rates must not be negative"
        }
    }
}

/** Token bucket with burst capacity equal to the per-second rate; refilled lazily from an injected
 * [Clock]. */
internal class TokenBucket(
    private val ratePerSecond: Int,
    private val clock: Clock,
) {
    private var tokens = ratePerSecond.toDouble()
    private var lastMillis = clock.millis()

    @Synchronized
    fun tryAcquire(): Boolean {
        val now = clock.millis()
        val elapsed = (now - lastMillis).coerceAtLeast(0)
        lastMillis = now
        tokens = minOf(ratePerSecond.toDouble(), tokens + elapsed * ratePerSecond / 1000.0)
        if (tokens >= 1.0) {
            tokens -= 1.0
            return true
        }
        return false
    }
}
