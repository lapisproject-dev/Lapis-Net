package net.lapisphilosophorum.lapisnet.onionwire.anonymity

import net.lapisphilosophorum.lapisnet.networking.config.AnonymityPaddingMode

/**
 * Padding and timing protection of anonymity mode (wave V0.10.0-H). Every default is an *assumption awaiting
 * confirmation* (docs/anonymity.adoc, "Assumptions awaiting confirmation (wave H)"). All values are validated: each one
 * bounds a resource (bandwidth, memory, timer rate) that must never be zero, negative or unbounded.
 */
data class TrafficPaddingConfig(
    /** Frames are padded to size classes (inside the end-to-end encrypted stream). */
    val sizeClasses: Boolean = true,
    /** Cover cells (relay DROP towards [coverTargetHop]) are sent on a randomised schedule. */
    val cover: Boolean = true,
    /** Outgoing cells leave only at the boundaries of time slices of [sliceMillis]. */
    val slicing: Boolean = true,
    val sliceMillis: Long = 50,
    /** Base rate: the next cover cell follows after U(0.5, 1.5) times this (with the default jitter). */
    val coverMeanIntervalMillis: Long = 4_000,
    val coverJitterFraction: Double = 0.5,
    /** A slice with real cells is followed by at least this many slices with one cell each (budget permitting). */
    val burstTailSlices: Int = 3,
    /** Hard cap of cover traffic (token bucket); real traffic never draws from it. */
    val coverBudgetBytesPerSecond: Int = 1024,
    val coverBudgetBurstCells: Int = 16,
    /** The hop that discards the cover cell. Never 1: the guard would recognise the cover. */
    val coverTargetHop: Int = 2,
) {
    init {
        require(sliceMillis in 20..100) { "sliceMillis must be in 20..100" }
        require(coverMeanIntervalMillis in 100..3_600_000) { "coverMeanIntervalMillis must be in 100..3600000" }
        require(coverJitterFraction in 0.0..0.9) { "coverJitterFraction must be in 0..0.9" }
        require(burstTailSlices in 0..100) { "burstTailSlices must be in 0..100" }
        require(coverBudgetBytesPerSecond in 1..16_384) { "coverBudgetBytesPerSecond must be in 1..16384" }
        require(coverBudgetBurstCells in 1..1_000) { "coverBudgetBurstCells must be in 1..1000" }
        require(coverTargetHop >= 2) { "coverTargetHop must be at least 2" }
    }

    /** The mode as shown to an operator: `standard` unless everything is off. */
    val wireMode: String get() = if (sizeClasses || cover || slicing) "standard" else "off"

    companion object {
        val STANDARD = TrafficPaddingConfig()
        val OFF = TrafficPaddingConfig(sizeClasses = false, cover = false, slicing = false)

        fun of(mode: AnonymityPaddingMode): TrafficPaddingConfig =
            when (mode) {
                AnonymityPaddingMode.STANDARD -> STANDARD
                AnonymityPaddingMode.OFF -> OFF
            }
    }
}
