package net.lapisphilosophorum.lapisnet.madli

import io.github.oshai.kotlinlogging.KotlinLogging
import io.libp2p.core.PeerId
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.networking.relay.RelayReliabilityCounts

private val logger = KotlinLogging.logger {}

/**
 * Turns this node's locally observed relay reliability (`LapisNode.relayReliabilityCounts`) into
 * signed Madli vectors and announces them over [MadliGossip] - the WRITE side of the relay
 * reliability metric.
 *
 * **Readers before writers.** [enabled] defaults to `false`: nodes running a release that predates
 * the v2 vector format reject v2 vectors as `ValidationResult.Invalid`, which lowers the
 * GossipSub peer score of whoever forwards them. Publishing therefore stays off until a later
 * release has had time to roll out the decoder. When disabled, [publishForDay] does nothing.
 *
 * **Merge, never replace.** The vector index keeps exactly one vector per
 * `(observer, observedPeer, epochDay)` (latest wins). If this node already announced a core-metrics
 * vector for that tuple, a relay-only vector would displace it - so the existing own vector's core
 * block is carried into the new combined v2 vector.
 *
 * The same rule binds any future component that publishes core metrics for a tuple this publisher
 * may also have written: it must carry the relay block over, or it displaces it.
 *
 * No scheduling here: callers decide when to call [publishForDay] (once per UTC day for the
 * previous day is the intended cadence). Only relays with at least [minAttempts] attempts that day
 * are published, so a single failed dial does not brand a relay as unreliable.
 *
 * @param countsForDay e.g. `{ day -> node.relayReliabilityCounts(day) }`
 */
class MadliRelayReliabilityPublisher(
    private val gossip: MadliGossip,
    private val observer: Secp256k1KeyPair,
    private val countsForDay: (Long) -> Map<PeerId, RelayReliabilityCounts>,
    private val enabled: Boolean = false,
    private val minAttempts: Int = 3,
) {
    init {
        require(minAttempts >= 1) { "minAttempts must be >= 1: $minAttempts" }
    }

    /** Announces one vector per relay observed on [epochDay]; returns how many were announced
     * (`0` when disabled). */
    fun publishForDay(epochDay: Long): Int {
        if (!enabled) return 0
        var announced = 0
        for ((relay, counts) in countsForDay(epochDay)) {
            if (counts.attempts < minAttempts) continue
            try {
                val relayMetrics =
                    MadliRelayMetrics(
                        relayReliabilityMicros = counts.reliabilityMicros(),
                        relayAttemptCount = counts.attempts,
                    )
                val existing = gossip.ownVectorFor(observer.publicKey, relay, epochDay)
                val vector =
                    MadliDailyVector.create(
                        observer = observer,
                        observedPeer = relay,
                        epochDay = epochDay,
                        metrics = existing?.metrics,
                        relayMetrics = relayMetrics,
                    )
                gossip.announce(vector)
                announced++
            } catch (e: RuntimeException) {
                // One bad relay (e.g. a storage hiccup) must not stop the others.
                logger.warn(e) { "failed to publish relay reliability for $relay" }
            }
        }
        return announced
    }
}
