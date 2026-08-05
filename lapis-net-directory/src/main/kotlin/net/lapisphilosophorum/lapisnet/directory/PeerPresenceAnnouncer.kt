package net.lapisphilosophorum.lapisnet.directory

import java.time.Instant

/**
 * Client-side rate limiter wrapping [PeerDirectoryGossip.announce] with an enforced
 * minimum-republish-interval - a PARTIAL mitigation for the "known, accepted tension" with the
 * original spec's metadata-minimization principle documented on [PeerRecord]'s class doc comment:
 * broadcasting presence/address records over a network-wide GossipSub topic lets every subscriber
 * learn every published identity's current addresses and online-status heartbeat. This floor keeps
 * a caller that goes through THIS class from turning [PeerRecord] into a fine-grained real-time
 * presence oracle for its OWN identity, without banning re-announcement outright (a heartbeat TTL
 * still needs periodic renewal, see [PeerRecord.notValidAfterEpochSecond]).
 *
 * **Overstates its own reach if read as a network-wide guarantee - audit round 1, minor finding,
 * corrected in this doc comment.** This floor is enforced ONLY on the local publication path a
 * caller reaches through THIS wrapper: [PeerDirectoryGossip.announce] itself is public and entirely
 * unrate-limited (see its own class doc comment on why the floor deliberately lives here, one layer
 * up, rather than inside `announce()`), so a caller that publishes directly bypasses it trivially.
 * More importantly, [PeerDirectoryGossip.onGossipMessage] applies NO inbound per-identity rate limit
 * at all - a REMOTE peer running a modified client can publish a fresh record every second and this
 * node will accept, persist, and re-propagate every one of them. This class therefore bounds only
 * how often THIS node republishes ITS OWN presence, not how finely any other peer's client can be
 * made to expose theirs - it does not, by itself, prevent [PeerRecord] from being a fine-grained
 * presence oracle network-wide.
 *
 * **Deliberately NOT built into [PeerDirectoryGossip.announce] itself** - see that method's own doc
 * comment: `announce()` mirrors `VeritasGossip.announce`/`InboxGossip`'s established "retrying the
 * SAME call is always safe" property, which
 * `TwoNodePeerDirectoryGossipIntegrationTest`'s bounded-polling-against-one-deadline loop relies on
 * exactly like `TwoNodeVeritasGossipIntegrationTest`/`TwoNodeMailGossipIntegrationTest` already do.
 * Baking a multi-minute floor into `announce()` itself would silently break that retry pattern.
 * Rate limiting therefore lives here, one layer up, wrapping whichever caller decides WHEN a fresh
 * [PeerRecord] should be built and announced.
 */
class PeerPresenceAnnouncer(
    private val gossip: PeerDirectoryGossip,
    private val minRepublishIntervalSeconds: Long = MIN_REPUBLISH_INTERVAL_SECONDS,
) {
    /** `null` until the first successful [announceIfDue] call - deliberately NOT a `Long.MIN_VALUE`
     * sentinel: `nowEpochSecond - Long.MIN_VALUE` silently overflows a 64-bit `Long` (two's
     * complement wraparound makes it a huge NEGATIVE number, not a huge positive one - `-b` for
     * `b == Long.MIN_VALUE` has no positive representation), which would make the very first call
     * look LESS than [minRepublishIntervalSeconds] elapsed rather than more, incorrectly suppressing
     * it. A nullable sentinel sidesteps the overflow entirely rather than trying to pick a "safe"
     * numeric sentinel. */
    private var lastAnnouncedAtEpochSecond: Long? = null

    /**
     * Publishes [record] via [PeerDirectoryGossip.announce] iff at least
     * [minRepublishIntervalSeconds] have elapsed since the last call that actually announced (or
     * this is the first call ever, or the wall clock has gone BACKWARDS since - see below). Returns
     * `true` iff this call announced, `false` iff it was suppressed by the rate limit.
     *
     * **A backward wall-clock jump is treated as immediately due, not suppressed - V0.8.1 sub-wave
     * audit round 2, minor finding 3 fix.** [Instant.now] is wall-clock, not monotonic: an NTP
     * correction, VM snapshot restore, or container clock skew can step [nowEpochSecond] BACKWARDS
     * between calls. Before this fix, `nowEpochSecond - last < minRepublishIntervalSeconds` stayed
     * `true` (a NEGATIVE delta is always less than a positive floor), so a rewind silently
     * suppressed every call until wall-clock caught back up past `last + minRepublishIntervalSeconds`
     * - for a large-enough jump, hours or days during which this node's OWN [PeerRecord] TTL lapses
     * and it becomes undiscoverable via [PeerDirectoryGossip.lookup], a fail-CLOSED presence outage
     * from what is meant to be only a soft rate limit. Explicitly checking `nowEpochSecond >= last`
     * before applying the floor means a rewind cannot stall the heartbeat - the very next call after
     * a rewind is treated exactly like a first call.
     *
     * [nowEpochSecond] is caller-injectable purely for deterministic testing - a real caller should
     * never need to pass it explicitly.
     */
    @Synchronized
    fun announceIfDue(
        record: PeerRecord,
        nowEpochSecond: Long = Instant.now().epochSecond,
    ): Boolean {
        val last = lastAnnouncedAtEpochSecond
        if (last != null && nowEpochSecond >= last && nowEpochSecond - last < minRepublishIntervalSeconds) {
            return false
        }
        gossip.announce(record)
        lastAnnouncedAtEpochSecond = nowEpochSecond
        return true
    }

    companion object {
        /** A presence/address heartbeat floor, not a fine-grained real-time oracle - see this
         * class's doc comment. 5 minutes, deliberately generous, not derived from any protocol
         * requirement. */
        const val MIN_REPUBLISH_INTERVAL_SECONDS = 300L
    }
}
