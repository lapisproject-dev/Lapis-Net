package net.lapisphilosophorum.lapisnet.directory

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
 *
 * **The interval decision is monotonic-clock-based ([System.nanoTime]), NOT wall-clock-based - V0.8.1
 * sub-wave audit round 4, major finding fix, replacing round 2's wall-clock fix entirely.** Before
 * this fix, [announceIfDue] compared successive [java.time.Instant.now] readings: a BACKWARD
 * wall-clock jump (NTP correction, VM snapshot restore, container clock skew) was explicitly
 * special-cased to be treated as immediately due (round 2's own fix for a fail-CLOSED presence
 * outage - see git history for that version of this doc comment). Re-reviewed for round 4: that
 * same special case is also a fail-OPEN bypass. Wall-clock time is NOT tamper-proof the way a
 * monotonic clock reading is - anything able to step the local system clock backward before every
 * single call (a misbehaving local NTP daemon, a VM host adjusting guest time, or a deliberately
 * misconfigured/malicious local clock) makes `nowEpochSecond >= last` false on every call, which
 * disables the floor check ENTIRELY, forever, not just for one rewind - the exact opposite failure
 * mode from round 2's, and just as real a way to turn this class into a no-op. **A monotonic elapsed
 * duration cannot be manipulated this way**: [System.nanoTime] is not tied to wall-clock time at all
 * and is guaranteed by the JVM never to run backward within a single process - there is no
 * "backward jump" case to special-case in either direction, and therefore no fail-closed-stall
 * failure mode to reintroduce and no fail-open-bypass failure mode to leave open. This also sidesteps
 * the wall-clock approach's need for the tricky `Long.MIN_VALUE`-overflow-avoiding nullable sentinel
 * dance in a DIFFERENT way than round 2's fix did - see [lastAnnouncedAtNanos]'s own doc comment.
 *
 * **Deliberately does NOT also track wall-clock time for anything "meaningful across restarts"** -
 * unlike, say, [PeerRecord.notValidAfterEpochSecond] (which genuinely must remain meaningful to
 * OTHER nodes, and across this node's own restarts, since it travels over gossip), this class's
 * entire state ([lastAnnouncedAtNanos]) is process-local, in-memory, and reset to `null` on every
 * restart regardless of clock source (see [lastAnnouncedAtNanos]'s doc comment) - there is nothing
 * here for which "meaningful across restarts" would even apply, so there is no reason to also carry
 * a wall-clock reading for that purpose. [System.nanoTime]'s own well-known restriction - its
 * absolute value is meaningless across JVM restarts/different processes, only DIFFERENCES computed
 * within the same running JVM are - is therefore not a limitation for this specific use, since this
 * class never needed cross-restart meaning in the first place.
 */
class PeerPresenceAnnouncer(
    private val gossip: PeerDirectoryGossip,
    private val minRepublishIntervalSeconds: Long = MIN_REPUBLISH_INTERVAL_SECONDS,
) {
    private val minRepublishIntervalNanos: Long = minRepublishIntervalSeconds * NANOS_PER_SECOND

    /** `null` until the first successful [announceIfDue] call. A monotonic [System.nanoTime]
     * reading, not an epoch-second timestamp - see this class's doc comment for why the round-4
     * fix moved the interval decision off wall-clock time entirely. Subtracting two
     * [System.nanoTime] readings taken within the same JVM run is well-defined and wraparound-safe
     * by that method's own contract even without a nullable sentinel, but nullability is kept
     * anyway (rather than some `Long` sentinel) for the same reason round 2's fix preferred it:
     * the plainest possible way to express "no prior call" without inventing a magic numeric value
     * to reason about. */
    private var lastAnnouncedAtNanos: Long? = null

    /**
     * Publishes [record] via [PeerDirectoryGossip.announce] iff at least
     * [minRepublishIntervalSeconds] of MONOTONIC elapsed time have passed since the last call that
     * actually announced, or this is the first call ever. Returns `true` iff this call announced,
     * `false` iff it was suppressed by the rate limit.
     *
     * [nowNanos] is caller-injectable purely for deterministic testing - a real caller should never
     * need to pass it explicitly. It is expected to be a [System.nanoTime]-shaped reading (or, in
     * tests, an arbitrary synthetic tick count advancing at the same granularity) - NOT an epoch
     * second count; see this class's doc comment for why wall-clock time is deliberately not
     * consulted anywhere in this decision.
     */
    @Synchronized
    fun announceIfDue(
        record: PeerRecord,
        nowNanos: Long = System.nanoTime(),
    ): Boolean {
        val last = lastAnnouncedAtNanos
        if (last != null && nowNanos - last < minRepublishIntervalNanos) {
            return false
        }
        gossip.announce(record)
        lastAnnouncedAtNanos = nowNanos
        return true
    }

    companion object {
        /** A presence/address heartbeat floor, not a fine-grained real-time oracle - see this
         * class's doc comment. 5 minutes, deliberately generous, not derived from any protocol
         * requirement. */
        const val MIN_REPUBLISH_INTERVAL_SECONDS = 300L

        private const val NANOS_PER_SECOND = 1_000_000_000L
    }
}
