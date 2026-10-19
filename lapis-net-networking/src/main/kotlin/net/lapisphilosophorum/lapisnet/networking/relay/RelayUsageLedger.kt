package net.lapisphilosophorum.lapisnet.networking.relay

import io.libp2p.core.PeerId
import java.time.Duration
import java.time.Instant

/**
 * A node-local, bilateral usage ledger in the style of the Bitswap ledger: it records, per
 * counterparty, how many relayed bytes this node spent on the peer versus how many the peer spent
 * on this node. The balance drives the **priority** (never admission) of relay requests, see
 * [RelayServerLimits.priorityHeadroomFraction].
 *
 * Sign convention: the balance of a peer is `received - served`. A peer this node forwarded bytes
 * for ([recordServed]) goes negative (it "owes"), a relay that forwarded bytes for this node
 * ([recordReceivedFrom]) goes positive (this node is in its debt, i.e. the relay has credit with
 * us).
 *
 * **Never gossiped, never self-reported.** Every number here is observed locally by this node on
 * connections it terminates itself. There is deliberately no import path and no network
 * representation: it is the relay *client's* signed observation ([net.lapisphilosophorum.lapisnet.networking.relay.RelayReliabilityTracker]
 * -> Madli) that travels, not this ledger.
 *
 * **Bounded.** At most [maxTrackedPeers] entries. When full, the entry with the smallest absolute
 * (decayed) balance is evicted - a debtor with a large negative balance can therefore not be
 * pushed out by flooding the ledger with throw-away identities (those have tiny balances and
 * evict each other).
 *
 * **Decay.** Balances decay lazily toward zero with half-life [halfLife], computed on access. An
 * old debt is forgiven over time, a long-ago credit expires. Memory only: a restart forgets every
 * balance. Together with "a new PeerId starts at 0" this means identity changes shed debt - a
 * documented property, bounded by `maxReservationsPerSourceAddress`.
 *
 * Thread-safe (single monitor); all operations are O(1) except an eviction, which is O([maxTrackedPeers])
 * and only happens when the ledger is full and a new, larger entry arrives.
 */
class RelayUsageLedger internal constructor(
    private val maxTrackedPeers: Int = DEFAULT_MAX_TRACKED_PEERS,
    private val halfLife: Duration = DEFAULT_HALF_LIFE,
    private val clock: () -> Instant = Instant::now,
) {
    private class Entry(
        var balance: Long,
        var updatedAt: Instant,
    )

    private val entries = LinkedHashMap<PeerId, Entry>()

    init {
        require(maxTrackedPeers > 0) { "maxTrackedPeers must be > 0" }
        require(!halfLife.isNegative && !halfLife.isZero) { "halfLife must be positive" }
    }

    /** This node spent [bytes] on [peer]: the peer's balance decreases. */
    @Synchronized
    internal fun recordServed(
        peer: PeerId,
        bytes: Long,
    ) = adjust(peer, bytes, -1)

    /** [peer] spent [bytes] on this node: the peer's balance increases. */
    @Synchronized
    internal fun recordReceivedFrom(
        peer: PeerId,
        bytes: Long,
    ) = adjust(peer, bytes, +1)

    /** The decayed balance of [peer]; `0` for an unknown peer. */
    @Synchronized
    fun balanceOf(peer: PeerId): Long {
        val entry = entries[peer] ?: return 0L
        val now = clock()
        val decayed = decayedBalance(entry, now)
        if (decayed == 0L) {
            entries.remove(peer)
            return 0L
        }
        return decayed
    }

    /** A copy of every tracked non-zero (decayed) balance. */
    @Synchronized
    fun snapshot(): Map<PeerId, Long> {
        val now = clock()
        val result = LinkedHashMap<PeerId, Long>()
        val iterator = entries.entries.iterator()
        while (iterator.hasNext()) {
            val (peer, entry) = iterator.next()
            val decayed = decayedBalance(entry, now)
            if (decayed == 0L) iterator.remove() else result[peer] = decayed
        }
        return result
    }

    @Synchronized
    internal fun trackedPeers(): Int = entries.size

    private fun adjust(
        peer: PeerId,
        bytes: Long,
        sign: Int,
    ) {
        require(bytes >= 0) { "bytes must be >= 0: $bytes" }
        if (bytes == 0L) return
        val now = clock()
        val delta = if (sign < 0) -bytes else bytes
        val existing = entries[peer]
        if (existing != null) {
            existing.balance = saturatingAdd(decayedBalance(existing, now), delta)
            existing.updatedAt = maxOf(existing.updatedAt, now)
            return
        }
        if (entries.size >= maxTrackedPeers) {
            // Evict the smallest |balance| (oldest on a tie) among the existing entries AND the
            // newcomer. If the newcomer is the smallest, it is simply not tracked.
            var victim: PeerId? = null
            var victimAbs = Long.MAX_VALUE
            var victimAt = Instant.MAX
            for ((p, e) in entries) {
                val abs = absSaturating(decayedBalance(e, now))
                if (abs < victimAbs || (abs == victimAbs && e.updatedAt.isBefore(victimAt))) {
                    victim = p
                    victimAbs = abs
                    victimAt = e.updatedAt
                }
            }
            val newcomerAbs = absSaturating(delta)
            if (victim == null || newcomerAbs <= victimAbs) return
            entries.remove(victim)
        }
        entries[peer] = Entry(delta, now)
    }

    private fun decayedBalance(
        entry: Entry,
        now: Instant,
    ): Long {
        val elapsedNanos = Duration.between(entry.updatedAt, now).toNanos().coerceAtLeast(0L)
        if (elapsedNanos == 0L) return entry.balance
        val factor = Math.pow(0.5, elapsedNanos.toDouble() / halfLife.toNanos().toDouble())
        return Math.round(entry.balance.toDouble() * factor)
    }

    private fun saturatingAdd(
        a: Long,
        b: Long,
    ): Long {
        val sum = a + b
        // Overflow iff both operands have the same sign and the sum's sign differs.
        return if (((a xor sum) and (b xor sum)) < 0) (if (a < 0) Long.MIN_VALUE else Long.MAX_VALUE) else sum
    }

    private fun absSaturating(value: Long): Long = if (value == Long.MIN_VALUE) Long.MAX_VALUE else Math.abs(value)

    companion object {
        const val DEFAULT_MAX_TRACKED_PEERS = 4096

        /** Balances halve every 7 days. Provisional operator default. */
        val DEFAULT_HALF_LIFE: Duration = Duration.ofDays(7)
    }
}
