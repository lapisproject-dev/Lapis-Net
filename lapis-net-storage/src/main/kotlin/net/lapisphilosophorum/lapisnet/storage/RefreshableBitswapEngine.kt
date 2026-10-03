package net.lapisphilosophorum.lapisnet.storage

import io.libp2p.core.PeerId
import org.peergos.BlockRequestAuthoriser
import org.peergos.HashedBlock
import org.peergos.Want
import org.peergos.blockstore.Blockstore
import org.peergos.protocol.bitswap.BitswapEngine
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap

/** How long a want keeps being re-sent to a single peer after it was last (re-)requested; Nabu's own limit. */
internal val WANT_LIFETIME: Duration = Duration.ofMinutes(5)

private val MIN_RESEND_WAIT: Duration = Duration.ofSeconds(5)

/** The most peers one want is tracked for at the same time; the least recently requested are dropped first. */
internal const val MAX_TRACKED_PEERS_PER_WANT = 32

/**
 * Nabu's [BitswapEngine] with a want lifetime that can be RENEWED, and wants that are tracked PER PEER.
 *
 * Nabu stamps a want with its creation time once and, against a single peer, stops re-sending it five
 * minutes later - for the life of the process, because a want is only removed when its block arrives.
 * [NabuStorage.get] always asks one peer at a time, so without this a block whose first fetch failed
 * could never be fetched again after those five minutes, even from a provider that is reachable by then.
 *
 * Here a want is tracked together with the peers it was really requested from: [refresh] records
 * "this peer was asked for this block just now". [getWants] for a single peer returns only the wants
 * requested FROM THAT PEER within [WANT_LIFETIME] (and not sent to it in the last five seconds). Two
 * consequences, both of which Nabu's own `getWants` (it returns every pending want of the process,
 * whichever peer it was asked for) does not have:
 *
 * - **No CID leak between peers.** The CID is the access token for a block. A want that was asked of
 *   one peer (say, the sender of a direct message) is never put into the wantlist sent to another peer
 *   (say, a provider the DHT named for an unrelated block), so "callers that must not reveal a CID to
 *   the DHT pass explicit `peers`" holds.
 * - **A re-send thread ends on time.** Bitswap runs one re-send thread per `get` call, and it ends when
 *   `getWants` for its peer is empty - that is, five minutes after the last request TO THAT PEER, however
 *   busy other peers are.
 *
 * For several peers or none [getWants] behaves exactly like Nabu's (every pending want); [NabuStorage]
 * never asks that way. A completed want is forgotten. Nabu has no API to cancel a want, so a want that is
 * never answered stays registered in the base class (as it always has), but the tracking kept here for it
 * is small (at most [MAX_TRACKED_PEERS_PER_WANT] peers) and goes away with the block.
 *
 * [clock] returns nanoseconds and is injectable only so tests can age wants without sleeping.
 */
internal class RefreshableBitswapEngine(
    blockstore: Blockstore,
    authoriser: BlockRequestAuthoriser,
    maxMessageSize: Int,
    private val clock: () -> Long = System::nanoTime,
) : BitswapEngine(blockstore, authoriser, maxMessageSize, false) {
    /** One peer a want was requested from: when that last happened, and when the want was last sent to it. */
    private class Target(
        var lastRequested: Long,
        var lastSent: Long? = null,
    )

    /** All access to [targets] is under the entry's own monitor. */
    private class Tracked {
        val targets = LinkedHashMap<PeerId, Target>()
    }

    private val tracked = ConcurrentHashMap<Want, Tracked>()

    override fun getWant(
        w: Want,
        addToBlockstore: Boolean,
    ): CompletableFuture<HashedBlock> {
        val future = super.getWant(w, addToBlockstore)
        if (!future.isDone && !tracked.containsKey(w)) {
            val entry = Tracked()
            if (tracked.putIfAbsent(w, entry) == null) future.whenComplete { _, _ -> tracked.remove(w, entry) }
        }
        return future
    }

    /**
     * Starts a new [WANT_LIFETIME] for [want] AGAINST [peer], if the want is still pending. Called when a
     * request to [peer] is really sent, and before Bitswap is asked to send it: only a peer registered
     * here is ever sent the want.
     */
    fun refresh(
        want: Want,
        peer: PeerId,
    ) {
        val entry = tracked[want] ?: return
        val now = clock()
        synchronized(entry) {
            val existing = entry.targets.remove(peer) // re-inserted last: the map is ordered by recency
            entry.targets[peer] = existing?.also { it.lastRequested = now } ?: Target(now)
            if (entry.targets.size > MAX_TRACKED_PEERS_PER_WANT) {
                entry.targets.values.removeIf { now - it.lastRequested > WANT_LIFETIME.toNanos() }
            }
            while (entry.targets.size > MAX_TRACKED_PEERS_PER_WANT) {
                entry.targets.remove(entry.targets.keys.first())
            }
        }
    }

    override fun getWants(peers: Set<PeerId>): Set<Want> {
        if (peers.size != 1) return super.getWants(peers)
        val peer = peers.first()
        val now = clock()
        val result = HashSet<Want>()
        for ((want, entry) in tracked) {
            synchronized(entry) {
                val target = entry.targets[peer] ?: return@synchronized
                if (now - target.lastRequested > WANT_LIFETIME.toNanos()) return@synchronized
                val sent = target.lastSent
                if (sent != null && now - sent < MIN_RESEND_WAIT.toNanos()) return@synchronized
                target.lastSent = now
                result += want
            }
        }
        return result
    }
}
