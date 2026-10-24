@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onionwire.path

import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptor
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.onion.CircuitPurpose
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onion.OnionConstants
import net.lapisphilosophorum.lapisnet.onionwire.OnionPathProvider
import java.security.SecureRandom
import java.time.Clock

/** A relay with everything the selection needs, computed once per selection. */
@ExperimentalOnionApi
class Candidate internal constructor(
    internal val descriptor: OnionRelayDescriptor,
    internal val buckets: Set<NetworkBucket>,
    internal val family: RelayFamilyId?,
    /** Madli reliability in `[0, 1]`, `null` = no history. */
    internal val reliability: Double?,
) {
    internal val identity: Secp256k1PublicKey get() = descriptor.identity

    /** The canonical bucket used for the share cap (one bucket per relay, otherwise a relay is counted twice). */
    internal val capBucket: NetworkBucket get() = buckets.min()
}

/**
 * Chooses relays for circuits (wave V0.10.0-E). Network-free and deterministic for a given [random] sequence.
 *
 * **Path:** hop 1 is the persistent primary guard; the last hop is prescribed by the caller (publish relay, intro point,
 * rendezvous point) or drawn; the middle hops are drawn with weights. A path always has at least
 * [PathPolicy.PRODUCTION_PATH_LENGTH] relays: if not enough diverse relays exist the answer is
 * [PathSelectionResult.Insufficient], never a shorter path.
 *
 * **Diversity (hard):** no relay twice, no two relays with an overlapping /16 (IPv4) or /48 (IPv6) bucket, at most one
 * relay of unknown network, no two relays of the same non-null family, optionally no Veritas edge. The addresses come
 * from [locator] and are self-declared by the relays, so an adversary can lie about them (documented limit).
 *
 * **Weights (soft):** the Madli reliability, floor [PathPolicy.MIN_WEIGHT], [PathPolicy.NO_HISTORY_WEIGHT] without
 * history. Relays without history together are capped at [PathPolicy.NEW_RELAYS_TOTAL_CAP]; the share of a single
 * bucket (and family) is capped at `max(0.10, 1/buckets)` (water filling), recomputed per hop on the remaining
 * candidates. Madli is never a hard gate.
 */
@ExperimentalOnionApi
class OnionPathSelector(
    private val descriptors: () -> List<OnionRelayDescriptor>,
    private val ownIdentity: Secp256k1PublicKey,
    private val locator: RelayNetworkLocator,
    private val reputation: RelayReputation,
    private val families: RelayFamilyResolver = RelayFamilyResolver { null },
    private val guards: GuardManager,
    private val random: SecureRandom,
    private val clock: Clock,
    private val options: PathSelectionOptions = PathSelectionOptions(),
) {
    /**
     * Selects a full path ending at [lastHop] (or at a drawn relay if `null`).
     *
     * With [lastHopChosenRemotely] the last hop was named by a remote party (rendezvous point of an INTRODUCE, intro
     * point of a service descriptor). It is then NEVER refused because of the guard: whether a build works must not
     * depend on the guard, otherwise a remote party could probe for the guard's identity and network. The diversity rule
     * then only applies to the middle hops (towards the guard strictly; towards the last hop as far as possible).
     */
    fun select(
        lastHop: OnionRelayDescriptor?,
        hops: Int = PathPolicy.PRODUCTION_PATH_LENGTH,
        lastHopChosenRemotely: Boolean = false,
    ): PathSelectionResult {
        require(hops in PathPolicy.PRODUCTION_PATH_LENGTH..OnionConstants.MAX_HOPS) { "path length out of range" }
        val now = clock.millis() / 1000
        val cands = candidates(now)
        val last = lastHop?.let { toCandidate(it, now) }
        if (last != null && last.identity == ownIdentity) throw PathConflictException()
        val guardDescriptor = guards.primaryUsable(cands.map { it.descriptor }) { pickGuard(cands, it, null, hops) }
        var guard =
            guardDescriptor?.let { d -> cands.firstOrNull { it.identity == d.identity } }
                ?: return PathSelectionResult.Insufficient
        if (lastHopChosenRemotely && last != null && last.identity == guard.identity) {
            // A relay can not appear twice in a path, and the build must not fail because of the guard (that would let
            // a remote party probe for it): enter through the persistent backup guard for this one circuit.
            val backupId = guards.snapshot().backup?.identity
            guard =
                cands.firstOrNull { it.identity == backupId && it.identity != last.identity }
                    ?: return PathSelectionResult.Insufficient
        }
        if (!lastHopChosenRemotely) {
            if (last != null && last.identity == guard.identity) throw PathConflictException()
            if (last != null && conflicts(guard, last)) throw PathConflictException()
        }

        repeat(ATTEMPTS) { attempt ->
            // a remotely chosen last hop is relaxed in the later attempts so that the path never fails because of it
            val relaxLast = lastHopChosenRemotely && attempt >= ATTEMPTS / 2
            val fixed = ArrayList<Candidate>(hops)
            fixed += guard
            if (last != null) fixed += last
            val drawn = ArrayList<Candidate>(hops)
            repeat(hops - fixed.size) {
                val allowed =
                    cands.filter { c ->
                        fixed.none { f ->
                            f.identity == c.identity || (!(relaxLast && f === last) && conflicts(c, f))
                        } &&
                            drawn.none { it.identity == c.identity || conflicts(c, it) }
                    }
                pickWeighted(allowed)?.let { drawn += it }
            }
            if (drawn.size == hops - fixed.size) {
                val path = ArrayList<OnionRelayDescriptor>(hops)
                path += guard.descriptor
                drawn.forEach { path += it.descriptor }
                if (last != null) path += last.descriptor
                return PathSelectionResult.Selected(path)
            }
        }
        return PathSelectionResult.Insufficient
    }

    /**
     * Draws one relay to serve as an endpoint (introduction, rendezvous or publish relay): diverse to the guard and not in
     * [exclude]. `null` if there is none.
     */
    fun selectEndpoint(exclude: Set<Secp256k1PublicKey>): OnionRelayDescriptor? {
        val now = clock.millis() / 1000
        val cands = candidates(now)
        val guardDescriptor =
            guards.primaryUsable(
                cands.map { it.descriptor },
            ) { pickGuard(cands, it, null, PathPolicy.PRODUCTION_PATH_LENGTH) }
                ?: return null
        val guard = cands.firstOrNull { it.identity == guardDescriptor.identity } ?: return null
        val allowed = cands.filter { it.identity !in exclude && it.identity != guard.identity && !conflicts(it, guard) }
        return pickWeighted(allowed)?.descriptor
    }

    /** The selection weights of [cands] (normalised to sum 1), for tests. */
    internal fun weightsForTesting(cands: List<Candidate>): DoubleArray = weights(cands)

    internal fun candidateForTesting(
        d: OnionRelayDescriptor,
        nowEpochSecond: Long,
    ): Candidate = toCandidate(d, nowEpochSecond)

    private fun candidates(now: Long): List<Candidate> =
        descriptors()
            .asSequence()
            .filter { it.notValidAfterEpochSecond >= now && it.identity != ownIdentity }
            .distinctBy { it.identity }
            .sortedWith { a, b -> compareBytes(a.identity.bytes, b.identity.bytes) }
            .map { toCandidate(it, now) }
            .toList()

    private fun toCandidate(
        d: OnionRelayDescriptor,
        now: Long,
    ): Candidate {
        val buckets = locator.bucketsOf(d.identity, now).ifEmpty { setOf(NetworkBucket.Unknown) }
        val reliability = reputation.reliabilityOf(d.peerId)?.takeIf { it.isFinite() }
        return Candidate(d, buckets, families.familyOf(d), reliability)
    }

    /**
     * The hard diversity rule between two relays. A guard is only chosen if enough pairwise diverse relays remain for a
     * whole path (greedy check), otherwise a guard would be pinned that can never be part of a full path.
     */
    internal fun conflicts(
        a: Candidate,
        b: Candidate,
    ): Boolean {
        if (a.identity == b.identity) return true
        val real = a.buckets.intersect(b.buckets) - NetworkBucket.Unknown
        if (real.isNotEmpty()) return true
        if (a.buckets == setOf(NetworkBucket.Unknown) && b.buckets == setOf(NetworkBucket.Unknown)) return true
        if (a.family != null && a.family == b.family) return true
        if (options.forbidVeritasEdge) {
            val edge = options.veritasEdge
            if (edge != null && (edge(a.identity, b.identity) || edge(b.identity, a.identity))) return true
        }
        return false
    }

    private fun pickGuard(
        cands: List<Candidate>,
        offered: List<OnionRelayDescriptor>,
        last: Candidate?,
        hops: Int,
    ): OnionRelayDescriptor? {
        val offeredIds = offered.map { it.identity }.toSet()
        var pool =
            cands.filter {
                it.identity in offeredIds &&
                    (last == null || (it.identity != last.identity && !conflicts(it, last)))
            }
        repeat(GUARD_TRIES) {
            val g = pickWeighted(pool) ?: return null
            if (hasDiversePathAround(g, cands, last, hops)) return g.descriptor
            pool = pool.filter { it.identity != g.identity }
        }
        return null
    }

    private fun hasDiversePathAround(
        g: Candidate,
        cands: List<Candidate>,
        last: Candidate?,
        hops: Int,
    ): Boolean {
        val chosen = arrayListOf(g)
        if (last != null) chosen += last
        // greedy; may miss exotic solutions but never accepts an invalid one
        for (c in cands) {
            if (chosen.size >= hops) break
            if (chosen.none { it.identity == c.identity } && chosen.none { conflicts(c, it) }) chosen += c
        }
        return chosen.size >= hops
    }

    private fun pickWeighted(allowed: List<Candidate>): Candidate? {
        if (allowed.isEmpty()) return null
        val w = weights(allowed)
        val r = random.nextDouble()
        var cum = 0.0
        for (i in allowed.indices) {
            cum += w[i]
            if (r < cum) return allowed[i]
        }
        return allowed.last()
    }

    private fun weights(cands: List<Candidate>): DoubleArray {
        val n = cands.size
        val w =
            DoubleArray(n) { i ->
                val r = cands[i].reliability
                if (r == null) PathPolicy.NO_HISTORY_WEIGHT else maxOf(PathPolicy.MIN_WEIGHT, r.coerceIn(0.0, 1.0))
            }
        // 1. cap of the relays without history
        val total = w.sum()
        val isNew = BooleanArray(n) { cands[it].reliability == null }
        val sumNew = (0 until n).filter { isNew[it] }.sumOf { w[it] }
        val sumOld = total - sumNew
        if (sumNew > PathPolicy.NEW_RELAYS_TOTAL_CAP * total && sumOld > 0) {
            val factor = (PathPolicy.NEW_RELAYS_TOTAL_CAP / (1 - PathPolicy.NEW_RELAYS_TOTAL_CAP) * sumOld) / sumNew
            for (i in 0 until n) if (isNew[i]) w[i] *= factor
        }
        // 2. share caps per bucket, then per family
        capGroups(w) { cands[it].capBucket }
        capGroups(w) { cands[it].family }
        val sum = w.sum()
        if (!(sum > 0.0) || !sum.isFinite()) return DoubleArray(n) { 1.0 / n }
        return DoubleArray(n) { w[it] / sum }
    }

    /**
     * Water filling: no group (a `null` group key is uncapped) may hold more than `max(MIN_BUCKET_CAP, 1/groups)` of the
     * total weight; the excess goes proportionally to the groups below the cap. With one group, or with only uncapped
     * members, nothing is done (a degenerate set must still yield a draw, never a division by zero).
     */
    private fun capGroups(
        w: DoubleArray,
        groupOf: (Int) -> Any?,
    ) {
        val n = w.size
        val groups = LinkedHashMap<Any, MutableList<Int>>()
        for (i in 0 until n) groupOf(i)?.let { groups.getOrPut(it) { ArrayList() } += i }
        if (groups.size < 2) return
        val total = w.sum()
        val cap = maxOf(PathPolicy.MIN_BUCKET_CAP, 1.0 / groups.size) * total
        val capped = HashSet<Any>()
        repeat(groups.size + 1) {
            var changed = false
            var excess = 0.0
            for ((g, members) in groups) {
                if (g in capped) continue
                val s = members.sumOf { w[it] }
                if (s > cap * (1 + EPS)) {
                    val f = cap / s
                    for (i in members) w[i] *= f
                    excess += s - cap
                    capped += g
                    changed = true
                }
            }
            if (!changed) return
            val free = (0 until n).filter { i -> groupOf(i).let { it == null || it !in capped } }
            val freeSum = free.sumOf { w[it] }
            if (freeSum <= 0.0) return
            val f = (freeSum + excess) / freeSum
            for (i in free) w[i] *= f
        }
    }

    private companion object {
        const val ATTEMPTS = 6
        const val GUARD_TRIES = 8
        const val EPS = 1e-9

        fun compareBytes(
            a: ByteArray,
            b: ByteArray,
        ): Int {
            for (i in 0 until minOf(a.size, b.size)) {
                val c = (a[i].toInt() and 0xFF).compareTo(b[i].toInt() and 0xFF)
                if (c != 0) return c
            }
            return a.size.compareTo(b.size)
        }
    }
}

/** Adapter to the existing [OnionPathProvider]: throws [InsufficientRelaysException] / [PathConflictException]. */
@ExperimentalOnionApi
class SelectingOnionPathProvider(
    private val selector: OnionPathSelector,
    private val onFailure: (Throwable) -> Unit = {},
) : OnionPathProvider {
    override fun pathEndingAt(
        last: OnionRelayDescriptor,
        purpose: CircuitPurpose,
    ): List<OnionRelayDescriptor> {
        try {
            return when (val r = selector.select(last, lastHopChosenRemotely = purpose in REMOTE_LAST_HOP)) {
                is PathSelectionResult.Selected -> r.hops
                PathSelectionResult.Insufficient -> throw InsufficientRelaysException()
            }
        } catch (e: InsufficientRelaysException) {
            onFailure(e)
            throw e
        } catch (e: PathConflictException) {
            onFailure(e)
            throw e
        }
    }

    private companion object {
        /** Purposes whose last hop is named by a remote party, so it must never be refused because of the guard. */
        val REMOTE_LAST_HOP = setOf(CircuitPurpose.RENDEZVOUS_RECEIVER, CircuitPurpose.INTRODUCE)
    }
}
