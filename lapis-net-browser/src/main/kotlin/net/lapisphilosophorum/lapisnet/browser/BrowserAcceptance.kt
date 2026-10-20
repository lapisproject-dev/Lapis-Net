package net.lapisphilosophorum.lapisnet.browser

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.dm.DmAcceptanceCheck
import net.lapisphilosophorum.lapisnet.dm.DmAcceptedContacts
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.karma.KarmaGossip
import net.lapisphilosophorum.lapisnet.policy.AcceptanceGate
import net.lapisphilosophorum.lapisnet.policy.AcceptanceGateEvaluator
import net.lapisphilosophorum.lapisnet.policy.KarmaScoreLookup
import net.lapisphilosophorum.lapisnet.trust.TrustGraph
import net.lapisphilosophorum.lapisnet.trust.VeritasGossip
import java.util.concurrent.atomic.AtomicReference

private val logger = KotlinLogging.logger {}

/** Why a call was silently blocked - shown to the LOCAL user only, never serialized onto the wire. */
enum class CallBlockReason {
    VERITAS_BELOW_THRESHOLD,
    KARMA_BELOW_THRESHOLD,

    /** Reserved: the deposit is a bypass, not a gate, so a missing deposit is not distinguishable yet (see docs). */
    DEPOSIT_MISSING,

    /** Any block that is not attributable to exactly one gate. */
    POLICY,
}

/**
 * Builds the ONE [DmAcceptanceCheck] instance that is handed to **both** `MailboxGossip.attach` and
 * `DmSessionManager.attach` (the "wiring footgun" in [DmAcceptanceCheck]'s documentation: wiring only one forfeits
 * the other gate silently), refreshes it when the Veritas trust graph changed, and explains - for display only - why
 * a sender was blocked.
 *
 * [blockReasonOf] never takes or influences a decision; it re-evaluates the gates of the CURRENT check for a sender
 * that was already blocked, uses only the check's cached Veritas verdicts and the in-memory Karma lookup (no I/O),
 * and falls back to [CallBlockReason.POLICY] on any failure. It runs on the call listener thread and must stay cheap.
 */
internal class BrowserAcceptance(
    private val settings: DmAcceptanceSettings,
    private val localIdentity: Secp256k1PublicKey,
    private val veritas: VeritasGossip,
    private val karmaLookupFactory: (TrustGraph) -> KarmaScoreLookup,
    private val acceptedContacts: DmAcceptedContacts,
) {
    private val current = AtomicReference<DmAcceptanceCheck?>(null)

    @Volatile private var lastGrantFingerprint: List<Byte>? = null

    /** The gates in effect, for the status panel (display names). */
    fun gateNames(): List<String> =
        settings.gates().map {
            when (it) {
                is AcceptanceGate.VeritasPath -> "veritas-path"
                is AcceptanceGate.KarmaThreshold -> "karma>=${it.minScore}"
            }
        }

    /** Builds (and remembers) a check from the current trust graph, or `null` when no gate is switched on. */
    fun buildCheck(): DmAcceptanceCheck? {
        if (!settings.enabled) return null
        val grants = veritas.currentGrants()
        val graph = TrustGraph.fromGrants(grants)
        val check =
            DmAcceptanceCheck(
                gates = settings.gates(),
                trustGraph = graph,
                karmaScoreOf = karmaLookupFactory(graph),
                isAcceptedContact = acceptedContacts::isAccepted,
                minDepositMsat = settings.minDepositMsat,
            )
        lastGrantFingerprint = veritas.currentGrantsFingerprint(grants)
        current.set(check)
        return check
    }

    /**
     * Rebuilds the check when the set of latest Veritas grants changed (content, not count) since the last build and hands the new
     * instance to [applyTo] (which must give it to BOTH consumers). Returns whether it did. No network I/O.
     */
    fun refresh(applyTo: (DmAcceptanceCheck?) -> Unit): Boolean {
        if (!settings.enabled) return false
        if (veritas.currentGrantsFingerprint() == lastGrantFingerprint) return false
        val check = buildCheck()
        applyTo(check)
        logger.debug { "acceptance check rebuilt after a trust graph change" }
        return true
    }

    fun blockReasonOf(sender: Secp256k1PublicKey): CallBlockReason {
        val check = current.get() ?: return CallBlockReason.POLICY
        return try {
            val failed =
                AcceptanceGateEvaluator.failedGates(
                    sender,
                    check.gates,
                    check.cachedVeritasPathCheck(localIdentity),
                    check.karmaScoreOf,
                )
            when (failed) {
                listOf(AcceptanceGate.VeritasPath) -> CallBlockReason.VERITAS_BELOW_THRESHOLD
                else ->
                    if (failed != null && failed.size == 1 && failed[0] is AcceptanceGate.KarmaThreshold) {
                        CallBlockReason.KARMA_BELOW_THRESHOLD
                    } else {
                        CallBlockReason.POLICY
                    }
            }
        } catch (e: Exception) {
            CallBlockReason.POLICY
        }
    }

    /** The check currently in effect (identity comparison in tests). */
    internal fun currentForTesting(): DmAcceptanceCheck? = current.get()
}

/**
 * The per-identity Karma score the Karma gate needs (finding F3: `lapis-net-karma` has no such notion): the sum of
 * the Veritas-weighted personalized Karma of the sender's most recent [maxPosts] posts. Memoized per sender for
 * [ttlNanos] and bounded, so a flood of distinct senders cannot make this expensive or unbounded.
 */
internal class PostKarmaScoreLookup(
    private val posts: PostAnnouncementGossip,
    private val karma: KarmaGossip,
    private val graph: TrustGraph,
    private val localIdentity: Secp256k1PublicKey,
    private val maxPosts: Int = 20,
    private val ttlNanos: Long = 60_000_000_000L,
    private val clock: () -> Long = System::nanoTime,
) : KarmaScoreLookup {
    private class Entry(
        val score: Double,
        val atNanos: Long,
    )

    private val cache =
        object : LinkedHashMap<Secp256k1PublicKey, Entry>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Secp256k1PublicKey, Entry>): Boolean =
                size > MAX_CACHED_SENDERS
        }

    override fun karmaScoreOf(sender: Secp256k1PublicKey): Double {
        val now = clock()
        synchronized(cache) { cache[sender] }?.let { if (now - it.atNanos < ttlNanos) return it.score }
        val score = compute(sender)
        synchronized(cache) { cache[sender] = Entry(score, now) }
        return score
    }

    private fun compute(sender: Secp256k1PublicKey): Double =
        posts
            .postsBy(sender)
            .sortedByDescending { it.announcement.timestampSeconds }
            .take(maxPosts)
            .sumOf { post ->
                KarmaScoring.personalizedKarmaForTarget(
                    votesForTarget = karma.currentVotesForTarget(post.cid),
                    votesByVoter = karma::currentVotesByVoter,
                    graph = graph,
                    localIdentity = localIdentity,
                )
            }

    companion object {
        const val MAX_CACHED_SENDERS = 4_096
    }
}
