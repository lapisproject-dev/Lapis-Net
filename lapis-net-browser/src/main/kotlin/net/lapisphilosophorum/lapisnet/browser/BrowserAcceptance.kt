package net.lapisphilosophorum.lapisnet.browser

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.dm.DmAcceptanceCheck
import net.lapisphilosophorum.lapisnet.dm.DmAcceptedContacts
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.karma.KarmaGossip
import net.lapisphilosophorum.lapisnet.mail.MailAcceptanceCheck
import net.lapisphilosophorum.lapisnet.mail.MailAcceptanceGate
import net.lapisphilosophorum.lapisnet.mail.MailRejectListener
import net.lapisphilosophorum.lapisnet.policy.AcceptanceGate
import net.lapisphilosophorum.lapisnet.policy.AcceptanceGateEvaluator
import net.lapisphilosophorum.lapisnet.policy.KarmaScoreLookup
import net.lapisphilosophorum.lapisnet.trust.TrustGraph
import net.lapisphilosophorum.lapisnet.trust.VeritasGossip
import java.util.EnumMap
import java.util.concurrent.atomic.AtomicLong
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

/** Why a mail was discarded by the mail acceptance policy - counted locally, never sent anywhere. */
enum class MailBlockReason {
    VERITAS_BELOW_THRESHOLD,
    KARMA_BELOW_THRESHOLD,
    ALL_ACTIVE_GATES_FAILED,
    POLICY,
}

/**
 * Lock-free in-memory counters of discarded mail deliveries (V0.9.17). Counts delivery attempts, not distinct mails:
 * the same mail arriving over gossip and over the DHT counts twice. Holds no sender, no key, no content - only the
 * reason and the time of the last block. Not persisted.
 */
internal class MailBlockCounter {
    private val counters = EnumMap<MailBlockReason, AtomicLong>(MailBlockReason::class.java)

    init {
        for (reason in MailBlockReason.entries) counters[reason] = AtomicLong()
    }

    @Volatile var lastBlockedEpochSecond: Long? = null
        private set

    fun record(
        reason: MailBlockReason,
        nowEpochSecond: Long =
            java.time.Instant
                .now()
                .epochSecond,
    ) {
        counters.getValue(reason).incrementAndGet()
        lastBlockedEpochSecond = nowEpochSecond
    }

    fun snapshot(): Map<MailBlockReason, Long> = MailBlockReason.entries.associateWith { counters.getValue(it).get() }

    fun total(): Long = counters.values.sumOf { it.get() }

    fun toStatus(): MailBlockedStatus =
        MailBlockedStatus(
            total = total(),
            byReason =
                snapshot()
                    .filterValues { it > 0 }
                    .mapKeys {
                        it.key.name
                            .lowercase()
                            .replace('_', '-')
                    },
            lastBlockedEpochSecond = lastBlockedEpochSecond,
        )
}

/** The DM and mail checks built from one trust-graph snapshot; each is `null` while its gates are all off. */
internal data class AcceptanceChecks(
    val dm: DmAcceptanceCheck?,
    val mail: MailAcceptanceCheck?,
)

/**
 * Builds the ONE [DmAcceptanceCheck] instance that is handed to **both** `MailboxGossip.attach` and
 * `DmSessionManager.attach` (the "wiring footgun" in [DmAcceptanceCheck]'s documentation: wiring only one forfeits
 * the other gate silently), plus (V0.9.17) the [MailAcceptanceCheck] for `InboxGossip` (which serves gossip and DHT
 * alike). Both are built from a single trust-graph snapshot, refreshed together when the Veritas grants changed, and
 * an accepted contact passes both policies.
 *
 * [blockReasonOf] never takes or influences a decision; it re-evaluates the gates of the CURRENT check for a sender
 * that was already blocked, uses only the check's cached Veritas verdicts and the in-memory Karma lookup (no I/O),
 * and falls back to [CallBlockReason.POLICY] on any failure. It runs on the call listener thread and must stay cheap.
 */
internal class BrowserAcceptance(
    private val settings: DmAcceptanceSettings,
    private val mailSettings: MailAcceptanceSettings,
    private val localIdentity: Secp256k1PublicKey,
    private val veritas: VeritasGossip,
    private val karmaLookupFactory: (TrustGraph) -> KarmaScoreLookup,
    private val acceptedContacts: DmAcceptedContacts,
) {
    private val current = AtomicReference<DmAcceptanceCheck?>(null)
    private val currentMail = AtomicReference<MailAcceptanceCheck?>(null)

    /** Survives refreshes (a refresh swaps the check, not the counters). */
    val mailBlocks = MailBlockCounter()

    @Volatile private var lastGrantFingerprint: List<Byte>? = null

    /** True when any DM or mail gate is switched on. */
    val anyEnabled: Boolean get() = settings.enabled || mailSettings.enabled

    /** The DM gates in effect, for the status panel (display names). */
    fun gateNames(): List<String> = settings.gates().map(::gateName)

    /** The mail gates in effect, for the status panel (same display names). */
    fun mailGateNames(): List<String> =
        mailSettings.gates().map {
            when (it) {
                is MailAcceptanceGate.VeritasPath -> "veritas-path"
                is MailAcceptanceGate.KarmaThreshold -> "karma>=${it.minScore}"
            }
        }

    private fun gateName(gate: AcceptanceGate): String =
        when (gate) {
            is AcceptanceGate.VeritasPath -> "veritas-path"
            is AcceptanceGate.KarmaThreshold -> "karma>=${gate.minScore}"
        }

    /** Builds (and remembers) both checks from ONE trust graph; a check is `null` when none of its gates is on. */
    fun buildChecks(): AcceptanceChecks {
        if (!anyEnabled) return AcceptanceChecks(null, null)
        val grants = veritas.currentGrants()
        val graph = TrustGraph.fromGrants(grants)
        val karmaLookup = karmaLookupFactory(graph)
        val dm =
            if (settings.enabled) {
                DmAcceptanceCheck(
                    gates = settings.gates(),
                    trustGraph = graph,
                    karmaScoreOf = karmaLookup,
                    isAcceptedContact = acceptedContacts::isAccepted,
                    minDepositMsat = settings.minDepositMsat,
                )
            } else {
                null
            }
        val mail =
            if (mailSettings.enabled) {
                MailAcceptanceCheck(
                    gates = mailSettings.gates(),
                    trustGraph = graph,
                    karmaScoreOf = { sender -> karmaLookup.karmaScoreOf(sender) },
                    minDepositMsat = mailSettings.minDepositMsat,
                    depositLookup = { null },
                    isAcceptedContact = acceptedContacts::isAccepted,
                    rejectListener = MailRejectListener { mailBlocks.record(mailBlockReasonOf(it.failedGates)) },
                )
            } else {
                null
            }
        lastGrantFingerprint = veritas.currentGrantsFingerprint(grants)
        current.set(dm)
        currentMail.set(mail)
        return AcceptanceChecks(dm, mail)
    }

    /** Builds (and remembers) the DM check only - kept for callers and tests that need just that. */
    fun buildCheck(): DmAcceptanceCheck? = buildChecks().dm

    /**
     * Rebuilds both checks when the set of latest Veritas grants changed (content, not count) since the last build.
     * [applyDm] (which must give the instance to BOTH DM consumers) is called only when DM gates are on, [applyMail]
     * only when mail gates are on, so a mail-only setup never touches the DM check and vice versa. Returns whether
     * it rebuilt. No network I/O.
     */
    fun refresh(
        applyDm: (DmAcceptanceCheck?) -> Unit,
        applyMail: (MailAcceptanceCheck?) -> Unit,
    ): Boolean {
        if (!anyEnabled) return false
        if (veritas.currentGrantsFingerprint() == lastGrantFingerprint) return false
        val checks = buildChecks()
        if (settings.enabled) applyDm(checks.dm)
        if (mailSettings.enabled) applyMail(checks.mail)
        logger.debug { "acceptance checks rebuilt after a trust graph change" }
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

    internal fun currentMailForTesting(): MailAcceptanceCheck? = currentMail.get()

    internal companion object {
        /** Maps the failed gates of a rejected mail to its counter bucket. */
        fun mailBlockReasonOf(failed: List<MailAcceptanceGate>): MailBlockReason =
            when {
                failed.size > 1 -> MailBlockReason.ALL_ACTIVE_GATES_FAILED
                failed.size == 1 && failed[0] is MailAcceptanceGate.VeritasPath ->
                    MailBlockReason.VERITAS_BELOW_THRESHOLD
                failed.size == 1 && failed[0] is MailAcceptanceGate.KarmaThreshold ->
                    MailBlockReason.KARMA_BELOW_THRESHOLD
                else -> MailBlockReason.POLICY
            }
    }
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
