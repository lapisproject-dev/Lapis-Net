package net.lapisphilosophorum.lapisnet.dm

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.directory.PeerDirectoryGossip
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import net.lapisphilosophorum.lapisnet.storage.NabuStorageException
import java.time.Duration
import java.time.Instant
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit

private val logger = KotlinLogging.logger {}

/**
 * The recipient-side driver for V0.8.5's offline mailbox: for every pending [MailboxPointer] in
 * [mailboxGossip]'s index, resolves the sender's CURRENT address via
 * [PeerDirectoryGossip.lookup] (V0.8.1), registers it, and attempts a direct Bitswap fetch of the
 * referenced blob by explicit peer - never via `NabuStorage.findProviders`, which remains broken
 * since V0.1.4 (see [MailboxPointer]'s own class doc comment for the full "central mechanism"
 * argument). On a successful fetch, the blob is structurally decoded as a [DmEnvelope] and handed
 * to [onDecodedEnvelope] (bound by the caller to `DmSessionManager::handleOfflineEnvelope`), which
 * routes it through the IDENTICAL session-resolution/decrypt/persist/dedup/listener-notification
 * logic the online path already uses - one trust boundary for both transports, not two
 * independently-reasoned-about ones. [onDecodedEnvelope] returns whether that outcome was FINAL for
 * this envelope's bytes (delivered, or cleanly/permanently rejected) vs. merely reflecting this
 * node's own current, mutable state (today: no session yet for the claimed sender) - see
 * `DmSessionManager.processInboundDmEnvelope`'s own doc comment on the return value. [attemptOne]
 * only calls [MailboxGossip.markResolved] on `true` - a `false` leaves the pointer pending so a
 * later poll pass, after this node's own state has moved on (e.g. a session was bootstrapped from a
 * different pointer), gets another chance to deliver it.
 *
 * Runs once, synchronously, at [attach] time - an initial pass over whatever [mailboxGossip]'s
 * index ALREADY HOLDS IN MEMORY at that moment (pointers received via live gossip since this node's
 * own process started, before this poller was wired up - NOT a reload from durable storage; see
 * [attach]'s own note on why nothing is actually reloaded on this node's own restart), then
 * periodically thereafter on [pollIntervalSeconds]. [pollOnce] never throws - each pointer's attempt
 * is independently try/caught so one bad pointer never blocks the rest of the pass (the adversarial
 * "unfetchable pointer must not wedge the poller" property).
 *
 * **Security audit round 1 findings (2026-08-27) closed in this class, stated here because they
 * shape [pollOnce]/[attemptOne]'s structure below:**
 * - **Unbounded, attacker-controlled, serialized network work per pass.** Every pending pointer
 *   used to get up to [net.lapisphilosophorum.lapisnet.directory.PeerRecordCodec.MAX_ADDRESSES]
 *   (16) SEQUENTIAL Bitswap timeouts (the SAME `peers` set passed to `storage.get` on every
 *   iteration - functionally one fetch attempt, priced sixteen times), with no per-pass budget and
 *   no per-sender cap - worst case [MailboxPointerIndex.MAX_TRACKED_POINTERS] (64,000) x 16 x
 *   `NabuStorage`'s own 10s default timeout, entirely attacker-mintable (a throwaway identity plus a
 *   signed pointer costs only local CPU). [attemptOne] now registers every address ONCE and issues a
 *   SINGLE `storage.get` (closing the 16x multiplier), and [pollOnce] enforces
 *   [POLL_PASS_WALL_CLOCK_BUDGET] and [MAX_FETCH_ATTEMPTS_PER_SENDER_PER_PASS] so ONE flooding
 *   sender identity cannot consume an entire pass's budget and starve every OTHER sender's pending
 *   pointers behind it for that pass - the flooded sender's own excess pointers simply carry over to
 *   the next pass. **This per-sender cap alone turned out NOT to prevent starvation across MULTIPLE
 *   distinct identities - see the round 2 finding immediately below, which is the actual fix for
 *   "the flood blocking unrelated senders indefinitely."**
 * - **Unsolicited outbound dials to unvalidated, gossip-supplied addresses.** [attemptOne] used to
 *   register and dial every address an attacker-chosen sender identity's PeerRecord names, with no
 *   address hygiene anywhere - a wildcard/multicast address would be dialed exactly like any other.
 *   [MultiaddrHygiene.isBlockedPrivateOrLocal] now filters those out before `registerPeerAddress`
 *   ever runs - see that object's own doc comment for the full analysis, INCLUDING why it is
 *   deliberately narrower than a textbook SSRF blocklist (loopback/RFC1918/link-local are this
 *   project's own primary, expected peer address space, not an anomaly to block).
 *
 * **Security audit round 2 major finding closed in this class - head-of-line blocking across
 * multiple sender identities (2026-08-27):** round 1's [MAX_FETCH_ATTEMPTS_PER_SENDER_PER_PASS] caps
 * attempts per SENDER, but [MailboxGossip.pending] returns a STABLY-ORDERED list with no rotation -
 * iterating it from index 0 on every pass meant that a small number of DISTINCT claimed sender
 * identities (no coordination between them required - a handful of legitimately-offline senders is
 * enough, no attacker needed) whose pointers happen to sort near the front and whose blobs are
 * directory-resolvable but genuinely unfetchable (a full `NabuStorage` Bitswap timeout each,
 * returning `true`/"attempt made" from [attemptOne] without ever being marked resolved) could
 * PERMANENTLY occupy the head of [POLL_PASS_WALL_CLOCK_BUDGET] - every pointer behind them, including
 * a genuinely fetchable one from an entirely unrelated sender, was never attempted, on ANY pass, for
 * as long as those pointers stayed pending. Proven with an executable probe: three blockless-but-
 * reachable pointers plus one genuinely fetchable pointer published last produced, on three
 * consecutive passes, zero received messages and the fetchable message never attempted at all. Fixed
 * by round-robining [pollOnce]'s pass start position via [passStartOffset] - see that field's and
 * [pollOnce]'s own doc comments for the mechanism. This is the "rotate the pass start offset across
 * passes" fix the finding itself suggested; per-pointer exponential backoff was considered as a
 * complementary fix but judged unnecessary on top of rotation, which alone already guarantees no
 * pending pointer can occupy the head of the budget indefinitely.
 *
 * **`MailboxPointer.senderIdentity` is a routing hint, NEVER trusted for message attribution or
 * authorization - V0.8.5 hardening pass finding, 2026-08-27, mirroring `DmSessionManager`'s own
 * CRITICAL IDENTITY-AUTHORITY RULE for `envelope.senderIdentity`/`fromPeerId`.** Everywhere in this
 * class that reads `pointer.senderIdentity` - [attemptOne]'s `peerDirectory.lookup` call and its
 * fingerprint-only logging, and [pollOnce]'s [fetchAttemptsBySender] cap key below - it does so
 * ONLY to pick which address to dial and which counter to charge, never to decide who actually sent
 * the underlying message: [DmEnvelope.senderIdentity] inside the fetched blob is a SEPARATE,
 * independently-signed-or-not claim, and only [DoubleRatchetSession]'s own AEAD-authenticated
 * decrypt (run downstream, inside `DmSessionManager.processInboundDmEnvelope`) is ever trusted for
 * "who actually sent this" - see that class's own doc comment. A pointer's `senderIdentity` and its
 * referenced blob's `DmEnvelope.senderIdentity` can legitimately disagree (anyone can sign a pointer
 * under a throwaway identity that references a blob whose decrypted envelope claims a wholly
 * different sender) with no exploitable consequence THIS class needs to guard against, precisely
 * because this class never treats either field as proof of authorship.
 *
 * **Does keying [MAX_FETCH_ATTEMPTS_PER_SENDER_PER_PASS] on this same untrusted-for-attribution
 * field open a fairness/DoS gap - e.g. a malicious pointer author claiming a VICTIM's
 * `senderIdentity` to burn the victim's fetch-attempt budget instead of their own? No - determined
 * and closed by construction, not merely accepted as residual risk.** `MailboxPointer.senderIdentity`
 * is UNTRUSTED only with respect to who authored the DmEnvelope inside the referenced blob; it is
 * NOT unauthenticated as a claim about who deposited THIS pointer. [MailboxPointer.verify] - called
 * by both [MailboxGossip.onGossipMessage] before a pointer is ever indexed AND, defensively, again
 * inside [MailboxPointerIndex.add] - checks the pointer's own signature against exactly this field,
 * so a pointer can only carry a given `senderIdentity` if its author possesses that identity's
 * secp256k1 private key. An attacker without a victim's private key cannot mint a pointer that
 * `fetchAttemptsBySender` will ever attribute to the victim; the only party who CAN make
 * `senderIdentity` say "the victim" is the victim's own key holder, which collapses this to the
 * ALREADY-accepted "one flooding identity spends its own pass budget" shape [pollOnce]'s round 1
 * finding above exists specifically to bound (see [MAX_FETCH_ATTEMPTS_PER_SENDER_PER_PASS]'s own doc
 * comment) - not a new gap. `MailboxPollerHardeningTest`'s round 1 regression case is exactly this
 * scenario exercised end to end (one real identity, six of its own pointers, capped at 4/pass).
 */
class MailboxPoller private constructor(
    private val mailboxGossip: MailboxGossip,
    private val storage: NabuStorage,
    private val peerDirectory: PeerDirectoryGossip,
    private val onDecodedEnvelope: (DmEnvelope) -> Boolean,
    private val pollIntervalSeconds: Long,
) {
    /** Lazily created so a [MailboxPoller] that is stopped before its first scheduled tick never
     * leaves a dangling thread - mirrors `DmProtocolHandler.scheduler`'s identical
     * `ScheduledThreadPoolExecutor` + `removeOnCancelPolicy = true` construction and its own doc
     * comment on why a bare `ScheduledThreadPoolExecutor` is used rather than
     * `Executors.newSingleThreadScheduledExecutor`. */
    private val executor: ScheduledExecutorService by lazy {
        ScheduledThreadPoolExecutor(1) { r -> Thread(r, "lapis-net-dm-mailbox-poll").apply { isDaemon = true } }
            .also { it.removeOnCancelPolicy = true }
    }
    private var scheduledTask: ScheduledFuture<*>? = null

    /** Index into the (per-pass, freshly-fetched) [MailboxGossip.pending] list that the NEXT
     * [pollOnce] pass should start iterating from - security audit ROUND 2 major finding fix, see
     * this class's own doc comment. Advances every pass, wrapping modulo the current pending-list
     * size; deliberately NOT reset on [attach]/[start] (a fresh poller naturally starts at 0, same as
     * the zero-initialized default) and deliberately NOT keyed by content id - a plain rotating
     * integer offset is enough to guarantee no list position is permanently "the head", which is the
     * only property this fix needs. */
    private var passStartOffset: Int = 0

    /**
     * Attempts fetch+decrypt for every currently-pending pointer, up to [POLL_PASS_WALL_CLOCK_BUDGET]
     * of wall-clock time and [MAX_FETCH_ATTEMPTS_PER_SENDER_PER_PASS] real (network-touching) fetch
     * attempts per distinct claimed sender identity - see this class's own doc comment for the
     * security-audit finding this closes. Expired pointers are marked resolved (stop retrying)
     * without a fetch attempt, and do not count against either budget. Never throws.
     *
     * **Round-robins the pass start position across calls (security audit ROUND 2 major finding).**
     * [MailboxGossip.pending] returns pointers in a STABLE order (insertion order, modulo resolved
     * entries being filtered out) with no rotation of its own - iterating it from index 0 on every
     * pass, as this method used to do, means a pointer that is directory-resolvable but whose blob is
     * genuinely unfetchable (a full `NabuStorage` Bitswap timeout, [POLL_PASS_WALL_CLOCK_BUDGET]'s
     * own ~10s default, per attempt) permanently occupies the head of every future pass: two such
     * pointers alone exhaust the entire [POLL_PASS_WALL_CLOCK_BUDGET], and every pointer behind them
     * - including a genuinely fetchable one - is never even ATTEMPTED, on any pass, for as long as the
     * blocking pointers remain pending. [MAX_FETCH_ATTEMPTS_PER_SENDER_PER_PASS] does not help here:
     * it caps attempts per SENDER IDENTITY within a pass, but a handful of DISTINCT throwaway
     * identities (or even a handful of legitimately-offline senders, no attacker required) each
     * contributing one unfetchable pointer defeats it just as completely. Fixed by starting each pass
     * at [passStartOffset] instead of index 0, and advancing [passStartOffset] to wherever THIS pass
     * stopped (budget-exhausted or a full lap) before returning - so the position that was "the head"
     * this pass is never "the head" again next pass, and every pending pointer is guaranteed to reach
     * the front of some future pass within a bounded number of passes, regardless of how many
     * pointers (and how many distinct claimed sender identities) are stuck ahead of it.
     */
    @Synchronized
    fun pollOnce(nowEpochSecond: Long = Instant.now().epochSecond) {
        mailboxGossip.evictExpired(nowEpochSecond)
        val passStartNanos = System.nanoTime()
        val fetchAttemptsBySender = HashMap<Secp256k1PublicKey, Int>()
        val pendingPointers = mailboxGossip.pending()
        if (pendingPointers.isEmpty()) {
            passStartOffset = 0
            return
        }
        val size = pendingPointers.size
        val startIndex = passStartOffset % size
        var processed = 0
        while (processed < size) {
            if (System.nanoTime() - passStartNanos >= POLL_PASS_WALL_CLOCK_BUDGET.toNanos()) {
                logger.debug {
                    "poll pass wall-clock budget ($POLL_PASS_WALL_CLOCK_BUDGET) exhausted - deferring " +
                        "remaining pending pointers to the next pass, which will start where this one " +
                        "stopped rather than from the head again"
                }
                break
            }
            val pointer = pendingPointers[(startIndex + processed) % size]
            try {
                if (pointer.notValidAfterEpochSecond < nowEpochSecond) {
                    mailboxGossip.markResolved(pointer)
                    processed++
                    continue
                }
                val attemptsSoFar = fetchAttemptsBySender.getOrDefault(pointer.senderIdentity, 0)
                if (attemptsSoFar >= MAX_FETCH_ATTEMPTS_PER_SENDER_PER_PASS) {
                    // This sender already used up its share of THIS pass's fetch-attempt budget -
                    // one flooding identity cannot consume the whole pass and starve every other
                    // sender's pending pointers behind it (see this class's own doc comment). Stays
                    // pending, retried next pass - never marked resolved, since this reflects this
                    // pass's own budget, not a property of the pointer's bytes.
                    processed++
                    continue
                }
                val attemptedFetch = attemptOne(pointer)
                if (attemptedFetch) fetchAttemptsBySender[pointer.senderIdentity] = attemptsSoFar + 1
            } catch (e: RuntimeException) {
                logger.warn(e) {
                    "unexpected exception polling mailbox pointer for CID ${pointer.blobCid} - leaving " +
                        "pending, will retry next poll"
                }
            }
            processed++
        }
        // Advance the rotation offset to wherever this pass actually stopped - a budget-truncated
        // pass resumes from there next time (see this method's own doc comment); a pass that
        // completed a full lap (processed == size) wraps back to startIndex, which is fine since
        // every pointer already got its chance this pass.
        passStartOffset = (startIndex + processed) % size
    }

    /**
     * One fetch+decrypt attempt for [pointer]. Returns `true` iff a real, network-touching fetch
     * attempt (`storage.get`) was actually made - used by [pollOnce] to charge this attempt against
     * [MAX_FETCH_ATTEMPTS_PER_SENDER_PER_PASS]; the cheap short-circuits below (no directory record,
     * no publicly-routable address) return `false` and are never charged, since they cost this node
     * nothing beyond a local map lookup.
     *
     * `senderRecord` is re-resolved on EVERY attempt (not cached across poll passes) - deliberate,
     * not overhead: the sender's address may have changed since the last attempt, so each poll cycle
     * uses [PeerDirectoryGossip.lookup]'s freshest data.
     *
     * **Address hygiene (security audit round 1 finding) runs BEFORE anything is registered or
     * dialed** - see [MultiaddrHygiene.isBlockedPrivateOrLocal]'s own doc comment for the full SSRF-
     * style analysis (and for why it deliberately does NOT block loopback/RFC1918/link-local, unlike
     * a textbook SSRF blocklist); a sender identity whose ENTIRE published address set is wildcard/
     * multicast is skipped for this attempt exactly like "no directory record at all", without ever
     * calling `registerPeerAddress`.
     *
     * **Registers every surviving address ONCE, then issues a SINGLE `storage.get` call** (security
     * audit round 1 finding) - previously looped `firstNotNullOfOrNull` over up to
     * [net.lapisphilosophorum.lapisnet.directory.PeerRecordCodec.MAX_ADDRESSES] (16) addresses,
     * calling `storage.get` with the SAME `peers = setOf(senderRecord.peerId)` on every iteration
     * (only the address book's most-recently-added entry actually varied) - a 16x self-inflicted
     * timeout multiplier for what was functionally one fetch attempt. `storage.registerPeerAddress`
     * is called before `storage.get` for the same reason as before (mirrors
     * `TwoNodeBitswapDirectFetchTest`'s established "register before fetch" sequence - Bitswap
     * resolves peer addresses from the libp2p host's address book, not from the `peers` set passed
     * to `get` directly), just for every surviving address up front instead of one-at-a-time.
     */
    private fun attemptOne(pointer: MailboxPointer): Boolean {
        val senderRecord = peerDirectory.lookup(pointer.senderIdentity) ?: return false

        val safeAddresses = senderRecord.addresses.filterNot { MultiaddrHygiene.isBlockedPrivateOrLocal(it) }
        if (safeAddresses.isEmpty()) {
            logger.debug {
                "claimed sender ${pointer.senderIdentity.fingerprint()}'s published addresses are all " +
                    "wildcard/multicast - refusing to dial, skipping this pass"
            }
            return false
        }

        val blobBytes =
            try {
                safeAddresses.forEach { address ->
                    // Security audit round 2 minor finding: Multiaddr.withP2P throws
                    // IllegalArgumentException when `address` already carries a /p2p component with
                    // a DIFFERENT value - reachable by any attacker-published PeerRecord, since
                    // PeerRecordCodec.decode deserializes addresses with no protocol filtering. That
                    // IAE is NOT a NabuStorageException, so left unguarded it would escape this
                    // try/catch entirely, aborting registration of every OTHER, perfectly good
                    // address in this forEach and skipping storage.get below outright - a single
                    // malformed address would make an otherwise-fetchable sender wholly unfetchable
                    // for the rest of this pointer's TTL. Wrapped per-address so only THIS address is
                    // skipped; every other surviving address still gets registered.
                    val addressWithP2P = runCatching { address.withP2P(senderRecord.peerId) }.getOrNull()
                    if (addressWithP2P == null) {
                        logger.debug {
                            "claimed sender ${pointer.senderIdentity.fingerprint()}'s published address " +
                                "$address already carries a conflicting /p2p component - skipping just this " +
                                "address, not the whole sender"
                        }
                    } else {
                        storage.registerPeerAddress(addressWithP2P)
                    }
                }
                storage.get(pointer.blobCid, peers = setOf(senderRecord.peerId))
            } catch (e: NabuStorageException) {
                null
            }
        if (blobBytes == null) return true // attempt made, but no reachable address / fetch timed out

        val envelope =
            try {
                DmEnvelopeCodec.decode(blobBytes)
            } catch (e: MalformedDmEnvelopeException) {
                logger.debug(e) {
                    "mailbox blob for CID ${pointer.blobCid} does not decode as a structurally valid " +
                        "DmEnvelope - discarding, will not retry (the bytes never change)"
                }
                mailboxGossip.markResolved(pointer)
                return true
            }

        // DmEnvelopeCodec.decode already ran above to distinguish "garbage frame, mark resolved"
        // from "worth attempting" - onDecodedEnvelope routes through DmSessionManager's own
        // session-resolution/decrypt/persist/dedup/listener-notification logic (identical to the
        // online path's own DmProtocol -> DmSessionManager.handleInboundEnvelope call chain), and
        // never throws.
        val outcomeIsFinal = onDecodedEnvelope(envelope)
        if (outcomeIsFinal) {
            // Delivered, cleanly-rejected-tamper/garbage (DmSessionManager's own try/catch around
            // session.decrypt swallows that internally and never re-throws here), or a clean
            // dedup-skip - none of these are worth retrying, the underlying bytes never change.
            mailboxGossip.markResolved(pointer)
        } else {
            // NOT resolved - the rejection reflects THIS node's own current, mutable state (today:
            // no session yet for the claimed sender), not a property of the envelope's bytes. Stays
            // pending so a later pollOnce pass - once this node's state has moved on, e.g. a
            // different pointer bootstrapped the missing session - gets another chance to deliver
            // the exact same bytes. See DmSessionManager.processInboundDmEnvelope's own doc comment
            // on the return value for the concrete ordering scenario this guards against.
            logger.debug {
                "mailbox blob for CID ${pointer.blobCid} was not yet processable given this node's " +
                    "current state - leaving pointer pending, will retry next poll"
            }
        }
        return true
    }

    /** Called once, synchronously, at [attach] time: whatever [mailboxGossip]'s index already holds
     * IN MEMORY - pointers received via live gossip since this node's own process started, before
     * this poller was wired up - gets an immediate first attempt, rather than waiting up to
     * [pollIntervalSeconds] for the first scheduled pass.
     *
     * **This is NOT a reload from durable storage, despite this wave's plan describing it as
     * "initial catch-up against already-stored pointers" - that phrasing overclaims.**
     * `MailboxGossip.attach` always constructs a brand-new, empty, in-memory-only
     * `MailboxPointerIndex`, and [NabuStorage] has no enumeration API to reload pointers from (the
     * same "no enumerate local CIDs primitive" gap `docs/architecture.adoc` already documents for
     * unrelated storage code). A pointer this node already received-and-persisted-the-raw-bytes-of
     * but had not yet fetched+decrypted before ITS OWN restart is therefore lost from this node's
     * own tracking on restart, with no local way to reconstruct it - symmetric to, but nowhere
     * previously documented alongside, `MailboxRedeliveryScheduler`'s own explicitly-documented
     * sender-side "lost on restart" limitation (see that class's own doc comment). The only recovery
     * path is the SENDER's [MailboxRedeliveryScheduler] re-announcing the same pointer again before
     * ITS OWN restart or the pointer's TTL, whichever comes first - this recipient-side gap does not
     * get a redelivery mechanism of its own in this wave. */
    private fun start() {
        pollOnce()
        // scheduleWithFixedDelay, not scheduleAtFixedRate - deliberately: a slow poll pass (many
        // pending pointers, several timing out against unreachable peers) must not queue up
        // overlapping runs; the next pass starts pollIntervalSeconds after the PREVIOUS one
        // finished, not on a fixed wall-clock cadence regardless of how long a pass took.
        scheduledTask =
            executor.scheduleWithFixedDelay(
                { runCatching { pollOnce() } },
                pollIntervalSeconds,
                pollIntervalSeconds,
                TimeUnit.SECONDS,
            )
    }

    /** Cancels the periodic poll task and shuts down this poller's background scheduler - mirrors
     * `DmProtocolHandler.stop`'s lifecycle-symmetry convention. Idempotent. */
    fun stop() {
        scheduledTask?.cancel(false)
        executor.shutdownNow()
    }

    companion object {
        /** Cheap local sweep + opportunistic fetch retry - can run more often than
         * [MailboxRedeliveryScheduler]'s own default cadence, since polling is a purely local,
         * bounded-cost operation (an index sweep plus, at most, one Bitswap attempt per pending
         * pointer) with no network broadcast of its own. Same "generous, provisional magnitude, not
         * derived from pilot data" framing as every sibling cap in this codebase. */
        const val DEFAULT_POLL_INTERVAL_SECONDS = 60L

        /** Wall-clock ceiling on a single [pollOnce] pass's total fetch-attempt time - security
         * audit round 1 finding: without this, a large flood of tracked-but-unreachable pointers
         * (bounded only by [MailboxPointerIndex.MAX_TRACKED_POINTERS], 64,000) could keep a pass
         * running for hours. Comfortably under [DEFAULT_POLL_INTERVAL_SECONDS] so a budget-truncated
         * pass still leaves headroom before the next scheduled pass would otherwise start (moot
         * regardless, since [scheduleWithFixedDelay] never overlaps passes - this is about bounding
         * PER-PASS latency, not about avoiding overlap). Same "generous headroom, provisional
         * magnitude" framing as every sibling cap in this codebase. */
        val POLL_PASS_WALL_CLOCK_BUDGET: Duration = Duration.ofSeconds(20)

        /** Caps how many real (network-touching) fetch attempts [pollOnce] will make per distinct
         * claimed sender identity, WITHIN ONE PASS - security audit round 1 finding: without this, a
         * single flooding sender identity's pointers (encountered first in [MailboxGossip.pending]'s
         * insertion order) could alone consume the ENTIRE [POLL_PASS_WALL_CLOCK_BUDGET], starving
         * every OTHER sender's genuinely fetchable pointers behind it for that pass. A capped sender's
         * EXCESS pointers are simply left pending for the next pass, never marked resolved - this caps
         * per-pass THROUGHPUT for one sender, it does not lose any pointer. Deliberately small - one
         * legitimate sender rarely has many simultaneously-pending offline messages to the SAME
         * recipient - same "provisional magnitude, not derived from pilot data" framing as every
         * sibling cap in this codebase. */
        const val MAX_FETCH_ATTEMPTS_PER_SENDER_PER_PASS = 4

        fun attach(
            mailboxGossip: MailboxGossip,
            storage: NabuStorage,
            peerDirectory: PeerDirectoryGossip,
            onDecodedEnvelope: (DmEnvelope) -> Boolean,
            pollIntervalSeconds: Long = DEFAULT_POLL_INTERVAL_SECONDS,
        ): MailboxPoller =
            MailboxPoller(mailboxGossip, storage, peerDirectory, onDecodedEnvelope, pollIntervalSeconds)
                .also { it.start() }
    }
}
