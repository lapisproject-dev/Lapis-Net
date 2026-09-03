package net.lapisphilosophorum.lapisnet.call

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.core.ratelimit.FixedWindowRateLimiter
import net.lapisphilosophorum.lapisnet.dm.DmInboundCallSignal
import net.lapisphilosophorum.lapisnet.dm.DmSessionManager
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.security.SecureRandom
import java.time.Duration
import java.time.Instant
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CopyOnWriteArraySet
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

private val logger = KotlinLogging.logger {}

private enum class CallDirection { OUTGOING, INCOMING }

/** One call's mutable state - touched EXCLUSIVELY from [CallManager]'s state thread (see that
 * class's own doc comment on its three-executor concurrency model). No field here is itself
 * synchronized; the single-threaded state executor is what makes that safe. */
private class ActiveCall(
    val callId: CallId,
    val peer: Secp256k1PublicKey,
    val direction: CallDirection,
) {
    var state: CallState =
        if (direction == CallDirection.OUTGOING) CallState.OUTGOING_RINGING else CallState.INCOMING_RINGING
    var mediaSession: CallMediaSession? = null
    var timeoutTask: ScheduledFuture<*>? = null

    /** Only ever set for an INCOMING call, between [CallManager.handleInboundInvite] admitting it
     * and a local [CallManager.acceptCall] consuming it. */
    var remoteOfferSdp: String? = null
}

private fun CallMediaSession.closeQuietly() {
    try {
        close()
    } catch (e: RuntimeException) {
        logger.debug(e) { "error closing call media session - already-failed/closed session, ignoring" }
    }
}

/**
 * Drives the full 1:1-call lifecycle - INVITE/ACCEPT/REJECT/HANGUP - over a [CallSignalTransport] (in
 * production, [DmCallSignalTransport] wrapping a real [DmSessionManager]) and a [CallMediaEngine] (in
 * production, `WebRtcCallMediaEngine`). See `docs/architecture.adoc`'s "1:1 calls over WebRTC
 * (V0.8.7)" section for the full design; this class doc comment covers the concurrency model that
 * every method body below depends on.
 *
 * **Three executors, strict division of labor - this is load-bearing, not a style preference:**
 * 1. **State thread** (`lapis-net-call-state`, single-threaded, daemon) - EVERY mutation of a call's
 *    [ActiveCall] fields, EVERY [CallEvent] emission, and every routing decision happens here, and
 *    ONLY here. Because it is single-threaded, no explicit lock is needed to reason about
 *    [calls]/an [ActiveCall]'s own fields - FIFO ordering on this one queue is the entire
 *    synchronization story.
 * 2. **Media thread** (`lapis-net-call-media`, single-threaded, daemon) - everything that BLOCKS:
 *    [CallMediaSession.createOffer]/`acceptOfferAndCreateAnswer`/`applyAnswer` (ICE gathering waits),
 *    [CallMediaSession.close], and every [CallSignalTransport.send] (a real
 *    [DmCallSignalTransport.send] dials the peer and can block for
 *    `DmSessionManager.DIAL_TIMEOUT`, 15 seconds).
 * 3. **Timeout scheduler** (`lapis-net-call-timeout`, a bare [ScheduledThreadPoolExecutor], NOT
 *    `Executors.newSingleThreadScheduledExecutor` - that factory method wraps the real
 *    `ScheduledThreadPoolExecutor` in a `DelegatedScheduledExecutorService` that can never be cast
 *    back, which is exactly the trap `DmProtocolHandler`'s own identical scheduler field already
 *    documents hitting in V0.8.4 - `removeOnCancelPolicy = true` so every timeout this class
 *    cancels ([cancelTimeout]) is actually reclaimed rather than sitting in the delay queue until it
 *    would have fired anyway.
 *
 * **Why inbound signal handling posts to the state thread instead of acting inline - the single most
 * important rule in this class.** [onInboundCallSignal] is invoked by `DmSessionManager` from
 * WITHIN `DmSessionManager.withPeerLock(sender)` - see `DmSessionManager.addCallSignalListener`'s own
 * doc comment. `withPeerLock` is `synchronized` (reentrant), so a listener that synchronously called
 * `DmSessionManager.sendCallSignal` for the SAME peer would not deadlock, but it WOULD run a
 * network dial that can take up to 15 seconds while holding that peer's stripe lock, blocking every
 * OTHER DM operation (text messages, mailbox delivery) for that peer for the duration. Every send in
 * this class ([sendSignalAsync], and every send inside [runOutgoingMediaSetup]/
 * [runIncomingMediaSetup]) therefore runs on the media thread, never inline from a signal-handling
 * callback - and [onInboundCallSignal] itself does nothing but decode-free dispatch onto the state
 * thread, returning to the Netty/`withPeerLock` caller immediately.
 */
class CallManager private constructor(
    private val transport: CallSignalTransport,
    private val mediaEngine: CallMediaEngine,
    private val config: CallConfig,
    private val random: SecureRandom,
    private val clock: () -> Instant,
) {
    private val listeners = CopyOnWriteArrayList<(CallEvent) -> Unit>()

    /** Shares this manager's own injectable [clock] - see [CallLog]'s own constructor doc comment
     * for why an independent `Instant.now()` here would be inconsistent with every other
     * timestamp this class reads through [clock] (via [nowMillis]). */
    private val callLog = CallLog(clockSeconds = { clock().epochSecond })

    /** Touched EXCLUSIVELY from [stateExecutor] - see this class's own doc comment. */
    private val calls = mutableMapOf<CallId, ActiveCall>()

    /** Every [CallMediaSession] [mediaEngine] has ever handed out that has not yet been closed -
     * added the instant [CallMediaEngine.newSession] returns (in [runOutgoingMediaSetup]/
     * [runIncomingMediaSetup], on [mediaExecutor]), removed by [closeAndUntrack] (the only path any
     * session is ever closed through). A [java.util.concurrent.CopyOnWriteArraySet] because it is
     * written from more than one thread with no separate lock needed - same "small, low-churn set,
     * correctness over write throughput" tradeoff as [listeners].
     *
     * **NOT simply "[mediaExecutor] writes, [stop] itself reads/drains"** - a claim this exact
     * comment made incorrectly before (see [liveMediaSessionCountForTesting]'s own doc comment for
     * the fuller correction history, round 2026-09-02). The writers are [mediaExecutor] (session
     * creation, and every session close reached from that thread) AND [stateExecutor], for exactly
     * the ONE deliberate exception [attachMediaSessionOrCloseIfEnded]'s own doc comment documents
     * (its already-ended-call fallback normally re-queues the close onto [mediaExecutor] same as
     * everywhere else; it closes inline, right there on the state thread, only when that hand-off is
     * itself rejected because [mediaExecutor] is already shut down) - never from
     * [endCallOnStateThread] or [handleInboundAccept], both of which used to also close inline on a
     * rejected [mediaExecutor] hand-off until the MAJOR review-round finding (2026-09-02, round 6)
     * removed that: see each of their own doc comments for the empirically-reproduced native
     * double-free that inline close caused. And the drain is not [stop] touching this set on its own
     * (arbitrary) caller thread at all - it is a task [stop] SUBMITS onto [mediaExecutor] (the
     * safety-net sweep below), running there like every other [mediaExecutor] write.
     *
     * **Why this exists at all - MAJOR review-round finding (2026-09-02).** [executeOnStateThreadIfRunning]
     * only closes a session whose [stateExecutor] hand-off to [attachMediaSessionOrCloseIfEnded] was
     * REJECTED (the executor already terminated at submission time) - it does nothing for one that
     * was ACCEPTED (successfully enqueued) but then DISCARDED, still unexecuted, by [stop]'s own
     * `stateExecutor.shutdownNow()`. That happens whenever the state thread is busy - e.g. stuck
     * behind a slow listener, exactly the scenario [stop]'s own `QUERY_TIMEOUT` fallback already
     * documents - for the whole window between the hand-off being queued and `shutdownNow()` running.
     * A session stuck in that window is attached to no [ActiveCall] (the queued task that would do
     * that never runs) and reaches no other close path either - this registry is the ONLY structure
     * that still knows it exists, independent of whether its own attach ever got the chance to run.
     * [stop] sweeps whatever remains here as its LAST [mediaExecutor] task, closing it regardless of
     * why the normal attach-or-close path never reached it. */
    private val liveMediaSessions = CopyOnWriteArraySet<CallMediaSession>()

    /** Closes [session] and removes it from [liveMediaSessions] - the ONLY path by which any session
     * this class creates is ever closed, so [stop]'s final registry sweep (see that field's own doc
     * comment) never redundantly re-closes one already closed through the normal attach/
     * [endCallOnStateThread] path. [CallMediaSession.close] is itself idempotent regardless (every
     * real and fake implementation guards on its own `closed` flag) - removing from the registry here
     * is about keeping its size an honest "sessions still needing a close", not correctness. */
    private fun closeAndUntrack(session: CallMediaSession) {
        liveMediaSessions.remove(session)
        session.closeQuietly()
    }

    /** One [FixedWindowRateLimiter] PER CALLING PEER, deliberately not a single shared instance. A
     * single shared limiter would let one hostile-but-authenticated sender (an INVITE cannot reach
     * [handleInboundInvite] without an already-established `DmSessionManager` session for its
     * sender, but that session's QUARANTINE classification is only known AFTER decryption - see
     * that function's own `quarantined` parameter) burn through the entire window's budget in the
     * first second, silently starving every other, unrelated sender's legitimate INVITEs for the
     * rest of that window - the exact opposite of what a per-caller flood guard is meant to do.
     * Touched EXCLUSIVELY from [stateExecutor], same discipline as [calls] itself - no separate
     * synchronization needed.
     *
     * **Bounded via LRU eviction, NOT "naturally bounded" by the session count** - review-fix round
     * correction (2026-09-02): an earlier version of this comment claimed this map was implicitly
     * capped by `DmSessionManager.MAX_LIVE_SESSIONS` because "a sender cannot reach this map
     * without a live session". That reasoning was wrong on two counts - `MAX_LIVE_SESSIONS` bounds
     * how many sessions are cached SIMULTANEOUSLY (an LRU itself, evicting the coldest entry as new
     * sessions arrive), not how many DISTINCT senders a session was ever created for over this
     * process's entire lifetime; and [inviteRateLimiterFor] is called (see [handleInboundInvite])
     * BEFORE the quarantine check, so even a sender whose INVITE is silently dropped for being
     * quarantined still gets an entry here. An attacker who mints a fresh identity per INVITE (each
     * one, at most, needing one new session - `DmSessionManager
     * .MAX_PREKEY_CONSUMPTIONS_PER_WINDOW` bounds the RATE of new sessions, not a lifetime total)
     * would otherwise grow this map without bound for as long as this node stays up - exactly the
     * "unbounded per-identity map" shape `DmSessionManager`'s own class doc comment (on
     * [DmSessionManager]'s dedup/stripe-lock caches) already treats as unacceptable. An access-
     * order [LinkedHashMap] with [LinkedHashMap.removeEldestEntry] - the identical pattern
     * `DmSessionManager.liveSessionCache` already uses - closes this: the least-recently-seen
     * sender's limiter is evicted once [MAX_INVITE_RATE_LIMITER_ENTRIES] is exceeded, never this
     * map's total size. */
    private val inviteRateLimiters =
        object : LinkedHashMap<Secp256k1PublicKey, FixedWindowRateLimiter>(16, 0.75f, true) {
            override fun removeEldestEntry(
                eldest: MutableMap.MutableEntry<Secp256k1PublicKey, FixedWindowRateLimiter>,
            ): Boolean = size > MAX_INVITE_RATE_LIMITER_ENTRIES
        }

    private fun inviteRateLimiterFor(sender: Secp256k1PublicKey): FixedWindowRateLimiter =
        inviteRateLimiters.getOrPut(sender) {
            FixedWindowRateLimiter(config.maxInvitesPerWindow, config.inviteRateWindow) { clock().toEpochMilli() }
        }

    /** Every [CallId] a [CallEvent.IncomingCall]`(quarantined = true)` has already been emitted for -
     * review-fix round correction (2026-09-03): [CallEvent.IncomingCall]'s own doc comment promises
     * that event is "the ONLY event this manager will ever emit for that [callId]" when
     * [CallConfig.autoRejectQuarantined] is `true`, but the silent-drop branch below never recorded
     * [signal].[CallSignal.callId] into [calls] (by design - it must never become an actionable,
     * answerable call), so [handleInboundInvite]'s OWN retransmit guard just above (`calls
     * .containsKey(signal.callId)`) could never catch a repeat. A hostile sender who re-encrypts the
     * identical `CallSignal` bytes under a fresh DM ratchet message produces a distinct
     * `DmDedupKey` (see `DmSessionManager.DmDedupKey.of` - keyed on the ratchet message HEADER -
     * (senderIdentity, ratchetPublicKey, messageNumber), never on the ciphertext or the plaintext
     * `callId` it decrypts to - so a fresh `session.encrypt` of the identical plaintext advances `Ns`
     * and yields a different key) for every retransmit, sailing straight past DM-layer dedup
     * too - so, left unguarded, every retransmit re-emitted [CallEvent.IncomingCall] for the SAME
     * [callId], directly contradicting the "ONLY event" promise and inflating any audit/log a
     * listener keeps per emitted event well past the true number of distinct quarantined attempts.
     * Bounded the identical way [inviteRateLimiters] is (LRU eviction via an access-order
     * [LinkedHashMap] used as a set) - an unbounded set keyed by attacker-chosen [CallId]s would
     * itself be the exact "unbounded per-identity map" shape this class already treats as
     * unacceptable elsewhere. */
    private val quarantinedCallIds =
        object : LinkedHashMap<CallId, Boolean>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<CallId, Boolean>): Boolean =
                size > MAX_QUARANTINED_CALL_IDS
        }

    /** Test-only visibility into [inviteRateLimiters]' current size - round-trips through
     * [stateExecutor] exactly like [activeCalls] so it observes the map only after every
     * state-thread mutation queued up to this call has actually applied. `internal`, never a
     * production entry point - exists purely so a test can assert the LRU eviction bound
     * [inviteRateLimiters]' own doc comment promises. */
    internal fun inviteRateLimiterCountForTesting(): Int {
        val future = CompletableFuture<Int>()
        stateExecutor.execute { future.complete(inviteRateLimiters.size) }
        return future.get(QUERY_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS)
    }

    /** Test-only visibility into [quarantinedCallIds]' current size - round-trips through
     * [stateExecutor] exactly like [inviteRateLimiterCountForTesting]. `internal`, never a production
     * entry point - exists purely so a test can assert the LRU eviction bound [quarantinedCallIds]'
     * own doc comment promises. */
    internal fun quarantinedCallIdCountForTesting(): Int {
        val future = CompletableFuture<Int>()
        stateExecutor.execute { future.complete(quarantinedCallIds.size) }
        return future.get(QUERY_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS)
    }

    /** Test-only visibility into [liveMediaSessions]' current size - unlike
     * [inviteRateLimiterCountForTesting] this does NOT round-trip through [stateExecutor] itself, so
     * it is safe to call even after [stateExecutor] has been shut down. Correction (2026-09-02
     * review round, code-inspection finding): an earlier version of this comment claimed
     * [liveMediaSessions] was "never touched from [stateExecutor] at all, only [mediaExecutor] and
     * [stop]'s own caller thread" - both halves were wrong. It IS touched from [stateExecutor]:
     * [attachMediaSessionOrCloseIfEnded]'s already-ended-call fallback normally re-queues the close
     * onto [mediaExecutor] same as everywhere else, but falls back to closing a session inline,
     * right there on the state thread, in the one case where that hand-off is itself rejected
     * because [mediaExecutor] is already shut down (see that function's own doc comment on its
     * else-branch for why that fallback is safe). And [stop]'s own caller thread never touches this
     * set directly at all - both of [stop]'s accesses (the toClose-closing task and the safety-net
     * sweep) are themselves [mediaExecutor]
     * submissions, not code running on whatever thread called [stop]. `internal`, never a production
     * entry point - exists purely so a test can assert the MAJOR review-round finding's safety-net
     * sweep actually drains the registry rather than merely closing what it finds. */
    internal fun liveMediaSessionCountForTesting(): Int = liveMediaSessions.size

    private val stateExecutor =
        Executors.newSingleThreadExecutor { runnable ->
            Thread(runnable, "lapis-net-call-state").apply { isDaemon = true }
        }
    private val mediaExecutor =
        Executors.newSingleThreadExecutor { runnable ->
            Thread(runnable, "lapis-net-call-media").apply { isDaemon = true }
        }
    private val scheduler =
        ScheduledThreadPoolExecutor(
            1,
        ) { runnable -> Thread(runnable, "lapis-net-call-timeout").apply { isDaemon = true } }
            .also { it.removeOnCancelPolicy = true }

    /** Registers a listener invoked for every [CallEvent] - ALWAYS from [stateExecutor]. A listener
     * that throws is caught and logged; it never prevents delivery to other listeners or corrupts
     * this manager's own state. */
    fun addCallListener(listener: (CallEvent) -> Unit) {
        listeners.add(listener)
    }

    /** Places an outgoing call to [peer], returning a freshly minted [CallId] immediately - the
     * actual `INVITE` build-and-send happens asynchronously (state thread, then media thread); a
     * caller learns the outcome via [addCallListener] ([CallEvent.OutgoingRinging] first, eventually
     * [CallEvent.Active] or [CallEvent.Ended]), never via this function's return value alone -
     * EXCEPT when the call is never admitted in the first place (this node's own
     * [MAX_TRACKED_CALLS] ceiling, or [CallConfig.maxConcurrentCalls] already at capacity, e.g. its
     * default of 1 while another call is active): then a single [CallEvent.Ended] with
     * [CallEndReason.BUSY] is the ONLY event this [callId] ever gets, with no preceding
     * [CallEvent.OutgoingRinging] - see [placeCallOnStateThread]'s own early-return checks. */
    fun placeCall(peer: Secp256k1PublicKey): CallId {
        val callId = CallId.random(random)
        // Guarded like every internal stateExecutor hand-off - MEDIUM review-round finding (2026-09-02):
        // unlike every other stateExecutor.execute call site in this class, this was one of five PUBLIC
        // entry points that submitted unguarded, so a caller invoking it after stop() (stateExecutor
        // already shutdownNow()'d) got an uncaught RejectedExecutionException straight out of a public
        // API method instead of the same "safe to call after stop(), effectively a no-op" contract this
        // class's other query methods (activeCalls(), stop() itself) already document and provide. No
        // action needed on rejection: there is no ActiveCall to tear down, nothing was ever admitted.
        executeOnStateThreadIfRunning("placing outgoing call to ${peer.fingerprint()}") {
            placeCallOnStateThread(callId, peer)
        }
        return callId
    }

    /** Accepts a currently [CallState.INCOMING_RINGING] call. A no-op (logged, not thrown) for an
     * unknown [callId] or one no longer in that state - mirrors `DmSessionManager`'s own "public-data
     * rejection, never a crash" discipline for a caller racing this manager's own async state
     * transitions. Also a no-op (same discipline, same MEDIUM review-round finding, 2026-09-02) for a
     * caller racing this manager's own [stop] - see [placeCall]'s own doc comment on
     * [executeOnStateThreadIfRunning] for why an unguarded submission here used to throw instead. */
    fun acceptCall(callId: CallId) {
        executeOnStateThreadIfRunning("accepting call ${callId.fingerprint()}") { acceptCallOnStateThread(callId) }
    }

    fun rejectCall(
        callId: CallId,
        reason: CallEndReason = CallEndReason.DECLINED,
    ) {
        // Guarded - see placeCall's own doc comment (MEDIUM review-round finding, 2026-09-02).
        executeOnStateThreadIfRunning("rejecting call ${callId.fingerprint()}") {
            rejectCallOnStateThread(callId, reason)
        }
    }

    fun hangUp(
        callId: CallId,
        reason: CallEndReason = CallEndReason.LOCAL_HANGUP,
    ) {
        // Guarded - see placeCall's own doc comment (MEDIUM review-round finding, 2026-09-02).
        executeOnStateThreadIfRunning("hanging up call ${callId.fingerprint()}") {
            hangUpOnStateThread(callId, reason)
        }
    }

    /** A snapshot of every call currently tracked, oldest concerns first. Blocks briefly (bounded by
     * [QUERY_TIMEOUT]) on the state thread - acceptable for a query this codebase never calls from a
     * hot path (a future UI's own polling loop, or a test assertion). Returns an empty list, never
     * throws, once [stop] has run (or if the state thread is stuck behind a slow listener past
     * [QUERY_TIMEOUT] - see [stop]'s own identical fallback) - a caller polling this in a loop while
     * the node is shutting down must see "no calls", not a [RejectedExecutionException]/
     * `TimeoutException` it was never told to expect. */
    fun activeCalls(): List<CallSnapshot> {
        val future = CompletableFuture<List<CallSnapshot>>()
        try {
            stateExecutor.execute {
                future.complete(calls.values.map { CallSnapshot(it.callId, it.peer, it.state) })
            }
        } catch (e: RejectedExecutionException) {
            logger.debug(e) { "activeCalls(): stateExecutor already shut down - returning empty list" }
            return emptyList()
        }
        return try {
            future.get(QUERY_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            logger.debug(e) { "activeCalls(): interrupted while querying - returning empty list" }
            emptyList()
        } catch (e: Exception) {
            // TimeoutException/ExecutionException - see stop()'s own identical catch for why a
            // RuntimeException catch here would never fire for either.
            logger.debug(e) { "activeCalls(): timed out querying - returning empty list" }
            emptyList()
        }
    }

    /** A snapshot of every ended call recorded so far, oldest first - see [CallLog]'s own class doc
     * comment for the FIFO cap and the deliberate "in-memory only, nothing persisted" discipline.
     * Safe to call from any thread and does not touch [stateExecutor] at all - [CallLog] guards its
     * own state internally ([CallLog.entries] is itself `@Synchronized`). */
    fun callHistory(): List<CallLogEntry> = callLog.entries()

    /** Guards [stop] so a second (or later) call is a true no-op rather than racing the first call's
     * already-shutdown executors - see [stop]'s own doc comment. */
    private val stopped = AtomicBoolean(false)

    /** Ends every tracked call (closing its media session, cancelling its timeout - never notifying
     * the remote peer, mirroring `DmSessionManager.stop`'s own "one-way, no graceful handshake"
     * shutdown discipline) and shuts down every executor plus [mediaEngine] itself. Safe to call more
     * than once; this manager is not usable again afterward.
     *
     * **Idempotency is enforced structurally, not merely by [mediaEngine]/executors already being
     * idempotent-safe themselves**: without the [stopped] guard below, a second call would still
     * reach `stateExecutor.execute { ... }` after the first call's own [stateExecutor]
     * `.shutdownNow()` already ran - `ThreadPoolExecutor`'s default `AbortPolicy` then throws
     * `RejectedExecutionException` for that submission, straight out of this function, breaking
     * exactly the "safe to call more than once" contract this doc comment promises (e.g. a JVM
     * shutdown hook AND an explicit `LapisNode` teardown both calling this). */
    fun stop() {
        if (!stopped.compareAndSet(false, true)) return
        val snapshot = CompletableFuture<List<ActiveCall>>()
        stateExecutor.execute {
            val all = calls.values.toList()
            calls.clear()
            snapshot.complete(all)
        }
        val toClose =
            try {
                snapshot.get(QUERY_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS)
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                logger.debug(e) { "stop(): interrupted while collecting active calls - shutting down anyway" }
                emptyList()
            } catch (e: Exception) {
                // TimeoutException (the state thread is stuck behind a slow listener - see emit()'s
                // own doc comment) or ExecutionException (the state-thread task itself threw, which
                // should be structurally impossible - it only ever touches calls/snapshot). Neither
                // is a RuntimeException - CompletableFuture.get(long, TimeUnit) declares exactly
                // these three checked exceptions, so a `catch (e: RuntimeException)` here would never
                // fire for the one failure mode this fallback exists to handle.
                logger.debug(e) { "stop(): timed out collecting active calls - shutting down anyway" }
                emptyList()
            }
        toClose.forEach { call -> call.timeoutTask?.cancel(false) }
        // Enqueued onto mediaExecutor - NOT called inline on stop()'s own (arbitrary) caller thread
        // - review-fix round-2 MEDIUM finding (2026-09-02): CallMediaSession.close (this class's own
        // doc comment, "Media thread") can run concurrently with a still-in-flight
        // createOffer/acceptOfferAndCreateAnswer/transport.send for the SAME session on the real
        // media thread otherwise - two threads touching one native RTCPeerConnection at once, one of
        // them freeing it. Submitted BEFORE mediaExecutor.shutdown() below, while the executor is
        // still definitely accepting work (this whole function runs after the [stopped] guard above
        // already made a concurrent second stop() a no-op), so this task is safely queued ahead of
        // that shutdown() call - the pairing the comment on that call explains next.
        mediaExecutor.execute { toClose.forEach { call -> call.mediaSession?.let { closeAndUntrack(it) } } }
        // Safety-net sweep for [liveMediaSessions] - see that field's own doc comment for the MAJOR
        // review-round finding (2026-09-02) this closes: a session whose attach hand-off to
        // stateExecutor was ACCEPTED but then DISCARDED, still unexecuted, by stateExecutor
        // .shutdownNow() below is never attached to any ActiveCall (so the toClose loop just above
        // never sees it) and never reaches attachMediaSessionOrCloseIfEnded's own else-branch close
        // either (that queued task is exactly what got discarded). Queued as the LAST mediaExecutor
        // task - strictly AFTER the toClose-closing task above (so a session already closed there is
        // simply a no-op removal here) and strictly BEFORE mediaExecutor.shutdown() below - so it is
        // guaranteed to run, on the correct thread, before mediaEngine.close() disposes the factory
        // every remaining session is backed by.
        mediaExecutor.execute { liveMediaSessions.toList().forEach { session -> closeAndUntrack(session) } }
        scheduler.shutdownNow()
        stateExecutor.shutdownNow()
        // Graceful shutdown() + a BOUNDED awaitTermination() - deliberately NOT shutdownNow() -
        // before mediaEngine.close() below. Fix for a review-round MAJOR finding (2026-09-02):
        // endCallOnStateThread (and every other call-ending path) enqueues a call's own
        // `session.closeQuietly()` onto mediaExecutor rather than closing it inline - see that
        // function's own call site. A call that ended just before this stop() (e.g. a HANGUP whose
        // own sendSignalAsync is still blocked inside a slow transport.send - a real
        // DmCallSignalTransport.send can dial for up to DmSessionManager.DIAL_TIMEOUT, 15s) has
        // ALREADY been removed from `calls` by the time `toClose` above is captured, so its session
        // is never closed by the loop above either - its ONLY close ever queued for it is the one
        // sitting behind that slow send on mediaExecutor (or, now, behind the closeQuietly() task
        // just enqueued above for whatever WAS still in `calls`). A bare mediaExecutor.shutdownNow()
        // here would DISCARD both, then mediaEngine.close() would dispose the whole
        // PeerConnectionFactory out from under a session that was never actually closed -
        // WebRtcCallMediaEngine.close's own doc comment states this exact ordering ("CallManager...
        // is responsible for closing every session before closing the engine") is required to avoid
        // the native `Native object was not deleted` crash that class's close() method documents.
        // A graceful shutdown() lets every already-queued task (the slow send, then the close behind
        // it) actually finish before mediaExecutor terminates; MEDIA_SHUTDOWN_TIMEOUT gives that
        // pairing enough headroom (DIAL_TIMEOUT plus margin) while still keeping stop() bounded.
        val mediaExecutorDrainedCleanly =
            try {
                mediaExecutor.shutdown()
                mediaExecutor.awaitTermination(MEDIA_SHUTDOWN_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS)
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                false
            }
        if (!mediaExecutorDrainedCleanly) {
            // Best-effort fallback for a genuinely stuck media thread (e.g. a hung native call into
            // transport.send that never returns and never responds to interruption) - forcing
            // shutdown here trades the same leak/crash risk this fix closes for the alternative of
            // stop() blocking forever, which this class's own "safe to call... during a JVM shutdown
            // hook" contract cannot accept either. Logged loudly (warn, not debug) because it means
            // the ordering guarantee above did NOT hold for this call to stop().
            logger.warn {
                "stop(): mediaExecutor did not drain within $MEDIA_SHUTDOWN_TIMEOUT - forcing " +
                    "shutdown; a queued call-media-session close may not have run before " +
                    "mediaEngine.close() below"
            }
            mediaExecutor.shutdownNow()
        }
        mediaEngine.close()
    }

    // ---- inbound signal entry point -----------------------------------------------------------

    /** The ONLY inbound entry point - wired to `DmSessionManager.addCallSignalListener` by [attach],
     * and called directly by test harnesses via [attachToTransport]'s returned manager. `internal`,
     * not `private`, for exactly that second reason. See this class's own doc comment for why this
     * function does nothing but dispatch onto [stateExecutor]. */
    internal fun onInboundCallSignal(inbound: DmInboundCallSignal) {
        // Guarded like every other stateExecutor hand-off - MEDIUM review-round finding (2026-09-02):
        // this function's own class doc comment already promises "onInboundCallSignal itself must
        // never throw - it is invoked directly from a Netty callback in production and must never let
        // anything escape" (see CallManagerAbuseTest's own assertion of that exact contract), but an
        // unguarded stateExecutor.execute here still let an uncaught RejectedExecutionException escape
        // straight out of that Netty callback for any CALL_SIGNAL arriving after stop() has already
        // shut stateExecutor down - e.g. because DmSessionManager has no removeCallSignalListener and
        // this manager's onInboundCallSignal stays registered there for the node's remaining lifetime.
        // No action needed on rejection: stop() is tearing this call down (or already has), so silently
        // dropping one more inbound signal changes nothing about this node's own state.
        executeOnStateThreadIfRunning("handling inbound call signal from ${inbound.sender.fingerprint()}") {
            try {
                handleInboundCallSignalOnStateThread(inbound)
            } catch (e: RuntimeException) {
                logger.warn(
                    e,
                ) { "unexpected exception handling inbound call signal from ${inbound.sender.fingerprint()}" }
            }
        }
    }

    // ---- state-thread-only methods below this point -------------------------------------------

    private fun nowMillis(): Long = clock().toEpochMilli()

    private fun emit(event: CallEvent) {
        listeners.forEach { listener ->
            try {
                listener(event)
            } catch (e: RuntimeException) {
                logger.warn(e) { "call listener threw - other listeners still notified" }
            }
        }
    }

    private fun scheduleTimeout(
        call: ActiveCall,
        duration: Duration,
        action: () -> Unit,
    ) {
        call.timeoutTask =
            // The scheduling call itself is guarded too - MINOR review-round finding (2026-09-02):
            // [scheduler] is shut down (`shutdownNow()`) BEFORE [stateExecutor] in [stop], so a
            // state-thread task still mid-execution when that runs can reach this call site with
            // [scheduler] already refusing new work - see [scheduleOnTimerIfRunning]'s own doc
            // comment.
            scheduleOnTimerIfRunning(
                "scheduling a call timeout for ${call.callId.fingerprint()}",
                duration,
            ) {
                // Guarded the same way as every other stateExecutor hand-off from a thread that
                // is not itself stateExecutor (here: the scheduler's own timeout thread) - MINOR
                // review-round finding (2026-09-02): an already-fired timeout task can reach this
                // callback after stop() has torn stateExecutor down, and an uncaught
                // RejectedExecutionException on the scheduler thread would otherwise kill it (and,
                // before this fix, was only ever swallowed by accident when the task itself never
                // fired that late).
                executeOnStateThreadIfRunning("running a scheduled call timeout for ${call.callId.fingerprint()}") {
                    action()
                }
            }
    }

    private fun cancelTimeout(call: ActiveCall) {
        call.timeoutTask?.cancel(false)
        call.timeoutTask = null
    }

    /** Attaches a freshly created [session] to [callId]'s [ActiveCall], OR - if the call already
     * ended while [session] was being created (e.g. a local `hangUp`/`rejectCall` racing
     * [CallMediaEngine.newSession]'s blocking call, before this function's own caller could post
     * this assignment) - closes it instead, on the media thread. Without this fallback, the
     * assignment below is silently a no-op for an already-removed [callId] (`calls[callId]` is
     * null): the session is never recorded on any [ActiveCall] for [endCallOnStateThread] to close,
     * NOR closed here, and is leaked for the remainder of this process's lifetime - for the real
     * `WebRtcCallMediaEngine`, a live `RTCPeerConnection` plus its audio source/track and bound UDP
     * port, made worse by [stop] later disposing the whole `PeerConnectionFactory` out from under
     * that still-open connection. Always called from [stateExecutor] (see every call site). */
    private fun attachMediaSessionOrCloseIfEnded(
        callId: CallId,
        session: CallMediaSession,
    ) {
        val call = calls[callId]
        if (call != null) {
            call.mediaSession = session
        } else {
            // Running on the STATE thread here (this function is, per its own doc comment above,
            // "Always called from stateExecutor") - correction (2026-09-02 review round,
            // code-inspection finding): an earlier version of this comment claimed the opposite
            // ("Already running ON the media thread"), directly contradicting that same doc comment
            // two lines away. The NORMAL path below still honors this class's own "media thread
            // closes CallMediaSession" contract (see the class doc comment's "Media thread" bullet):
            // it re-queues onto mediaExecutor rather than closing inline here. The ONLY deliberate
            // break of that contract is the catch block just below - closing inline, right here on
            // stateExecutor, but ONLY when mediaExecutor has already rejected the hand-off (i.e.
            // stop() has already shut it down). Safe specifically because this branch only runs for
            // a session whose call already ended BEFORE this attach ever reached it -
            // createOffer/acceptOfferAndCreateAnswer/applyAnswer for this session already returned
            // (or never started), so nothing on the media thread can still be concurrently touching
            // the same RTCPeerConnection.
            try {
                mediaExecutor.execute { closeAndUntrack(session) }
            } catch (e: RejectedExecutionException) {
                logger.debug(e) {
                    "mediaExecutor already shut down while closing an already-ended call's media " +
                        "session - closing inline instead"
                }
                closeAndUntrack(session)
            }
        }
    }

    /** Submits [action] to [stateExecutor], swallowing a [RejectedExecutionException] instead of
     * letting it escape onto the caller's thread and kill it. Needed because
     * [runOutgoingMediaSetup]/[runIncomingMediaSetup] run on [mediaExecutor] and post back to
     * [stateExecutor] at several points - but [stop] shuts [stateExecutor] down (`shutdownNow()`)
     * strictly BEFORE it drains [mediaExecutor] (see that function's own doc comment on why that
     * ordering is itself required for the OTHER leak it closes), so a media-setup task still
     * in-flight - or one still sitting in [mediaExecutor]'s queue behind an earlier slow
     * `transport.send` - when [stop] runs can reach any of these call sites with [stateExecutor]
     * already terminated. Returns whether the submission was accepted; [runOutgoingMediaSetup]/
     * [runIncomingMediaSetup]'s own attach call site uses that to close the session it just failed
     * to hand off (see their own call sites) - every other call site here just needs the exception
     * swallowed, since the session behind it was already closed by its own catch block (or never
     * created at all) before reaching this call. */
    private fun executeOnStateThreadIfRunning(
        description: String,
        action: () -> Unit,
    ): Boolean =
        try {
            stateExecutor.execute(action)
            true
        } catch (e: RejectedExecutionException) {
            logger.debug(e) {
                "stateExecutor already shut down while $description - ignoring, stop() is tearing " +
                    "this call down anyway"
            }
            false
        }

    /** Mirror of [executeOnStateThreadIfRunning] for the opposite hand-off direction: FROM
     * [stateExecutor] TO [mediaExecutor]. MINOR review-round finding (2026-09-02): [stop] shuts
     * [scheduler] down (`shutdownNow()`) and then [stateExecutor] (`shutdownNow()`) strictly BEFORE
     * it gracefully drains [mediaExecutor] (`mediaExecutor.shutdown()`, further below still) - so a
     * state-thread task that is already mid-execution when `stateExecutor.shutdownNow()` runs (e.g.
     * stuck behind the exact same "slow listener" scenario [stop]'s own `QUERY_TIMEOUT` fallback
     * documents) can reach any of [placeCallOnStateThread]/[acceptCallOnStateThread]/
     * [endCallOnStateThread]/[handleInboundAccept]/[sendSignalAsync]'s own `mediaExecutor.execute(...)`
     * call sites with [mediaExecutor] ALSO already shut down by then - an uncaught
     * [RejectedExecutionException] straight out of `lapis-net-call-state` that used to kill that
     * worker outright (empirically reproduced: `stop()` returning normally while the state thread
     * died underneath it with a "rejected from ... Terminated ..." `ThreadPoolExecutor` message on
     * STDERR). Returns whether the submission was accepted; every call site here closes/skips
     * whatever it was about to hand off when it was not, mirroring [executeOnStateThreadIfRunning]'s
     * own callers. */
    private fun executeOnMediaThreadIfRunning(
        description: String,
        action: () -> Unit,
    ): Boolean =
        try {
            mediaExecutor.execute(action)
            true
        } catch (e: RejectedExecutionException) {
            logger.debug(e) {
                "mediaExecutor already shut down while $description - ignoring, stop() is tearing " +
                    "this call down anyway"
            }
            false
        }

    /** Test-only hook exercising the EXACT same [stateExecutor] -> [mediaExecutor] guarded close
     * hand-off [endCallOnStateThread]/[handleInboundAccept] now use unconditionally, with no inline
     * close-on-rejection fallback (see each of their own doc comments for the MAJOR review-round
     * finding, 2026-09-02 round 6, that removed it): `executeOnMediaThreadIfRunning { closeAndUntrack
     * (session) }`. Lets a regression test pin the exact moment that hand-off is ATTEMPTED relative
     * to [stop]'s own `mediaExecutor.shutdown()` - real wall-clock timing alone cannot guarantee this
     * (see [scheduleGuardedTimeoutHandoffForTesting]'s own doc comment for the identical problem on
     * the scheduler side). [onStateThreadBeforeHandoff] runs ON THE STATE THREAD immediately before
     * the hand-off; [result] completes with whatever [executeOnMediaThreadIfRunning] itself returns -
     * `false` for a caught, logged rejection (in which case [session] is deliberately left
     * un-closed here, exactly like the real call sites, relying on [stop]'s own [liveMediaSessions]
     * safety-net sweep instead), `true` for an accepted submission. `internal`, never a production
     * entry point. */
    internal fun scheduleGuardedMediaCloseForTesting(
        session: CallMediaSession,
        result: CompletableFuture<Boolean>,
        onStateThreadBeforeHandoff: () -> Unit,
    ) {
        stateExecutor.execute {
            onStateThreadBeforeHandoff()
            result.complete(
                executeOnMediaThreadIfRunning("test-only guarded media close") { closeAndUntrack(session) },
            )
        }
    }

    /** Mirror of [executeOnMediaThreadIfRunning] for [scheduler] instead of [mediaExecutor] - the
     * sixth and last state-thread-to-other-executor hand-off the same finding covers, used only by
     * [scheduleTimeout]. Returns `null` (rather than a sentinel [ScheduledFuture]) on rejection, so
     * [scheduleTimeout] simply leaves [ActiveCall.timeoutTask] `null` - equivalent to the timeout
     * never firing, harmless here because a rejection only happens while [stop] is already tearing
     * this call down anyway. */
    private fun scheduleOnTimerIfRunning(
        description: String,
        delay: Duration,
        action: () -> Unit,
    ): ScheduledFuture<*>? =
        try {
            scheduler.schedule(action, delay.toMillis(), TimeUnit.MILLISECONDS)
        } catch (e: RejectedExecutionException) {
            logger.debug(e) {
                "scheduler already shut down while $description - ignoring, stop() is tearing this " +
                    "call down anyway"
            }
            null
        }

    /** Test-only hook exercising the EXACT same [scheduler] -> [stateExecutor] hand-off
     * [scheduleTimeout]'s own scheduled callback uses (`scheduleOnTimerIfRunning { ...
     * executeOnStateThreadIfRunning { action() } }`) - see [scheduleTimeout]'s own doc comment for
     * the MINOR review-round finding (2026-09-02) both of those private helpers guard against, and
     * the regression test using this hook for why real wall-clock timing cannot reliably reproduce
     * it: [stop] calls `scheduler.shutdownNow()` and `stateExecutor.shutdownNow()` back to back, so
     * the window in which a fired-but-not-yet-submitted timeout callback could observe [scheduler]
     * still accepting new work (irrelevant here) while [stateExecutor] has ALREADY terminated is, in
     * the general case, nanoseconds wide.
     *
     * [onSchedulerThreadBeforeHandoff] runs ON THE SCHEDULER THREAD, immediately before the
     * [stateExecutor] hand-off itself - a test blocks there (on a latch it releases only once it has
     * independently confirmed [stop] has already fully run) to pin the exact moment that hand-off is
     * attempted, something no amount of `Thread.sleep` tuning can guarantee. [result] is completed
     * with whatever [executeOnStateThreadIfRunning] itself returns - `false` for a caught, logged
     * rejection, `true` for an accepted submission - never with an exception, mirroring the guarantee
     * [executeOnStateThreadIfRunning] provides to every production call site. `internal`, never a
     * production entry point. */
    internal fun scheduleGuardedTimeoutHandoffForTesting(
        delay: Duration,
        result: CompletableFuture<Boolean>,
        onSchedulerThreadBeforeHandoff: () -> Unit,
    ) {
        scheduleOnTimerIfRunning("test-only guarded timeout handoff", delay) {
            onSchedulerThreadBeforeHandoff()
            result.complete(
                executeOnStateThreadIfRunning("test-only guarded timeout handoff callback") {},
            )
        }
    }

    /** Sends [signal] to [peer] on the media thread - NEVER inline from the state thread (which may
     * itself be running inside a call stack that started on a `DmSessionManager` Netty callback -
     * see this class's own doc comment). Failures are logged and otherwise swallowed: a failed
     * outbound `HANGUP`/`REJECT` notification does not change this node's OWN, already-decided local
     * state (the call is ending locally regardless of whether the peer ever learns why).
     *
     * [marksAcceptance] is forwarded verbatim to [CallSignalTransport.send] - see that parameter's
     * own doc comment (SECURITY, round-11/round-12 review findings, 2026-09-03). Being reachable
     * from a user-initiated public API alone does NOT make a call site pass `true`: the question is
     * whether THIS specific send reflects a local decision to communicate with [peer], not merely
     * whether a human pressed a button. [rejectCallOnStateThread]'s REJECT and a still-ringing,
     * never-accepted INCOMING call's HANGUP (from [hangUpOnStateThread]) both pass `false` - a
     * user declining or dismissing an unaccepted call is a decision NOT to communicate. Only
     * [hangUpOnStateThread] on an OUTGOING call (the user already decided to reach this peer by
     * dialing) or an already-answered call (CONNECTING/ACTIVE) passes `true`, alongside every other
     * automatically emitted signal this function sends staying `false` ([onRingTimeout],
     * [onConnectTimeout], [handleInboundInvite]'s BUSY/SDP-policy auto-rejects,
     * [onMediaFailedOnStateThread]). */
    private fun sendSignalAsync(
        peer: Secp256k1PublicKey,
        signal: CallSignal,
        marksAcceptance: Boolean,
    ) {
        // Guarded like every other state-thread-to-mediaExecutor hand-off - MINOR review-round
        // finding (2026-09-02, see executeOnMediaThreadIfRunning's own doc comment). A rejected
        // submission needs no fallback here: this signal not being sent changes nothing about this
        // node's own, already-decided local state (same "swallow the failure" discipline this
        // function's own class doc comment already describes for a transport.send that throws).
        executeOnMediaThreadIfRunning("sending ${signal.type} for call ${signal.callId.fingerprint()}") {
            try {
                transport.send(peer, CallSignalCodec.encode(signal), marksAcceptance)
            } catch (e: RuntimeException) {
                logger.debug(e) {
                    "failed to send ${signal.type} for call ${signal.callId.fingerprint()} to ${peer.fingerprint()}"
                }
            }
        }
    }

    private fun endCallOnStateThread(
        call: ActiveCall,
        reason: CallEndReason,
    ) {
        // remove() returning null means this call already ended (e.g. a media-failure callback
        // racing an already-processed HANGUP) - never double-emit CallEvent.Ended for one callId.
        if (calls.remove(call.callId) == null) return
        cancelTimeout(call)
        call.state = CallState.ENDED
        call.mediaSession?.let { session ->
            // Guarded like every other state-thread-to-mediaExecutor hand-off - MINOR review-round
            // finding (2026-09-02, see executeOnMediaThreadIfRunning's own doc comment).
            //
            // Deliberately NO inline close-on-rejection fallback here - MAJOR review-round finding
            // (2026-09-02, round 6), reverting one introduced by the PREVIOUS round: a rejected
            // submission does NOT mean "nothing else can be concurrently touching this session",
            // the reasoning the removed fallback relied on. [mediaExecutor] rejects new work once
            // [stop] calls its (graceful) `shutdown()` - see that function's own doc comment on why
            // that shutdown is deliberately graceful, NOT `shutdownNow()` - so a task already queued
            // ahead of that call (e.g. the safety-net sweep enqueued just below, or an
            // already-in-flight `createOffer`/`transport.send` for this very session) is still
            // running or about to run on the SAME thread this fallback would have closed [session]
            // from, right up until [MEDIA_SHUTDOWN_TIMEOUT] elapses. Closing inline here raced that
            // work directly on the same native `RTCPeerConnection` - empirically reproduced as a
            // double-free (`WebRtcCallMediaSession.close`'s own doc comment) that can crash the
            // whole JVM, not just leak a call. The submission being rejected only ever happens once
            // [stop] has ALREADY enqueued its own [liveMediaSessions] safety-net sweep (program order
            // within the same, singly-guarded [stop] invocation - see that field's own doc comment),
            // which is guaranteed to close [session] itself, on [mediaExecutor], strictly before
            // [stop]'s own `mediaEngine.close()` - so no fallback is needed, and adding one back
            // only reopens this exact race.
            executeOnMediaThreadIfRunning(
                "closing media session for ended call ${call.callId.fingerprint()}",
            ) { closeAndUntrack(session) }
        }
        val event = CallEvent.Ended(call.callId, call.peer, reason)
        callLog.record(event)
        emit(event)
    }

    private fun placeCallOnStateThread(
        callId: CallId,
        peer: Secp256k1PublicKey,
    ) {
        // MINOR review-round finding (2026-09-02): [MAX_TRACKED_CALLS]'s own doc comment already
        // describes it as "a defensive, generous-headroom ceiling on calls' total size... independent
        // of CallConfig.maxConcurrentCalls" - docs/roadmap.adoc makes the identical claim - but before
        // this fix it was only ever enforced in handleInboundInvite, never here. A CallConfig with a
        // generous maxConcurrentCalls (CallManagerAbuseTest itself already uses 100) let OUTGOING
        // placeCall grow `calls` past MAX_TRACKED_CALLS without limit, contradicting both doc
        // comments' own "independent of maxConcurrentCalls" claim. Checked FIRST, mirroring
        // handleInboundInvite's own ordering (MAX_TRACKED_CALLS before its BUSY/maxConcurrentCalls
        // check).
        if (calls.size >= MAX_TRACKED_CALLS) {
            logger.debug { "refusing outgoing call to ${peer.fingerprint()} - too many tracked calls" }
            val event = CallEvent.Ended(callId, peer, CallEndReason.BUSY)
            callLog.record(event)
            emit(event)
            return
        }
        if (calls.size >= config.maxConcurrentCalls) {
            // Recorded in callLog same as every other Ended emission below (endCallOnStateThread) -
            // this early-return path never reaches that shared helper (there is no ActiveCall to
            // remove; this call was never admitted into calls at all), so without this explicit
            // record() call it would be the one CallEvent.Ended this manager ever emits with no
            // corresponding call-history entry.
            val event = CallEvent.Ended(callId, peer, CallEndReason.BUSY)
            callLog.record(event)
            emit(event)
            return
        }
        val call = ActiveCall(callId, peer, CallDirection.OUTGOING)
        calls[callId] = call
        scheduleTimeout(call, config.ringTimeout) { onRingTimeout(callId) }
        emit(CallEvent.OutgoingRinging(callId, peer))
        // Guarded like every other state-thread-to-mediaExecutor hand-off - MINOR review-round
        // finding (2026-09-02, see executeOnMediaThreadIfRunning's own doc comment). No fallback
        // needed on rejection: no session was ever created for this call, so there is nothing to
        // close - the call itself is torn down by stop()'s own toClose loop regardless.
        executeOnMediaThreadIfRunning("starting outgoing media setup for ${callId.fingerprint()}") {
            runOutgoingMediaSetup(callId, peer)
        }
    }

    private fun acceptCallOnStateThread(callId: CallId) {
        val call = calls[callId] ?: return
        if (call.direction != CallDirection.INCOMING || call.state != CallState.INCOMING_RINGING) return
        val remoteSdp = call.remoteOfferSdp
        if (remoteSdp == null) {
            endCallOnStateThread(call, CallEndReason.LOCAL_ERROR)
            return
        }
        cancelTimeout(call)
        call.state = CallState.CONNECTING
        emit(CallEvent.Connecting(callId, call.peer))
        scheduleTimeout(call, config.connectTimeout) { onConnectTimeout(callId) }
        // Guarded like every other state-thread-to-mediaExecutor hand-off - MINOR review-round
        // finding (2026-09-02, see executeOnMediaThreadIfRunning's own doc comment). No fallback
        // needed on rejection, for the identical reason placeCallOnStateThread's own call site
        // needs none.
        executeOnMediaThreadIfRunning("starting incoming media setup for ${callId.fingerprint()}") {
            runIncomingMediaSetup(callId, call.peer, remoteSdp)
        }
    }

    private fun rejectCallOnStateThread(
        callId: CallId,
        reason: CallEndReason,
    ) {
        val call = calls[callId] ?: return
        if (call.direction != CallDirection.INCOMING) return
        val now = nowMillis()
        // marksAcceptance=false (review-round finding, 2026-09-03 - REJECT was wrongly `true`
        // before this fix): a REJECT is the user's decision to NOT communicate with this peer, the
        // exact opposite of the "local decision to communicate" DmAcceptedContacts promotion is
        // gated on (see sendSignalAsync's own doc comment, and DmSessionManager.sendCallSignal's).
        // Sending `true` here let anyone with an existing (even quarantined) ratchet session with
        // this node force their own promotion to accepted contact merely by inviting and having the
        // user press "reject" - permanently bypassing every configured DmAcceptancePolicy gate.
        sendSignalAsync(call.peer, CallSignal.reject(callId, reason, now, now + config.signalTtl.toMillis()), false)
        endCallOnStateThread(call, reason)
    }

    private fun hangUpOnStateThread(
        callId: CallId,
        reason: CallEndReason,
    ) {
        val call = calls[callId] ?: return
        val now = nowMillis()
        // marksAcceptance: reachable from the user-initiated hangUp() public API, but that alone
        // does NOT make it a "local decision to communicate" with call.peer (review-round finding,
        // 2026-09-03) - hangUp() is also the obvious UI action for dismissing a still-ringing
        // INCOMING call the user never accepted, which is a decision NOT to communicate, same as
        // reject(). Only `true` when this call was actually placed by us (OUTGOING - the user
        // already decided to reach this peer by dialing) or already answered (CONNECTING/ACTIVE -
        // the user already decided to accept it); `false` for hanging up a still-ringing INCOMING
        // call, which must behave like a REJECT for DmAcceptedContacts purposes.
        val marksAcceptance =
            call.direction == CallDirection.OUTGOING ||
                call.state == CallState.CONNECTING ||
                call.state == CallState.ACTIVE
        sendSignalAsync(
            call.peer,
            CallSignal.hangUp(callId, reason, now, now + config.signalTtl.toMillis()),
            marksAcceptance,
        )
        endCallOnStateThread(call, reason)
    }

    private fun onRingTimeout(callId: CallId) {
        val call = calls[callId] ?: return
        val now = nowMillis()
        val signal =
            if (call.direction == CallDirection.OUTGOING) {
                CallSignal.hangUp(callId, CallEndReason.RING_TIMEOUT, now, now + config.signalTtl.toMillis())
            } else {
                CallSignal.reject(callId, CallEndReason.RING_TIMEOUT, now, now + config.signalTtl.toMillis())
            }
        // marksAcceptance=false: an automatic timeout reaction, never a local user decision about
        // this peer (see sendSignalAsync's own doc comment).
        sendSignalAsync(call.peer, signal, false)
        endCallOnStateThread(call, CallEndReason.RING_TIMEOUT)
    }

    private fun onConnectTimeout(callId: CallId) {
        val call = calls[callId] ?: return
        val now = nowMillis()
        // marksAcceptance=false: an automatic timeout reaction, never a local user decision about
        // this peer (see sendSignalAsync's own doc comment).
        sendSignalAsync(
            call.peer,
            CallSignal.hangUp(callId, CallEndReason.CONNECT_TIMEOUT, now, now + config.signalTtl.toMillis()),
            false,
        )
        endCallOnStateThread(call, CallEndReason.CONNECT_TIMEOUT)
    }

    private fun handleInboundCallSignalOnStateThread(inbound: DmInboundCallSignal) {
        val signal =
            try {
                CallSignalCodec.decode(inbound.payload)
            } catch (e: MalformedCallSignalException) {
                logger.debug(e) { "dropping malformed call signal from ${inbound.sender.fingerprint()}" }
                return
            }
        val now = nowMillis()
        if (signal.createdAtEpochMillis > now + config.maxClockSkew.toMillis()) {
            logger.debug {
                "dropping call signal from ${inbound.sender.fingerprint()} - createdAt too far in the future"
            }
            return
        }
        if (signal.notValidAfterEpochMillis < now) {
            logger.debug { "dropping expired call signal from ${inbound.sender.fingerprint()}" }
            return
        }
        when (signal.type) {
            CallSignalType.INVITE -> handleInboundInvite(inbound.sender, inbound.quarantined, signal)
            CallSignalType.ACCEPT -> handleInboundAccept(inbound.sender, signal)
            CallSignalType.REJECT -> handleInboundReject(inbound.sender, signal)
            CallSignalType.HANGUP -> handleInboundHangup(inbound.sender, signal)
            CallSignalType.ICE_CANDIDATE, CallSignalType.RINGING, CallSignalType.RENEGOTIATE ->
                error("unreachable: CallSignalCodec.decode already rejects reserved CallSignalTypes")
        }
    }

    private fun handleInboundInvite(
        sender: Secp256k1PublicKey,
        quarantined: Boolean,
        signal: CallSignal,
    ) {
        if (calls.containsKey(signal.callId)) {
            // A duplicate INVITE for an already-known callId (e.g. a retransmit) rings only once -
            // never a second CallEvent.IncomingCall for the same call.
            return
        }
        if (!inviteRateLimiterFor(sender).tryAcquire()) {
            logger.debug { "dropping INVITE from ${sender.fingerprint()} - invite rate limit exceeded" }
            return
        }
        if (calls.size >= MAX_TRACKED_CALLS) {
            logger.debug { "dropping INVITE from ${sender.fingerprint()} - too many tracked calls" }
            return
        }
        if (quarantined && config.autoRejectQuarantined) {
            // Deliberate SILENT drop - no REJECT sent. See CallConfig.autoRejectQuarantined's own
            // doc comment: sending a REJECT would itself be an online-presence leak to a stranger
            // this node's DM acceptance policy has already decided not to trust. The caller simply
            // rings out to their own RING_TIMEOUT. Emitted as an event so a local listener can still
            // log/audit the attempt, WITHOUT it ever becoming an actionable, answerable call.
            //
            // Deduped via [quarantinedCallIds] - see that field's own doc comment (review-fix round,
            // 2026-09-03): this branch never admits signal.callId into [calls], so the retransmit
            // guard at the top of this function can never catch a repeat here the way it does for an
            // admitted call. Without this, a re-encrypted retransmit of the identical INVITE would
            // re-emit CallEvent.IncomingCall for the same callId, contradicting that event's own
            // "ONLY event ever emitted for this callId" doc-comment promise.
            val alreadyEmitted = quarantinedCallIds.put(signal.callId, true) != null
            if (alreadyEmitted) {
                logger.debug {
                    "silently re-dropping retransmitted INVITE from quarantined sender " +
                        "${sender.fingerprint()} - already emitted for this callId, no reply sent"
                }
                return
            }
            logger.debug { "silently dropping INVITE from quarantined sender ${sender.fingerprint()} - no reply sent" }
            emit(CallEvent.IncomingCall(signal.callId, sender, quarantined = true))
            return
        }
        // BUSY - checked AFTER the quarantine drop (a quarantined caller gets silence regardless of
        // capacity - see that branch's own doc comment) but BEFORE SDP validation (no point spending
        // CallSdpPolicy's own work on an INVITE this node is about to reject purely on capacity
        // grounds). calls.size counts every tracked call for THIS node's own accounting, ringing or
        // active alike - a config.maxConcurrentCalls slot is occupied the moment a call is admitted,
        // not only once it goes ACTIVE.
        if (calls.size >= config.maxConcurrentCalls) {
            val now = nowMillis()
            // marksAcceptance=false: an automatic capacity-driven auto-reject, never a local user
            // decision about sender (see sendSignalAsync's own doc comment).
            sendSignalAsync(
                sender,
                CallSignal.reject(
                    signal.callId,
                    CallEndReason.BUSY,
                    now,
                    now + config.signalTtl.toMillis(),
                ),
                false,
            )
            return
        }
        val sdp =
            signal.sdp ?: run {
                // Structurally unreachable - CallSignal's own init{} guarantees sdp != null for
                // INVITE - but handled explicitly rather than with a non-null assertion, consistent
                // with this codebase's "never let an internal-consistency assumption surface as an
                // NPE" discipline.
                logger.warn { "INVITE from ${sender.fingerprint()} had a null sdp despite CallSignal's own invariant" }
                return
            }
        try {
            CallSdpPolicy.validateRemote(sdp, signal.mediaKind)
        } catch (e: CallSdpRejectedException) {
            val now = nowMillis()
            // marksAcceptance=false: an automatic SDP-policy auto-reject, never a local user decision
            // about sender (see sendSignalAsync's own doc comment).
            sendSignalAsync(
                sender,
                CallSignal.reject(signal.callId, e.reason, now, now + config.signalTtl.toMillis()),
                false,
            )
            return
        }
        val call = ActiveCall(signal.callId, sender, CallDirection.INCOMING)
        call.remoteOfferSdp = sdp
        calls[signal.callId] = call
        scheduleTimeout(call, config.ringTimeout) { onRingTimeout(signal.callId) }
        // MAJOR review-round finding (2026-09-02): this used to hard-code `quarantined = false`
        // unconditionally. That was correct ONLY for the config.autoRejectQuarantined == true default
        // (the only way execution reaches here with quarantined == true is the silent-drop branch just
        // above, which returns before this line) - but with autoRejectQuarantined == false (a node
        // operator opting into "let me decide myself"), a genuinely quarantined sender's INVITE falls
        // straight through both branches above and was reported to the listener/UI as if it were an
        // ordinary, non-quarantined contact - exactly the information a caller needs to make an
        // informed accept/reject decision, silently discarded. Passing the real, already-computed
        // [quarantined] value through here costs nothing (BUSY is still checked first, same as before)
        // and makes a quarantined-but-admitted INVITE distinguishable from a trusted one for every
        // caller of [addCallListener], regardless of [CallConfig.autoRejectQuarantined].
        emit(CallEvent.IncomingCall(signal.callId, sender, quarantined = quarantined))
    }

    private fun handleInboundAccept(
        sender: Secp256k1PublicKey,
        signal: CallSignal,
    ) {
        val call = calls[signal.callId] ?: return
        if (call.peer != sender ||
            call.direction != CallDirection.OUTGOING ||
            call.state != CallState.OUTGOING_RINGING
        ) {
            return
        }
        val sdp = signal.sdp ?: return
        try {
            CallSdpPolicy.validateRemote(sdp, signal.mediaKind)
        } catch (e: CallSdpRejectedException) {
            endCallOnStateThread(call, e.reason)
            return
        }
        val session = call.mediaSession
        if (session == null) {
            endCallOnStateThread(call, CallEndReason.LOCAL_ERROR)
            return
        }
        cancelTimeout(call)
        call.state = CallState.CONNECTING
        emit(CallEvent.Connecting(call.callId, call.peer))
        scheduleTimeout(call, config.connectTimeout) { onConnectTimeout(call.callId) }
        // Guarded like every other state-thread-to-mediaExecutor hand-off - MINOR review-round
        // finding (2026-09-02, see executeOnMediaThreadIfRunning's own doc comment).
        //
        // Deliberately NO inline close-on-rejection fallback here either - MAJOR review-round
        // finding (2026-09-02, round 6), reverting one introduced by the PREVIOUS round for the
        // identical, mistaken reason [endCallOnStateThread]'s own identical correction explains (see
        // that function's own doc comment for the full mechanism and the empirically-reproduced
        // native double-free it caused). [session] is already tracked in [liveMediaSessions] (added
        // the instant [runOutgoingMediaSetup] created it), so [stop]'s own safety-net sweep closes it
        // regardless of whether this particular submission is accepted or rejected - no leak, and no
        // second, racing close of the same `RTCPeerConnection`.
        executeOnMediaThreadIfRunning("applying answer for call ${call.callId.fingerprint()}") {
            try {
                session.applyAnswer(sdp)
            } catch (e: CallMediaException) {
                closeAndUntrack(session)
                // MINOR review-round finding (2026-09-02): this hand-off was overlooked when every
                // other mediaExecutor-to-stateExecutor call site was moved onto
                // executeOnStateThreadIfRunning - a still-queued applyAnswer task that only starts
                // running during stop()'s graceful mediaExecutor drain (session already closed just
                // above, but stateExecutor itself already shut down by then) used to throw an uncaught
                // RejectedExecutionException straight out of the media thread.
                executeOnStateThreadIfRunning(
                    "ending call ${call.callId.fingerprint()} after an applyAnswer failure",
                ) {
                    endCallOnStateThread(call, CallEndReason.LOCAL_ERROR)
                }
            }
        }
    }

    private fun handleInboundReject(
        sender: Secp256k1PublicKey,
        signal: CallSignal,
    ) {
        val call = calls[signal.callId] ?: return
        if (call.peer != sender || call.direction != CallDirection.OUTGOING) return
        val reason = if (signal.reason == CallEndReason.NONE) CallEndReason.DECLINED else signal.reason
        endCallOnStateThread(call, reason)
    }

    private fun handleInboundHangup(
        sender: Secp256k1PublicKey,
        signal: CallSignal,
    ) {
        val call = calls[signal.callId] ?: return
        if (call.peer != sender) return
        endCallOnStateThread(call, CallEndReason.REMOTE_HANGUP)
    }

    private fun mediaObserverFor(
        callId: CallId,
        @Suppress("UNUSED_PARAMETER") peer: Secp256k1PublicKey,
    ): CallMediaObserver =
        object : CallMediaObserver {
            override fun onMediaConnected() {
                // MEDIUM review-round finding (2026-09-02): unlike every OTHER stateExecutor hand-off
                // in this class, these two are invoked directly from mediaEngine's OWN internal thread
                // (see CallMediaObserver's own class doc comment) - for the real WebRtcCallMediaEngine,
                // libwebrtc's native signaling thread, from inside a JNI callback. A bare
                // stateExecutor.execute(...) here threw an uncaught RejectedExecutionException straight
                // into that callback for any connection-state change arriving during stop()'s graceful
                // mediaExecutor drain (stateExecutor.shutdownNow() has already run by then, but a
                // still-open RTCPeerConnection can keep reporting state changes throughout that
                // window) - undefined behavior for the webrtc-java JNI bridge, not just a log line.
                executeOnStateThreadIfRunning("delivering onMediaConnected for call ${callId.fingerprint()}") {
                    onMediaConnectedOnStateThread(callId)
                }
            }

            override fun onMediaFailed(cause: String) {
                executeOnStateThreadIfRunning("delivering onMediaFailed for call ${callId.fingerprint()}") {
                    onMediaFailedOnStateThread(callId, cause)
                }
            }

            override fun onMediaClosed() {
                // No-op, deliberately: closing is already driven top-down by endCallOnStateThread's
                // own explicit session.close() call. A CLOSED callback firing as a CONSEQUENCE of
                // that close() would otherwise re-enter endCallOnStateThread for an
                // already-removed callId, which is already a harmless no-op (calls.remove returns
                // null) - stated here so that is legible as a deliberate decision, not a forgotten
                // case.
            }
        }

    private fun onMediaConnectedOnStateThread(callId: CallId) {
        val call = calls[callId] ?: return
        if (call.state == CallState.ACTIVE) return
        cancelTimeout(call)
        call.state = CallState.ACTIVE
        emit(CallEvent.Active(callId, call.peer))
    }

    private fun onMediaFailedOnStateThread(
        callId: CallId,
        cause: String,
    ) {
        val call = calls[callId] ?: return
        logger.debug { "media failed for call ${callId.fingerprint()}: $cause" }
        val now = nowMillis()
        // marksAcceptance=false: an automatic media-failure reaction, never a local user decision
        // about this peer (see sendSignalAsync's own doc comment).
        sendSignalAsync(
            call.peer,
            CallSignal.hangUp(
                callId,
                CallEndReason.LOCAL_ERROR,
                now,
                now + config.signalTtl.toMillis(),
            ),
            false,
        )
        endCallOnStateThread(call, CallEndReason.LOCAL_ERROR)
    }

    private fun runOutgoingMediaSetup(
        callId: CallId,
        peer: Secp256k1PublicKey,
    ) {
        // MINOR review-round finding (2026-09-02), part (b): closes the narrow window
        // executeOnMediaThreadIfRunning's own guard cannot - this task's OWN submission (from
        // placeCallOnStateThread) can land in mediaExecutor's queue AFTER [stop]'s liveMediaSessions
        // safety-net sweep was enqueued but BEFORE mediaExecutor.shutdown() runs (mediaExecutor still
        // accepting new work in that window, so no RejectedExecutionException to catch there). If
        // this task then ran anyway, mediaEngine.newSession() below would create a session that
        // reaches liveMediaSessions too late for the sweep to ever see it - closed by nothing before
        // stop()'s own mediaEngine.close() disposes the factory it depends on (the exact native
        // "Native object was not deleted" crash WebRtcCallMediaEngine.kt's close() documents).
        // Checking [stopped] here - evaluated when this task actually starts running, not when it
        // was submitted - closes that gap structurally: [stop] flips this flag as its very first
        // action, strictly before it could possibly have enqueued that sweep.
        if (stopped.get()) {
            logger.debug { "stop() already in progress - skipping outgoing media setup for ${callId.fingerprint()}" }
            return
        }
        val session =
            try {
                mediaEngine.newSession(mediaObserverFor(callId, peer))
            } catch (e: RuntimeException) {
                logger.debug(e) { "failed to create media session for outgoing call ${callId.fingerprint()}" }
                executeOnStateThreadIfRunning(
                    "ending outgoing call ${callId.fingerprint()} after a newSession failure",
                ) {
                    calls[callId]?.let { endCallOnStateThread(it, CallEndReason.LOCAL_ERROR) }
                }
                return
            }
        // Registered the instant newSession() returns - see [liveMediaSessions]' own doc comment for
        // the MAJOR review-round finding this closes: whatever happens below (the attach submission
        // rejected OR accepted-then-discarded, createOffer failing, the INVITE send failing), this
        // session is now guaranteed to be closed by [stop]'s own final registry sweep even in the one
        // path none of those individual close calls below can reach.
        liveMediaSessions.add(session)
        // Installed BEFORE the network send below - see this class's own doc comment for why the
        // single-threaded stateExecutor's FIFO ordering guarantees this is visible before any
        // ACCEPT (which cannot arrive until AFTER the INVITE this function sends below has actually
        // reached the peer) is ever processed. See attachMediaSessionOrCloseIfEnded's own doc
        // comment for why a bare `calls[callId]?.mediaSession = session` here would leak the session
        // whenever the call already ended while newSession() above was still blocking - and see
        // [executeOnStateThreadIfRunning]'s own doc comment for the second, [stop]-shutdown-ordering
        // race that requires closing [session] here (not just re-raising) when the submission itself
        // is rejected: [stop] can have shut [stateExecutor] down while THIS very task was still
        // sitting in mediaExecutor's queue, in which case attachMediaSessionOrCloseIfEnded never gets
        // to run AT ALL for this session, and it would otherwise be leaked exactly like the case that
        // function's own fallback branch already guards against.
        val attached =
            executeOnStateThreadIfRunning(
                "attaching media session for outgoing call ${callId.fingerprint()}",
            ) {
                attachMediaSessionOrCloseIfEnded(callId, session)
            }
        if (!attached) {
            closeAndUntrack(session)
            return
        }
        val sdp =
            try {
                session.createOffer(config.iceGatheringTimeout)
            } catch (e: CallMediaException) {
                logger.debug(e) { "failed to create offer for outgoing call ${callId.fingerprint()}" }
                closeAndUntrack(session)
                executeOnStateThreadIfRunning(
                    "ending outgoing call ${callId.fingerprint()} after a createOffer failure",
                ) {
                    calls[callId]?.let { endCallOnStateThread(it, CallEndReason.LOCAL_ERROR) }
                }
                return
            }
        val now = nowMillis()
        val signal = CallSignal.invite(callId, sdp, now, now + config.signalTtl.toMillis())
        try {
            // marksAcceptance=true: this INVITE only exists because the local user called placeCall()
            // - a real, deliberate decision to communicate with peer (see
            // CallSignalTransport.send's own doc comment, SECURITY round-11 review finding).
            transport.send(peer, CallSignalCodec.encode(signal), true)
        } catch (e: RuntimeException) {
            logger.debug(e) { "failed to send INVITE for outgoing call ${callId.fingerprint()}" }
            closeAndUntrack(session)
            executeOnStateThreadIfRunning(
                "ending outgoing call ${callId.fingerprint()} after a failed INVITE send",
            ) {
                calls[callId]?.let { endCallOnStateThread(it, CallEndReason.LOCAL_ERROR) }
            }
        }
    }

    private fun runIncomingMediaSetup(
        callId: CallId,
        peer: Secp256k1PublicKey,
        remoteOfferSdp: String,
    ) {
        // MINOR review-round finding (2026-09-02), part (b) - identical rationale and mechanism as
        // runOutgoingMediaSetup's own identical check, mirrored here for the incoming-call path.
        if (stopped.get()) {
            logger.debug { "stop() already in progress - skipping incoming media setup for ${callId.fingerprint()}" }
            return
        }
        val session =
            try {
                mediaEngine.newSession(mediaObserverFor(callId, peer))
            } catch (e: RuntimeException) {
                logger.debug(e) { "failed to create media session for incoming call ${callId.fingerprint()}" }
                executeOnStateThreadIfRunning(
                    "ending incoming call ${callId.fingerprint()} after a newSession failure",
                ) {
                    calls[callId]?.let { endCallOnStateThread(it, CallEndReason.LOCAL_ERROR) }
                }
                return
            }
        // Registered the instant newSession() returns - see [liveMediaSessions]' own doc comment and
        // runOutgoingMediaSetup's identical call site for the MAJOR review-round finding this closes.
        liveMediaSessions.add(session)
        // See attachMediaSessionOrCloseIfEnded's own doc comment - same leak risk as
        // runOutgoingMediaSetup's identical call site, mirrored here for the incoming-call path -
        // and see [executeOnStateThreadIfRunning]'s own doc comment for why a rejected submission
        // here must close [session] directly rather than just being logged and ignored.
        val attached =
            executeOnStateThreadIfRunning(
                "attaching media session for incoming call ${callId.fingerprint()}",
            ) {
                attachMediaSessionOrCloseIfEnded(callId, session)
            }
        if (!attached) {
            closeAndUntrack(session)
            return
        }
        val answerSdp =
            try {
                session.acceptOfferAndCreateAnswer(remoteOfferSdp, config.iceGatheringTimeout)
            } catch (e: CallMediaException) {
                logger.debug(e) { "failed to create answer for incoming call ${callId.fingerprint()}" }
                closeAndUntrack(session)
                executeOnStateThreadIfRunning(
                    "ending incoming call ${callId.fingerprint()} after an acceptOfferAndCreateAnswer failure",
                ) {
                    calls[callId]?.let { endCallOnStateThread(it, CallEndReason.LOCAL_ERROR) }
                }
                return
            }
        val now = nowMillis()
        val signal = CallSignal.accept(callId, answerSdp, now, now + config.signalTtl.toMillis())
        try {
            // marksAcceptance=true: this ACCEPT only exists because the local user called
            // acceptCall() - a real, deliberate decision to communicate with peer (see
            // CallSignalTransport.send's own doc comment, SECURITY round-11 review finding).
            transport.send(peer, CallSignalCodec.encode(signal), true)
        } catch (e: RuntimeException) {
            logger.debug(e) { "failed to send ACCEPT for incoming call ${callId.fingerprint()}" }
            closeAndUntrack(session)
            executeOnStateThreadIfRunning(
                "ending incoming call ${callId.fingerprint()} after a failed ACCEPT send",
            ) {
                calls[callId]?.let { endCallOnStateThread(it, CallEndReason.LOCAL_ERROR) }
            }
        }
    }

    companion object {
        private val QUERY_TIMEOUT: Duration = Duration.ofSeconds(5)

        /** Bound on [stop]'s graceful `mediaExecutor` drain before it falls back to `shutdownNow()`
         * - see that call site's own doc comment. `DmSessionManager.DIAL_TIMEOUT` (15s) plus
         * headroom for the queued session-close task that can be waiting right behind a slow send. */
        private val MEDIA_SHUTDOWN_TIMEOUT: Duration = Duration.ofSeconds(20)

        /** Hard cap on [inviteRateLimiters]' size, enforced by LRU eviction - see that field's own
         * doc comment for the full "why" (review-fix round, 2026-09-02). Same "generous headroom,
         * provisional magnitude, not derived from pilot data" framing as every sibling cap in this
         * codebase (e.g. [MAX_TRACKED_CALLS] just below). */
        internal const val MAX_INVITE_RATE_LIMITER_ENTRIES = 512

        /** Hard cap on [quarantinedCallIds]' size, enforced by LRU eviction - see that field's own
         * doc comment for the full "why" (review-fix round, 2026-09-03). Same "generous headroom,
         * provisional magnitude, not derived from pilot data" framing as every sibling cap in this
         * codebase (e.g. [MAX_INVITE_RATE_LIMITER_ENTRIES] just above). */
        internal const val MAX_QUARANTINED_CALL_IDS = 512

        /** Defensive, generous-headroom ceiling on [calls]' total size (every state combined,
         * `INCOMING_RINGING` included) - independent of [CallConfig.maxConcurrentCalls] (which is
         * measured against that very same `calls.size`, ringing or active alike - a slot is occupied
         * the moment a call is admitted, not only once it goes ACTIVE; see [handleInboundInvite]'s own
         * BUSY-check doc comment) and of [CallConfig.maxInvitesPerWindow]/
         * [CallConfig.inviteRateWindow] (which bound the RATE new entries can be added, not the
         * total ever alive at once if ring timeouts were somehow slower than the rate window). Same
         * "generous headroom, provisional magnitude, not derived from pilot data" framing as every
         * sibling cap in this codebase. `internal`, mirroring [MAX_INVITE_RATE_LIMITER_ENTRIES]'s own
         * identical visibility - lets a test pin this exact bound rather than hardcoding a copy of
         * the literal `64` that could silently drift out of sync. Enforced in BOTH
         * [handleInboundInvite] and [placeCallOnStateThread] - see the MINOR review-round finding
         * (2026-09-02) at the latter's own call site for why it used to be inbound-only, contradicting
         * this very doc comment's "independent of maxConcurrentCalls" claim. */
        internal const val MAX_TRACKED_CALLS = 64

        /** Production entry point: wires a [DmCallSignalTransport] over [dm] and registers
         * [CallManager.onInboundCallSignal] as [dm]'s call-signal listener. */
        fun attach(
            dm: DmSessionManager,
            mediaEngine: CallMediaEngine,
            config: CallConfig = CallConfig(),
            random: SecureRandom = SecureRandom(),
            clock: () -> Instant = Instant::now,
        ): CallManager {
            val manager = CallManager(DmCallSignalTransport(dm), mediaEngine, config, random, clock)
            dm.addCallSignalListener(manager::onInboundCallSignal)
            return manager
        }

        /** Test-only, low-level entry point: builds a [CallManager] against an arbitrary
         * [CallSignalTransport] with no [DmSessionManager] in the loop - lets
         * `CallManagerStateMachineTest`/`CallManagerAbuseTest` drive the full state machine with a
         * `FakeCallSignalTransport`/`FakeCallMediaEngine`, feeding inbound signals via the returned
         * manager's own [CallManager.onInboundCallSignal]. `internal` - never a production
         * construction path. */
        internal fun attachToTransport(
            transport: CallSignalTransport,
            mediaEngine: CallMediaEngine,
            config: CallConfig = CallConfig(),
            random: SecureRandom = SecureRandom(),
            clock: () -> Instant = Instant::now,
        ): CallManager = CallManager(transport, mediaEngine, config, random, clock)
    }
}
