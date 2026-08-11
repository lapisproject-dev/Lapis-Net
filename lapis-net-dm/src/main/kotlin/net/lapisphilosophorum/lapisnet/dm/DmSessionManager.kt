package net.lapisphilosophorum.lapisnet.dm

import io.github.oshai.kotlinlogging.KotlinLogging
import io.libp2p.core.PeerId
import net.lapisphilosophorum.lapisnet.directory.PeerDirectoryGossip
import net.lapisphilosophorum.lapisnet.directory.PrekeyBundleGossip
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.EncryptionKeyBinding
import net.lapisphilosophorum.lapisnet.identity.KeystoreDecryptionException
import net.lapisphilosophorum.lapisnet.identity.KeystoreEncryption
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.ratchet.CorruptedRatchetSessionException
import net.lapisphilosophorum.lapisnet.ratchet.DoubleRatchetException
import net.lapisphilosophorum.lapisnet.ratchet.DoubleRatchetSession
import net.lapisphilosophorum.lapisnet.ratchet.DoubleRatchetSessionCodec
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyConsumptionException
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyStore
import net.lapisphilosophorum.lapisnet.ratchet.RatchetMessageRejectedException
import net.lapisphilosophorum.lapisnet.ratchet.X3dh
import net.lapisphilosophorum.lapisnet.ratchet.X3dhException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions
import java.security.SecureRandom
import java.time.Duration
import java.time.Instant
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.ExecutionException
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write

private val logger = KotlinLogging.logger {}

/** Base type for every [DmSessionManager] failure. */
open class DmSessionException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/** Thrown by [DmSessionManager.send] when [PeerDirectoryGossip.lookup]/[PrekeyBundleGossip.lookup]
 * has no record for the recipient - a specific, catchable failure, never a crash or hang. Directory/
 * bundle propagation racing a genuinely reachable peer is the expected cause; [DmSessionManager]
 * itself owns no retry loop for this (see this class's own doc comment on why). */
class DmUnknownRecipientException(
    message: String,
) : DmSessionException(message)

/** Thrown when an X3DH handshake attempt fails - either [X3dh.initiate] (outbound, first contact)
 * or an inbound `X3DH_INITIAL` envelope's [X3dh.respond] rejects the claimed handshake. */
class DmHandshakeFailedException(
    message: String,
    cause: Throwable? = null,
) : DmSessionException(message, cause)

/** Simple fixed-window rate limiter bounding [DmSessionManager]'s one-time-prekey consumption RATE,
 * not merely its concurrency - see [DmSessionManager.prekeyConsumptionRateLimiter]'s own doc comment
 * for exactly why a concurrency bound alone (what [DmSessionManager.prekeyConsumptionSemaphore]
 * provides) is insufficient. Deliberately a plain fixed-window counter, not a smoother token bucket
 * or sliding log - this codebase's usual "generous headroom, provisional magnitude, not derived from
 * pilot data" numeric-cap convention (see [DmSessionManager.MAX_LIVE_SESSIONS]) applies here too: the
 * goal is to turn an unbounded drain into a bounded one, not to perfectly smooth request admission.
 * Thread-safe via a single `synchronized` block per [tryAcquire] call - this sits behind
 * [DmSessionManager.prekeyConsumptionSemaphore]'s own small concurrency bound, so contention here is
 * never a hot path. */
private class FixedWindowRateLimiter(
    private val maxPerWindow: Int,
    private val window: Duration,
    private val clockMillis: () -> Long = System::currentTimeMillis,
) {
    private var windowStartMillis = clockMillis()
    private var countInWindow = 0

    @Synchronized
    fun tryAcquire(): Boolean {
        val now = clockMillis()
        if (now - windowStartMillis >= window.toMillis()) {
            windowStartMillis = now
            countInWindow = 0
        }
        if (countInWindow >= maxPerWindow) return false
        countInWindow++
        return true
    }
}

/** One decrypted, delivered direct message - [sender] is trustworthy ONLY because it is handed out
 * here, after [DmSessionManager.handleInboundEnvelope]'s ratchet decryption already succeeded under
 * a session bootstrapped with this exact identity - see that function's own doc comment. [dedupKey]
 * is V0.8.5's forward-compatible hook (see [DmDedupKey]'s own doc comment) - NOT deduplicated
 * against anything in this wave. */
data class DmInboundMessage(
    val sender: Secp256k1PublicKey,
    val plaintext: ByteArray,
    val dedupKey: ByteArray,
    val receivedAtEpochSecond: Long,
)

/**
 * Drives the full handshake-then-ratchet lifecycle: resolves a recipient's current network address
 * ([PeerDirectoryGossip.lookup]) and prekey bundle ([PrekeyBundleGossip.lookup]), dials them via
 * [DmProtocol], and on first contact with a given recipient runs [X3dh.initiate] to bootstrap a
 * [DoubleRatchetSession], thereafter driving that session's `encrypt`/`decrypt` for every further
 * message to/from that recipient. Sessions are durably persisted (via
 * [DoubleRatchetSessionCodec.encodeWithKey]/`decodeWithKey`, see this class's own doc comment on
 * why NOT the slow, per-call-Argon2id `encode`/`decode`), so a process restart resumes an existing
 * conversation rather than re-handshaking.
 *
 * **CRITICAL IDENTITY-AUTHORITY RULE - the load-bearing property of this entire class, stated here
 * because this is the ONLY place in the codebase that both terms are simultaneously in scope.** A
 * libp2p [PeerId] a stream connection authenticates (via Noise, at the TRANSPORT layer) is NOT the
 * same thing as the secp256k1 identity the Double Ratchet/X3DH layer authenticates. [PeerId] is
 * NEVER used for message authorization or sender attribution anywhere in this class - only the
 * ratchet's own AEAD-authenticated decryption (bound to a specific X3DH-derived session between two
 * specific secp256k1 identities) is ever trusted for "who actually sent this." A connection from a
 * given [PeerId] claiming to relay messages "from" some `senderIdentity` in a [DmEnvelope] is NOT
 * trusted on that claim alone - see [handleInboundEnvelope]'s own doc comment for exactly where and
 * how that claim becomes trustworthy.
 *
 * **Explicit, deliberate scope cuts, stated here rather than silently omitted:**
 * - **No delivery receipts, no typing indicators** - not even as stubs (`DmMessageType.RECEIPT`
 *   exists on the wire but is rejected outright everywhere - see that enum's own doc comment).
 * - **No NAT traversal.** This repo has no working NAT traversal (a documented gap since
 *   V0.1.3/networking) - this wave supports only DIRECT-DIALABLE peers (same-LAN, or otherwise
 *   directly reachable). A peer behind NAT without port forwarding simply cannot be reached via
 *   [send] - [PeerDirectoryGossip.lookup]'s returned [net.lapisphilosophorum.lapisnet.directory.PeerRecord.addresses]
 *   will not be dialable, and [send] will surface a [DmSessionException] wrapping the underlying
 *   dial failure, not silently hang.
 * - **No offline/mailbox redelivery in this wave** - V0.8.5's job. [DmDedupKey] exists now
 *   specifically so that wave does not have to retrofit one.
 * - **No multi-device/session migration** (inherited limitation from [DoubleRatchetSession] itself).
 * - **No session registry beyond what V0.8.3 already documents as partial** - a second, legitimate
 *   `X3DH_INITIAL` from the same peer (e.g. because they lost local state) simply creates a new
 *   session, overwriting the persisted one - the same residual gap `X3dh`'s own doc comment already
 *   discloses, not something this wave closes further.
 * - **[prekeyConsumptionSemaphore]/[prekeyConsumptionRateLimiter] bound HOW MUCH and HOW FAST, they
 *   do not authenticate anyone** - see those fields' own doc comments. This wave does NOT attempt to
 *   distinguish a flooding attacker's self-signed throwaway identity from a legitimate first-contact
 *   initiator before the ratchet itself authenticates - see the CRITICAL IDENTITY-AUTHORITY RULE
 *   above for why no cheaper distinguishing signal exists at this layer. What this wave DOES do
 *   (security audit round 1 finding, 2026-08-11, added in response) is make the consequence of that
 *   gap bounded and self-healing rather than unbounded and permanent: [prekeyConsumptionRateLimiter]
 *   bounds the RATE a flood can burn one-time prekeys at (closing the gap a concurrency bound alone
 *   leaves open for a purely sequential attacker), and [replenishOneTimePrekeysIfLow] tops the pool
 *   back up and republishes once it runs low, so depletion - attacker-triggered or not - recovers on
 *   its own instead of requiring manual operator intervention.
 * - **No automatic retry on [DmUnknownRecipientException].** [send]'s directory/bundle lookups can
 *   race a peer whose record/bundle has not propagated yet; the caller owns retry policy, mirroring
 *   how [PeerDirectoryGossip.lookup]/[PrekeyBundleGossip.lookup] themselves make no delivery
 *   guarantee.
 * - **Deliberate simplification versus a full cross-process [PrekeyStore]-grade sidecar file lock:**
 *   session persistence here uses atomic temp-file-then-[Files.move] writes (durable against a
 *   crash mid-write) guarded by an IN-PROCESS per-peer monitor ([withPeerLock]), but no OS-level
 *   [java.nio.channels.FileChannel] lock the way [PrekeyStore] takes for its own file. A single
 *   [LapisNode] process is this codebase's only supported deployment shape per identity today (no
 *   two [DmSessionManager] instances ever legitimately point at the same [sessionStoreDirectory]
 *   from different processes) - stated explicitly as a scope reduction from the planning notes, not
 *   a silent omission.
 */
class DmSessionManager private constructor(
    private val localIdentity: DualKeyIdentity,
    private val localPrekeyStore: PrekeyStore,
    private val node: LapisNode,
    private val peerDirectory: PeerDirectoryGossip,
    private val prekeyBundleGossip: PrekeyBundleGossip,
    private val sessionStoreDirectory: Path,
    private val cachedKey: ByteArray,
    private val kdfParams: KeystoreEncryption.Params,
    private val random: SecureRandom,
) {
    private lateinit var dmProtocol: DmProtocol

    /** Guards [cachedKey] against the race between [stop]'s `cachedKey.fill(0)` and an IN-FLIGHT
     * [persistSession]/[loadPersisted] call reading it - follow-up hardening item 2 (2026-08-11).
     * Traced, not assumed: [withPeerLock]'s per-peer stripe lock (held by every [persistSession]/
     * [loadPersisted] call site, both only ever called from within [send]/[handleInboundEnvelope]'s
     * `withPeerLock` blocks) gives NO protection here, because [stop] never acquires a stripe lock at
     * all before zeroing [cachedKey] - it only takes `synchronized(liveSessionCache)` (a DIFFERENT
     * monitor) for the live-session-destroy loop, then calls `cachedKey.fill(0)` completely
     * unguarded. Without this lock, a concurrent [stop] could zero [cachedKey] WHILE
     * [DoubleRatchetSessionCodec.encodeWithKey]/`decodeWithKey` is mid-read of it on another thread -
     * not a data race in the memory-safety sense (`ByteArray.fill` and a sequential read are
     * `synchronized`-free but each individual byte write/read is still atomic on the JVM), but a
     * genuine CORRECTNESS race: the in-flight call could observe a PARTIALLY-zeroed key (some bytes
     * already overwritten, others not), silently persisting a session file encrypted under neither
     * the real key nor a all-zero key - undecryptable by ANY key, including a future correctly-
     * re-derived one, unlike the fully-zeroed case this class's own [stop] doc comment already
     * accepts and documents ("persisting or loading a session would silently use an all-zero key").
     *
     * A [ReentrantReadWriteLock] makes the two well-defined outcomes exact: [persistSession]/
     * [loadPersisted] (readers, [read]) may run concurrently with each other exactly as they always
     * could ([withPeerLock]'s stripe locks already serialize same-peer access; DIFFERENT peers'
     * encode/decode calls were never serialized against each other and still are not - this lock adds
     * no new contention on that path). [stop] (the sole writer, [write]) either waits for every
     * CURRENTLY in-flight reader to finish before zeroing (so that read observes the real key, start
     * to finish, never a half-zeroed one), or - if it wins the race - fully zeroes [cachedKey] BEFORE
     * a reader that arrives after can start, so that reader deterministically observes the documented
     * all-zero key, not a torn intermediate state. Never contends with [withPeerLock]'s stripe locks
     * or the `liveSessionCache` monitor (disjoint lock ordering: stripe lock, if any, is always
     * acquired OUTSIDE/BEFORE this lock, and [stop] never holds a stripe lock at all) - no deadlock
     * risk. */
    private val cachedKeyLock = ReentrantReadWriteLock()

    private val dialSemaphore = Semaphore(MAX_CONCURRENT_OUTBOUND_DIALS)

    /** Bounds concurrent [PrekeyStore.consumeOneTimePrekey] calls triggered by inbound `X3DH_INITIAL`
     * envelopes - closes a DoS gap found in this wave's own review round 3.
     * [EncryptionKeyBinding.verify], run immediately above this call site in [handleInboundEnvelope],
     * only proves a claimed `X3DH_INITIAL` header is INTERNALLY self-consistent (the encryption
     * binding really was signed by the claimed identity's own key) - it proves NOTHING about whether
     * that identity is legitimate, known, or has any relationship to this node. Minting a fresh
     * throwaway secp256k1 identity and self-signing a binding for it costs an attacker microseconds
     * of local CPU, no private key material ever shared with this node. [PrekeyStore.consumeOneTimePrekey]
     * itself (unmodified by this wave, in `lapis-net-ratchet`) unconditionally performs a full
     * Argon2id derivation (64 MiB / 3 passes) via `PrekeyStore.withExclusiveFileAccess` BEFORE the id
     * lookup that could reject the request even runs - and that method is guarded by a SINGLE
     * per-file JVM monitor shared by the whole store, so every concurrent call serializes. Without a
     * bound here, a flood of structurally-valid-but-garbage-signed `X3DH_INITIAL` envelopes would
     * queue without limit on that one lock, starving every legitimate incoming first-contact
     * handshake for as long as the flood continues - the same class of "Argon2id is not viable as an
     * unbounded live-network-path cost" problem this wave's own
     * [DoubleRatchetSessionCodec.encodeWithKey]/`decodeWithKey` refactor closes for session
     * persistence, left open here because [PrekeyStore] itself is out of this wave's scope.
     *
     * A small, fixed concurrency bound - the same "generous headroom, provisional magnitude" framing
     * as [MAX_CONCURRENT_OUTBOUND_DIALS] - converts that unbounded pileup into a bounded amount of
     * concurrent CPU/lock-contention work: at most [MAX_CONCURRENT_PREKEY_CONSUMPTIONS] Argon2id
     * derivations (roughly [MAX_CONCURRENT_PREKEY_CONSUMPTIONS] × 64 MiB peak) in flight at once,
     * regardless of how many envelopes arrive concurrently.
     *
     * **Permits are acquired with a ZERO-wait [Semaphore.tryAcquire] - this call NEVER blocks.**
     * [handleInboundEnvelope] runs directly on a Netty I/O thread (see [DmProtocolHandler]'s own doc
     * comment on [DmInboundMessageHandler.onMessage]'s call chain) - blocking that thread while
     * waiting for a permit would itself compound the exact stall this guards against, and would risk
     * starving unrelated streams sharing the same event loop. A rejected attempt here is logged and
     * handled exactly like any other rejected `X3DH_INITIAL` (`return@withPeerLock`) - no different
     * observable behavior to the caller, and no cryptographic material is touched. */
    private val prekeyConsumptionSemaphore = Semaphore(MAX_CONCURRENT_PREKEY_CONSUMPTIONS)

    /** Bounds the RATE, not merely the concurrency, of [PrekeyStore.consumeOneTimePrekey] calls -
     * closes a gap [prekeyConsumptionSemaphore] alone leaves wide open (security audit round 1
     * finding, 2026-08-11, PROVEN with an executable probe, not theoretical):
     * [prekeyConsumptionSemaphore] only ever throttles CONCURRENT attempts, so a purely SEQUENTIAL
     * attacker - one self-signed, structurally-valid `X3DH_INITIAL` at a time, each one passing
     * [EncryptionKeyBinding.verify] trivially (a fresh throwaway [DualKeyIdentity] costs an attacker
     * only a local secp256k1 keygen plus one ECDSA sign, no key material ever shared with this node)
     * - drained a five-entry test pool to zero in 2.9s without the semaphore ever mattering at all.
     *
     * **Deliberately a GLOBAL limiter, not keyed per claimed `senderIdentity`.** A per-identity
     * limiter is trivially bypassed by minting a fresh throwaway identity per attempt - exactly the
     * shape of the attack this closes, and exactly the same reasoning [peerLockStripes]'s own doc
     * comment already applies to a different attacker-mintable-key concern in this class.
     *
     * See [replenishOneTimePrekeysIfLow] for this fix's complementary self-healing half: even a
     * patient attacker who deliberately stays under this rate limit forever cannot achieve PERMANENT
     * depletion, because the pool is topped back up and republished as soon as it crosses a low
     * watermark - this field alone only slows the drain, it does not by itself guarantee recovery. */
    private val prekeyConsumptionRateLimiter =
        FixedWindowRateLimiter(MAX_PREKEY_CONSUMPTIONS_PER_WINDOW, PREKEY_CONSUMPTION_RATE_WINDOW)

    /** Guards against queueing more than one concurrent [replenishOneTimePrekeysIfLow] background
     * task - a burst of inbound `X3DH_INITIAL`s that each cross the low watermark around the same
     * moment should trigger ONE replenishment pass, not one per envelope racing to re-derive the
     * same top-up. `compareAndSet(false, true)` in [replenishOneTimePrekeysIfLow] makes "first
     * trigger wins, everyone else no-ops" exact even under concurrent Netty-thread callers. */
    private val replenishmentInFlight = AtomicBoolean(false)

    /** Lazily created so a [DmSessionManager] that never actually receives an `X3DH_INITIAL` never
     * spins up a background thread - mirrors [DmProtocolHandler]'s own identical lazy-scheduler
     * convention. Daemon thread so it never blocks JVM shutdown. Single-threaded: replenishment is
     * infrequent (gated by [replenishmentInFlight] to at most one at a time) and never
     * latency-sensitive, so no larger pool is warranted. */
    private val replenishmentExecutor: ExecutorService by lazy {
        Executors.newSingleThreadExecutor { runnable ->
            Thread(runnable, "lapis-net-dm-prekey-replenish").apply { isDaemon = true }
        }
    }

    /** Bounded, LRU-evicting cache of LIVE (decoded) sessions - the "bounded concurrent-session
     * count" this class must enforce. Every entry is ALREADY durably persisted before ever entering
     * or updating this cache (persist-before-cache, mirroring `DoubleRatchetSession`'s own
     * "persist-before-network-write"/"persist-before-deliver" ordering rules) - safe to
     * [DoubleRatchetSession.destroy] the evicted entry's in-memory copy, since the durable copy on
     * disk is unaffected. Access always wrapped in `synchronized(liveSessionCache)`, itself always
     * called from within a [withPeerLock] critical section (consistent lock ordering: per-peer lock
     * first, cache lock second, released immediately - no deadlock risk). */
    private val liveSessionCache =
        object : LinkedHashMap<Secp256k1PublicKey, DoubleRatchetSession>(16, 0.75f, true) {
            override fun removeEldestEntry(
                eldest: MutableMap.MutableEntry<Secp256k1PublicKey, DoubleRatchetSession>,
            ): Boolean {
                if (size <= MAX_LIVE_SESSIONS) return false
                eldest.value.destroy()
                return true
            }
        }

    /** Bounded lock striping - deliberately NOT an unbounded per-identity map. [handleInboundEnvelope]
     * calls [withPeerLock] for every distinct claimed `senderIdentity` on every inbound envelope,
     * BEFORE any cryptographic authentication of that claim (see that function's own doc comment) - a
     * structurally-valid [Secp256k1PublicKey] costs an attacker nothing to mint in bulk (no private
     * key needed, only curve-point validity - see that class's own constructor). An unbounded
     * per-identity monitor map keyed on the untrusted claim would let an unauthenticated remote peer
     * grow this node's memory without bound over its lifetime, unlike every other bounded structure in
     * this class ([liveSessionCache], [MAX_CONCURRENT_OUTBOUND_DIALS]). A fixed-size array of
     * [PEER_LOCK_STRIPE_COUNT] plain lock objects, indexed by a stable hash of the peer's public key
     * bytes, bounds this at a small CONSTANT regardless of how many distinct identities are ever seen -
     * the only cost is that two different peers landing on the same stripe serialize against each other
     * unnecessarily sometimes, never a correctness issue (a stripe lock is always a strict superset of
     * the per-peer mutual exclusion this class actually needs, so two DIFFERENT peers sharing a stripe
     * only ever costs extra contention, never lets two operations on the SAME peer run concurrently). */
    private val peerLockStripes: Array<Any> = Array(PEER_LOCK_STRIPE_COUNT) { Any() }

    /** [Secp256k1PublicKey.hashCode] is cached and content-derived (see that class's own doc comment),
     * never object identity - so the SAME peer identity always maps to the SAME stripe here. */
    private fun stripeFor(peer: Secp256k1PublicKey): Any =
        peerLockStripes[
            (peer.hashCode() and Int.MAX_VALUE) %
                PEER_LOCK_STRIPE_COUNT,
        ]

    private inline fun <T> withPeerLock(
        peer: Secp256k1PublicKey,
        block: () -> T,
    ): T = synchronized(stripeFor(peer)) { block() }

    private fun getCached(peer: Secp256k1PublicKey): DoubleRatchetSession? =
        synchronized(liveSessionCache) {
            liveSessionCache[peer]
        }

    /** Destroys any session PREVIOUSLY cached for [peer] before installing [session] in its place -
     * follow-up hardening item 1 (2026-08-11). [LinkedHashMap.removeEldestEntry] is only ever
     * consulted when a NEW key is inserted, never when an EXISTING key's value is overwritten
     * (verified against the JDK's own `LinkedHashMap`/`HashMap.putVal` source: the `afterNodeInsertion`
     * hook `removeEldestEntry` hangs off only runs on the "created a new node" branch) - so a plain
     * `liveSessionCache[peer] = session` overwrite previously left the SUPERSEDED session's
     * root/chain/ratchet-private key material un-zeroed on the heap until GC, unlike every other path
     * that removes an entry from this cache ([removeEldestEntry] itself, [stop]). This matters
     * concretely for [handleInboundEnvelope]'s `X3DH_INITIAL` branch: a second, legitimate
     * `X3DH_INITIAL` from a `claimedSender` that already had a live cached session (the residual gap
     * this class's own doc comment already discloses under "No session registry beyond...") bootstraps
     * a brand-new [DoubleRatchetSession] and calls this function to install it - the OLD session for
     * that same peer must be destroyed here, not merely dropped. Safe to call on a peer with no prior
     * entry (`get` returns `null`, [DoubleRatchetSession.destroy] is simply skipped) and safe even if
     * [session] and the previously-cached value happen to be THE SAME instance (the normal
     * re-persist-and-recache path after a successful decrypt/encrypt, see [send] and
     * [handleInboundEnvelope]'s `TEXT` branch) - [DoubleRatchetSession.destroy] on a session then
     * immediately continuing to use that same live instance would be a correctness bug, so this
     * function deliberately does NOT destroy when the previous and new values are reference-identical. */
    private fun putCached(
        peer: Secp256k1PublicKey,
        session: DoubleRatchetSession,
    ) {
        synchronized(liveSessionCache) {
            val previous = liveSessionCache.put(peer, session)
            if (previous != null && previous !== session) previous.destroy()
        }
    }

    private fun getCachedOrLoad(peer: Secp256k1PublicKey): DoubleRatchetSession? {
        getCached(peer)?.let { return it }
        val loaded = loadPersisted(peer) ?: return null
        putCached(peer, loaded)
        return loaded
    }

    /** Test-visibility accessor for the live (in-memory or freshly-loaded-from-disk) session held
     * for [peer], or `null` if none exists - `internal`, mirrors `DoubleRatchetSession`'s own
     * `...ForTest` accessor convention exactly, never a public API surface. Lets
     * `DmStreamAbuseTest`'s cross-session-confusion cases (e)/(g) drive a specific party's REAL live
     * session directly (e.g. to `encrypt()` an extra message outside the normal `send()` path)
     * without reaching into this class's private fields via reflection. */
    internal fun liveSessionForTest(peer: Secp256k1PublicKey): DoubleRatchetSession? = getCachedOrLoad(peer)

    private val inboundListeners = CopyOnWriteArrayList<(DmInboundMessage) -> Unit>()

    /** Registers a listener invoked for every successfully decrypted inbound message, from within
     * the same [withPeerLock] critical section that persisted it - see
     * [handleInboundEnvelope]'s doc comment. A listener that throws is caught and logged; it never
     * prevents delivery to other listeners or corrupts this manager's own state. */
    fun addInboundListener(listener: (DmInboundMessage) -> Unit) {
        inboundListeners.add(listener)
    }

    /**
     * Sends [plaintext] to [recipient]: resolves [recipient]'s [PeerDirectoryGossip] record FIRST
     * (before any session state is touched - see this function's body for why), then resolves or
     * bootstraps a session (X3DH first contact, or reuse of an existing/persisted session), persists
     * the post-encrypt session state BEFORE putting the ciphertext on the wire (mirroring
     * [DoubleRatchetSession]'s own "persist and destroy ordering" rule 3), then dials [recipient]'s
     * current address via [DmProtocol] and writes exactly one [DmEnvelope] frame.
     *
     * @throws DmUnknownRecipientException if [recipient] has no [PeerDirectoryGossip] record (checked
     *   first, before any session work) or no [PrekeyBundleGossip] bundle (first-contact only).
     * @throws DmHandshakeFailedException if X3DH initiation against [recipient]'s bundle fails.
     * @throws DmSessionException for a dial/send timeout or failure, or if the session cannot
     *   currently send (should not happen for a caller-visible session - see
     *   [DoubleRatchetSession.canSend]).
     */
    fun send(
        recipient: Secp256k1PublicKey,
        plaintext: ByteArray,
    ) {
        withPeerLock(recipient) {
            // Directory lookup happens FIRST, before any X3DH/encrypt/persist work below - see this
            // function's own doc comment and the CRITICAL review finding it fixes. PeerRecord and
            // PrekeyBundle have independent TTL/propagation lifecycles, so it is realistic for the
            // bundle lookup (further down) to succeed while this lookup fails; if that check ran
            // AFTER a brand-new session was already persisted+cached, this recipient would end up
            // with a durable phantom session here that the recipient never received the
            // X3DH_INITIAL envelope to bootstrap their own side of - every subsequent send() would
            // then silently reuse that phantom session forever. Failing here, before any session
            // state exists yet, makes the whole first-contact attempt a no-op on failure.
            val record =
                peerDirectory.lookup(recipient)
                    ?: throw DmUnknownRecipientException("no directory record for ${recipient.fingerprint()}")

            var session = getCachedOrLoad(recipient)
            val envelope: DmEnvelope
            if (session == null) {
                val bundle =
                    prekeyBundleGossip.lookup(recipient)
                        ?: throw DmUnknownRecipientException(
                            "no prekey bundle for recipient ${recipient.fingerprint()}",
                        )
                val ownBinding =
                    EncryptionKeyBinding.create(
                        localIdentity.secp256k1KeyPair,
                        localPrekeyStore.x25519IdentityPublicKey,
                    )
                val ownX25519Private = localPrekeyStore.x25519IdentityPrivateKey()
                val initiation =
                    try {
                        X3dh.initiate(
                            initiatorIdentity = localIdentity.secp256k1KeyPair.publicKey,
                            initiatorEncryptionBinding = ownBinding,
                            initiatorX25519IdentityPrivateKey = ownX25519Private,
                            bundle = bundle,
                            random = random,
                        )
                    } catch (e: X3dhException) {
                        throw DmHandshakeFailedException(
                            "X3DH initiation failed against ${recipient.fingerprint()}'s bundle",
                            e,
                        )
                    } finally {
                        ownX25519Private.destroy()
                    }
                val newSession = DoubleRatchetSession.initializeSender(initiation.session, bundle.signedPrekey, random)
                initiation.session.destroy()
                val ratchetMessage = newSession.encrypt(plaintext)
                envelope =
                    DmEnvelope(
                        DmMessageType.X3DH_INITIAL,
                        localIdentity.secp256k1KeyPair.publicKey,
                        initiation.header,
                        ratchetMessage,
                    )
                session = newSession
            } else {
                check(session.canSend) {
                    "session with ${recipient.fingerprint()} cannot currently send (receiver-only, awaiting first inbound reply)"
                }
                val ratchetMessage = session.encrypt(plaintext)
                envelope =
                    DmEnvelope(DmMessageType.TEXT, localIdentity.secp256k1KeyPair.publicKey, null, ratchetMessage)
            }

            // Persist BEFORE network write - see DoubleRatchetSession's own persist/destroy-ordering
            // rule 3, and this class's own doc comment. `record` was already resolved above, before
            // any of this session state was created.
            persistSession(recipient, session)
            putCached(recipient, session)

            val bytes = DmEnvelopeCodec.encode(envelope)

            if (!dialSemaphore.tryAcquire(DIAL_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS)) {
                throw DmSessionException(
                    "timed out waiting for an available outbound dial slot " +
                        "(MAX_CONCURRENT_OUTBOUND_DIALS=$MAX_CONCURRENT_OUTBOUND_DIALS)",
                )
            }
            try {
                val promise = dmProtocol.dial(node, record.peerId, *record.addresses.toTypedArray())
                val controller = await(promise.controller, "dial ${recipient.fingerprint()} for DM send")
                (controller as DmSendHandle).sendEnvelope(bytes)
            } finally {
                dialSemaphore.release()
            }
        }
    }

    /**
     * Called from [DmProtocolHandler]'s inbound-envelope callback. `fromPeerId` is the TRANSPORT-
     * authenticated [PeerId] - used here ONLY for logging/diagnostics, NEVER for authorization (see
     * this class's own CRITICAL IDENTITY-AUTHORITY RULE doc-comment section).
     *
     * `envelope.senderIdentity` is an UNTRUSTED CLAIM at the point it is read below - it selects
     * WHICH session to attempt, nothing more. It is NEVER cross-checked against `fromPeerId` either
     * (a completely separate identity space). The claim only becomes trustworthy the instant
     * `session.decrypt(...)` returns successfully: AEAD authentication under a session that was
     * itself bootstrapped via a real X3DH exchange, bound (via [X3dh]'s associated-data
     * construction) to this EXACT secp256k1 identity pair, is the ONLY thing ever treated as proof
     * of "who actually sent this." See [X3dh]'s own class doc comment for why AD is folded into the
     * KDF, not left to a downstream AEAD's AD slot alone - a message truly encrypted under a
     * DIFFERENT (sender, us) pair can never verify here even if the wrapping envelope LIES about who
     * sent it.
     *
     * **Never lets an exception escape** - this is called directly from a Netty callback
     * ([DmProtocolHandler]); every failure mode is caught and logged, never rethrown.
     */
    internal fun handleInboundEnvelope(
        fromPeerId: PeerId,
        envelopeBytes: ByteArray,
    ) {
        val envelope =
            try {
                DmEnvelopeCodec.decode(envelopeBytes)
            } catch (e: MalformedDmEnvelopeException) {
                logger.debug(e) { "rejected malformed DM envelope from $fromPeerId" }
                return
            } catch (e: RuntimeException) {
                logger.warn(e) { "unexpected exception decoding DM envelope from $fromPeerId - rejecting" }
                return
            }

        val claimedSender = envelope.senderIdentity
        try {
            withPeerLock(claimedSender) {
                val (session, isFreshHandshake) =
                    when (envelope.messageType) {
                        DmMessageType.X3DH_INITIAL -> {
                            val header =
                                envelope.x3dhInitialHeader
                                    ?: error(
                                        "DmEnvelope's own init already guarantees x3dhInitialHeader is non-null here",
                                    )
                            // Cheap, stateless authenticity check BEFORE ever touching
                            // localPrekeyStore.consumeOneTimePrekey below - see this function's own
                            // doc comment section on why. X3dh.respond performs this SAME check
                            // itself (its own check 2), but only AFTER a one-time prekey would
                            // already have been durably consumed if this guard were absent. Without
                            // it, an attacker holding NO private key material at all could mint
                            // structurally-valid-but-garbage-signed X3DH_INITIAL envelopes naming
                            // sequential one-time-prekey ids and durably burn through this node's
                            // entire one-time-prekey pool for zero cryptographic cost -
                            // EncryptionKeyBinding's own constructor performs only a 64-byte size
                            // check on the signature, never a cryptographic one. This is the
                            // SAME (initiatorIdentity, initiatorEncryptionBinding) pair X3dh.respond
                            // itself verifies further down - duplicated here deliberately, not
                            // routed through respond() first, because respond() also needs the
                            // ALREADY-consumed prekey as an argument (see PrekeyConsumptionException
                            // - the consume-before-respond ordering [X3dh]'s own class doc comment
                            // mandates for replay protection).
                            val headerBindingVerifies =
                                EncryptionKeyBinding.verify(header.initiatorIdentity, header.initiatorEncryptionBinding)
                            if (!headerBindingVerifies) {
                                logger.debug {
                                    "X3DH_INITIAL from claimed sender ${claimedSender.fingerprint()} carries an " +
                                        "encryption key binding that does not verify against the claimed identity " +
                                        "- rejecting BEFORE any one-time prekey consumption"
                                }
                                return@withPeerLock
                            }
                            // **Follow-up hardening item 3 (2026-08-11), judgment call: NO equivalent
                            // rate/concurrency bound is added for the case `header.oneTimePrekeyId ==
                            // null` (a "signed-prekey-only" X3DH_INITIAL, no one-time prekey named) -
                            // deliberately, not an oversight. Traced, not assumed:
                            // [prekeyConsumptionRateLimiter]/[prekeyConsumptionSemaphore] exist to
                            // bound ONE SPECIFIC expensive operation - [PrekeyStore.consumeOneTimePrekey]'s
                            // Argon2id derivation (64 MiB/3 passes) behind [PrekeyStore]'s single
                            // shared per-file lock (see [prekeyConsumptionSemaphore]'s own doc comment).
                            // When `oneTimePrekeyId` is null, this `?.let` block never runs AT ALL -
                            // `consumeOneTimePrekey` is never called, so that specific expensive,
                            // lock-contending operation these two mitigations exist to protect is
                            // categorically untouched by this path, not merely under-protected.
                            //
                            // What a no-OTPK X3DH_INITIAL costs INSTEAD (traced through
                            // [X3dh.respond] and [DoubleRatchetSession.initializeReceiver]): the SAME
                            // [EncryptionKeyBinding.create] self-sign this class always performs one
                            // line below regardless of this branch, 3 X25519 Diffie-Hellman agreements
                            // plus one HKDF derivation (`dh4`/the one-time-prekey DH term is simply
                            // never computed), and one AES-GCM ratchet-message decrypt attempt further
                            // down - ordinary constant-time symmetric/EC-curve arithmetic, microseconds
                            // each, NO Argon2id anywhere in that chain. This is the SAME order of
                            // magnitude of per-envelope work every OTHER inbound envelope already
                            // costs unconditionally (e.g. a `TEXT` envelope's own ratchet decrypt) -
                            // not a novel unbounded-resource-per-request the way Argon2id-guarded
                            // [PrekeyStore] access is, so reusing (or duplicating) either mitigation
                            // here would bound a resource that was never actually at risk.
                            //
                            // **Also the one wire shape a genuinely LEGITIMATE initiator produces**:
                            // [X3dh.initiate]'s own `oneTimePrekey` selection (see that function) is
                            // `null` exactly when the RESPONDER's own currently-published
                            // [net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundle] has an EMPTY
                            // `oneTimePrekeys` list - i.e. this exact node's own pool was already
                            // exhausted (transiently, between [replenishOneTimePrekeysIfLow] triggering
                            // and the republished bundle propagating). Applying the OTPK-consumption
                            // rate limit here too would throttle honest first-contact attempts reacting
                            // to THIS node's own degraded-but-still-working fallback, on top of a
                            // resource ([PrekeyStore]) that fallback doesn't even touch.
                            //
                            // Residual risk this leaves accepted, not eliminated: a flood of
                            // structurally-valid, genuinely self-signed (real ECDSA sign, one throwaway
                            // identity per attempt - the same "costs an attacker microseconds of local
                            // CPU" cost [prekeyConsumptionSemaphore]'s own doc comment already accepts
                            // as unavoidable at this layer) no-OTPK X3DH_INITIAL envelopes could still
                            // force many cheap-but-nonzero handshake attempts. That volume is bounded
                            // by the connection/stream-level defenses ABOVE this layer instead -
                            // [MAX_CONCURRENT_STREAMS_PER_PEER], [DmProtocolHandler]'s frame-size cap
                            // and slowloris/absolute-lifetime timeouts, and [MAX_LIVE_SESSIONS]'s
                            // LRU-eviction cap on how many resulting sessions can pile up in
                            // [liveSessionCache] - plus a global connection cap at the [LapisNode] level
                            // (see [net.lapisphilosophorum.lapisnet.networking.LapisNode.create]'s own
                            // `MAX_CONCURRENT_CONNECTIONS`, follow-up hardening item 5, same 2026-08-11
                            // wave), none of which are specific to the one-time-prekey resource these
                            // two fields guard.
                            val consumed =
                                header.oneTimePrekeyId?.let { id ->
                                    // See prekeyConsumptionRateLimiter's own doc comment for why a
                                    // RATE bound is needed in addition to prekeyConsumptionSemaphore's
                                    // concurrency bound. Checked FIRST - cheaper than the semaphore,
                                    // and rejects a sustained flood without even touching the
                                    // concurrency-bounded resource below.
                                    if (!prekeyConsumptionRateLimiter.tryAcquire()) {
                                        logger.debug {
                                            "rejecting X3DH_INITIAL from claimed sender " +
                                                "${claimedSender.fingerprint()} - " +
                                                "MAX_PREKEY_CONSUMPTIONS_PER_WINDOW " +
                                                "($MAX_PREKEY_CONSUMPTIONS_PER_WINDOW per " +
                                                "$PREKEY_CONSUMPTION_RATE_WINDOW) exceeded"
                                        }
                                        return@withPeerLock
                                    }
                                    // See prekeyConsumptionSemaphore's own doc comment for why this
                                    // gate exists and why it never blocks.
                                    if (!prekeyConsumptionSemaphore.tryAcquire()) {
                                        logger.debug {
                                            "rejecting X3DH_INITIAL from claimed sender " +
                                                "${claimedSender.fingerprint()} - " +
                                                "MAX_CONCURRENT_PREKEY_CONSUMPTIONS " +
                                                "($MAX_CONCURRENT_PREKEY_CONSUMPTIONS) already in flight"
                                        }
                                        return@withPeerLock
                                    }
                                    try {
                                        val result = localPrekeyStore.consumeOneTimePrekey(id)
                                        // Self-healing half of this fix - see that function's own
                                        // doc comment. Never blocks this Netty thread.
                                        replenishOneTimePrekeysIfLow()
                                        result
                                    } catch (e: PrekeyConsumptionException) {
                                        logger.debug(e) {
                                            "cannot consume one-time prekey $id for claimed X3DH_INITIAL from " +
                                                "${claimedSender.fingerprint()} - rejecting"
                                        }
                                        return@withPeerLock
                                    } finally {
                                        prekeyConsumptionSemaphore.release()
                                    }
                                }
                            val ownBinding =
                                EncryptionKeyBinding.create(
                                    localIdentity.secp256k1KeyPair,
                                    localPrekeyStore.x25519IdentityPublicKey,
                                )
                            val ownX25519Private = localPrekeyStore.x25519IdentityPrivateKey()
                            // ONE fetch, reused for BOTH X3dh.respond's own argument AND the Double
                            // Ratchet receiver's `ourRatchetKeyPair` below - no second, independent
                            // PrekeyStore.signedPrekeyPrivateKey() call. PrekeyStore.rotateSignedPrekey()
                            // swaps its whole state object atomically, but signedPrekeyId/
                            // signedPrekeyPublicKey/signedPrekeyPrivateKey() are plain reads of that
                            // @Volatile field, not a group-atomic snapshot; two independent fetches
                            // straddling a concurrent rotation could otherwise bootstrap a session whose
                            // ratchet keypair is inconsistent with the X3DH-derived shared secret,
                            // silently failing to decrypt the genuine first message with no diagnostic
                            // pointing at the real cause.
                            val signedPrekeyPrivate = localPrekeyStore.signedPrekeyPrivateKey()
                            val newSession =
                                try {
                                    val sharedSecret =
                                        try {
                                            X3dh.respond(
                                                responderIdentity = localIdentity.secp256k1KeyPair.publicKey,
                                                responderEncryptionBinding = ownBinding,
                                                responderX25519IdentityPrivateKey = ownX25519Private,
                                                responderSignedPrekeyId = localPrekeyStore.signedPrekeyId,
                                                responderSignedPrekeyPublicKey = localPrekeyStore.signedPrekeyPublicKey,
                                                responderSignedPrekeyPrivateKey = signedPrekeyPrivate,
                                                header = header,
                                                consumedOneTimePrekey = consumed,
                                            )
                                        } catch (e: X3dhException) {
                                            logger.debug(e) {
                                                "X3DH respond failed for claimed sender " +
                                                    "${claimedSender.fingerprint()} - rejecting, never falls back to trusting the claim"
                                            }
                                            return@withPeerLock
                                        } finally {
                                            ownX25519Private.destroy()
                                        }
                                    val ourRatchetKeyPair = X25519KeyPair.fromPrivateKeyBytes(signedPrekeyPrivate.bytes)
                                    val session =
                                        DoubleRatchetSession.initializeReceiver(
                                            sharedSecret,
                                            ourRatchetKeyPair,
                                            random,
                                        )
                                    sharedSecret.destroy()
                                    session
                                } finally {
                                    signedPrekeyPrivate.destroy()
                                }
                            newSession to true
                        }
                        DmMessageType.TEXT -> {
                            val existing = getCachedOrLoad(claimedSender)
                            if (existing == null) {
                                logger.debug {
                                    "no session for claimed sender ${claimedSender.fingerprint()} - rejecting TEXT envelope"
                                }
                                return@withPeerLock
                            }
                            existing to false
                        }
                        DmMessageType.RECEIPT, DmMessageType.CALL_SIGNAL -> {
                            logger.debug { "reserved messageType ${envelope.messageType} rejected outright" }
                            return@withPeerLock
                        }
                    }

                // THE ONLY MOMENT `claimedSender` BECOMES TRUSTWORTHY - see this function's own doc
                // comment.
                val plaintext =
                    try {
                        session.decrypt(envelope.ratchetMessage)
                    } catch (e: DoubleRatchetException) {
                        logger.debug(e) {
                            "ratchet decrypt failed under session claimed for ${claimedSender.fingerprint()} - " +
                                "rejecting; the claimed field alone is never trusted"
                        }
                        if (isFreshHandshake) session.destroy()
                        return@withPeerLock
                    } catch (e: RatchetMessageRejectedException) {
                        logger.debug(e) { "message rejected on public-data grounds: ${e.message}" }
                        if (isFreshHandshake) session.destroy()
                        return@withPeerLock
                    }

                persistSession(claimedSender, session)
                putCached(claimedSender, session)
                val dedupKey = DmDedupKey.of(claimedSender, envelope.ratchetMessage)
                val message = DmInboundMessage(claimedSender, plaintext, dedupKey, Instant.now().epochSecond)
                inboundListeners.forEach { listener ->
                    try {
                        listener(message)
                    } catch (e: RuntimeException) {
                        logger.warn(e) { "inbound DM listener threw - other listeners still notified" }
                    }
                }
            }
        } catch (e: RuntimeException) {
            // Final defense-in-depth catch: every known failure mode above already funnels itself
            // into a logged `return@withPeerLock`, so nothing should reach here today - but this
            // function is called directly from a Netty callback and must NEVER let an exception
            // escape (adversarial test case (f)).
            logger.warn(e) {
                "unexpected exception handling inbound DM envelope from $fromPeerId " +
                    "(claimed sender ${claimedSender.fingerprint()})"
            }
        }
    }

    /** Self-healing half of the prekey-pool-exhaustion fix (see [prekeyConsumptionRateLimiter]'s own
     * doc comment for the rate-limiting half). Called after every SUCCESSFUL
     * [PrekeyStore.consumeOneTimePrekey] in [handleInboundEnvelope] - legitimate or
     * attacker-triggered consumption looks identical at this layer, and this function does not try
     * to tell them apart, exactly like the rest of this mitigation. If
     * [PrekeyStore.availableOneTimePrekeyCount] has dropped to or below
     * [PREKEY_REPLENISH_LOW_WATERMARK], generates fresh one-time prekeys back up to
     * [PREKEY_REPLENISH_TARGET_COUNT] and republishes an updated
     * [net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundle] via [prekeyBundleGossip] - so a drained
     * pool recovers on its own rather than requiring manual operator intervention (a PERMANENT
     * DH1-DH3-only X3DH degradation, the only replay protection this codebase has for X3DH initial
     * messages, was this wave's original security-audit finding).
     *
     * **Dispatched onto [replenishmentExecutor], NEVER run inline on THIS call's own thread.**
     * [PrekeyStore.generateOneTimePrekeys] and [PrekeyStore.publishBundle] both take [PrekeyStore]'s
     * own Argon2id-guarded exclusive file lock (see that class's own doc comment on
     * `withExclusiveFileAccess`), and this function is called from [handleInboundEnvelope], which
     * runs on a Netty I/O thread - blocking THAT thread here would reintroduce exactly the kind of
     * unbounded-event-loop-latency problem [prekeyConsumptionSemaphore] already exists to avoid.
     * [replenishmentInFlight] collapses a burst of near-simultaneous triggers into ONE actual
     * replenishment pass (at most one outstanding at a time), so a flood that keeps crossing the
     * watermark cannot queue unboundedly many redundant top-ups either.
     *
     * **Residual, accepted, BOUNDED contention - not eliminated, deliberately not worth eliminating
     * given [PrekeyStore] is out of this wave's scope.** [PrekeyStore.withExclusiveFileAccess]'s file
     * monitor is shared by EVERY [PrekeyStore] handle open on the same file (by design - see that
     * method's own doc comment on why cross-instance sharing is load-bearing for correctness), so
     * while THIS background task's [PrekeyStore.generateOneTimePrekeys]/[PrekeyStore.publishBundle]
     * call holds that monitor, a CONCURRENT [PrekeyStore.consumeOneTimePrekey] call from a different
     * inbound envelope's Netty thread can observe brief added latency waiting for it - the exact same
     * class of bounded, serialized cost [prekeyConsumptionSemaphore]'s own doc comment already
     * accepts for up to [MAX_CONCURRENT_PREKEY_CONSUMPTIONS] concurrent consumption attempts today.
     * [replenishmentInFlight]'s one-at-a-time cap keeps this an occasional, single extra contender for
     * that monitor, not an unbounded one - a materially different shape from finding 1's original
     * "durably burn the pool with zero recovery" problem this whole fix exists to close.
     *
     * The cheap up-front count check runs directly on the calling (Netty) thread -
     * [PrekeyStore.availableOneTimePrekeyCount] is a fast in-memory read (no file I/O, no Argon2id),
     * consistent with every other zero-wait check this class performs inline (e.g.
     * [prekeyConsumptionSemaphore]'s own `tryAcquire`).
     *
     * Never throws - a failure here (e.g. a transient gossip-publish issue) is logged and simply
     * means the NEXT successful consumption gets another chance to trigger replenishment.
     */
    private fun replenishOneTimePrekeysIfLow() {
        if (localPrekeyStore.availableOneTimePrekeyCount() > PREKEY_REPLENISH_LOW_WATERMARK) return
        if (!replenishmentInFlight.compareAndSet(false, true)) return
        try {
            replenishmentExecutor.execute {
                try {
                    val currentCount = localPrekeyStore.availableOneTimePrekeyCount()
                    val deficit = PREKEY_REPLENISH_TARGET_COUNT - currentCount
                    if (deficit > 0) {
                        localPrekeyStore.generateOneTimePrekeys(deficit, random)
                        val notValidAfterEpochSecond =
                            Instant.now().epochSecond + PREKEY_REPLENISH_BUNDLE_TTL.toSeconds()
                        val bundle = localPrekeyStore.publishBundle(localIdentity, notValidAfterEpochSecond)
                        prekeyBundleGossip.announce(bundle)
                        logger.info {
                            "replenished one-time prekey pool for " +
                                "${localIdentity.secp256k1KeyPair.publicKey.fingerprint()} - generated $deficit " +
                                "fresh prekeys (was $currentCount, target $PREKEY_REPLENISH_TARGET_COUNT) and " +
                                "republished the prekey bundle"
                        }
                    }
                } catch (e: RuntimeException) {
                    logger.warn(e) {
                        "one-time prekey pool replenishment attempt failed - will retry on the next low-watermark trigger"
                    }
                } finally {
                    replenishmentInFlight.set(false)
                }
            }
        } catch (e: RuntimeException) {
            // execute() itself threw - e.g. RejectedExecutionException if stop() raced this call
            // and already shut down replenishmentExecutor - so the submitted Runnable above never
            // ran and its own finally never reset the flag. Reset it here instead, and NEVER let
            // this escape to the caller: handleInboundEnvelope's own doc comment requires every
            // path off the hot inbound-envelope path to never throw (adversarial test case (f)),
            // and this function sits directly in that path, right after a successful
            // consumeOneTimePrekey - the exact shape of a prior regression in this file where an
            // uncaught exception here would have silently dropped the otherwise-successful
            // handshake.
            replenishmentInFlight.set(false)
            logger.warn(e) {
                "failed to submit one-time prekey pool replenishment task - will retry on the next low-watermark trigger"
            }
        }
    }

    private fun sessionFilePath(peer: Secp256k1PublicKey): Path {
        val hex = peer.bytes.joinToString("") { "%02x".format(it) }
        return sessionStoreDirectory.resolve("$hex.lndm")
    }

    /** Atomic temp-file-then-[Files.move] write - durable against a crash mid-write. See this
     * class's own doc comment for why this stops short of [PrekeyStore]'s full cross-process
     * sidecar-lock discipline. The [cachedKey] read itself is wrapped in [cachedKeyLock]'s read lock -
     * see that field's own doc comment for exactly which race this closes. */
    private fun persistSession(
        peer: Secp256k1PublicKey,
        session: DoubleRatchetSession,
    ) {
        val bytes =
            cachedKeyLock.read {
                DoubleRatchetSessionCodec.encodeWithKey(session, cachedKey, kdfParams, random)
            }
        val target = sessionFilePath(peer)
        val tempFile =
            if (supportsPosixPermissions(sessionStoreDirectory)) {
                Files.createTempFile(
                    sessionStoreDirectory,
                    "${target.fileName}.",
                    ".tmp",
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")),
                )
            } else {
                Files.createTempFile(sessionStoreDirectory, "${target.fileName}.", ".tmp")
            }
        Files.write(tempFile, bytes)
        Files.move(tempFile, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
    }

    /** Returns `null` - "no persisted session, start fresh" - not just when no file exists, but also
     * when a file DOES exist but fails to decode: either [CorruptedRatchetSessionException]
     * (structural corruption - wrong size, bad header, an out-of-range/inconsistent field) or
     * [KeystoreDecryptionException] (AEAD authentication failure - a wrong key, or ANY tampered byte
     * anywhere in the header or ciphertext). Deliberately DIFFERENT from
     * [net.lapisphilosophorum.lapisnet.identity.FileIdentityRepository]'s own "corrupted keystore
     * file fails loudly, never silently recovers" discipline - that distinction is intentional, not
     * an oversight: an identity keystore is this node's ONE irreplaceable secret, so silently
     * treating a corrupt one as "absent" could mask real tampering or lose an unrecoverable key. A
     * persisted DM session, by contrast, is a disposable, ALWAYS-re-derivable cache - this class's own
     * doc comment already documents that a second, legitimate `X3DH_INITIAL` from a peer who lost
     * local state simply bootstraps a brand-new session, no special handling needed. Recovering from
     * a corrupt session file exactly the same way (treat as absent, let the next [send]/inbound
     * `X3DH_INITIAL` re-handshake) is consistent with that already-accepted design, not a new gap:
     * before this fix, [decodeWithKey][DoubleRatchetSessionCodec.decodeWithKey]'s exception simply
     * propagated up through [getCachedOrLoad] into [send]/[handleInboundEnvelope] uncaught -
     * [handleInboundEnvelope]'s own top-level `catch (e: RuntimeException)` happened to keep the node
     * alive, but every inbound message for that peer would then be silently dropped by that
     * catch-all forever (no re-handshake could ever succeed either, since the SAME corrupt file
     * would be hit again on every subsequent [getCachedOrLoad] call) - and [send] had no such
     * catch-all at all, so a corrupt session file would surface as an opaque crash to the caller
     * instead of the documented "unknown recipient"/"handshake failed" exception taxonomy. Also
     * covered by [cachedKeyLock]'s read lock - see that field's own doc comment. */
    private fun loadPersisted(peer: Secp256k1PublicKey): DoubleRatchetSession? {
        val target = sessionFilePath(peer)
        if (!Files.exists(target)) return null
        val bytes = Files.readAllBytes(target)
        return cachedKeyLock.read {
            try {
                DoubleRatchetSessionCodec.decodeWithKey(bytes, cachedKey, random)
            } catch (e: CorruptedRatchetSessionException) {
                logger.warn(e) {
                    "persisted DM session file for ${peer.fingerprint()} at $target is structurally " +
                        "corrupt - treating as no persisted session; a fresh X3DH handshake will " +
                        "bootstrap a new one on the next send/inbound X3DH_INITIAL"
                }
                null
            } catch (e: KeystoreDecryptionException) {
                logger.warn(e) {
                    "persisted DM session file for ${peer.fingerprint()} at $target failed to " +
                        "decrypt (wrong key or tampered ciphertext) - treating as no persisted " +
                        "session; a fresh X3DH handshake will bootstrap a new one on the next " +
                        "send/inbound X3DH_INITIAL"
                }
                null
            }
        }
    }

    private fun supportsPosixPermissions(path: Path): Boolean = "posix" in path.fileSystem.supportedFileAttributeViews()

    private fun <T> await(
        future: CompletableFuture<T>,
        action: String,
    ): T =
        try {
            future.get(DIAL_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS)
        } catch (e: TimeoutException) {
            throw DmSessionException("timed out waiting to $action", e)
        } catch (e: ExecutionException) {
            throw DmSessionException("failed to $action", e.cause ?: e)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            throw DmSessionException("interrupted while waiting to $action", e)
        }

    /** Releases every live session's in-memory secrets and stops [DmProtocol]'s background
     * scheduler - mirrors this codebase's other `stop()`-lifecycle conventions. Does not delete any
     * persisted session file. Also zeroes [cachedKey] - the raw AES-256 key that decrypts every
     * persisted session file for this identity - matching the same key-hygiene discipline
     * [X25519PrivateKey.destroy]/[net.lapisphilosophorum.lapisnet.ratchet.X3dhSharedSecret.destroy]/
     * [DoubleRatchetSession.destroy] already apply elsewhere in this codebase. Also shuts down
     * [replenishmentExecutor] - `shutdownNow()` on a lazily-created executor that was never actually
     * touched is harmless (mirrors [DmProtocolHandler.stop]'s identical "safe to call even if never
     * lazily created" convention), so this is unconditional, no `isInitialized` guard needed. Safe to
     * call more than once ([ByteArray.fill] on an already-zeroed array is a no-op); this manager is
     * not usable again afterward regardless (persisting or loading a session would silently use an
     * all-zero key), matching every other `stop()` in this codebase being a one-way shutdown, not a
     * pause/resume.
     *
     * **[cachedKey.fill(0)][cachedKey] runs under [cachedKeyLock]'s WRITE lock** - see that field's
     * own doc comment for the exact race this closes against a concurrent, in-flight
     * [persistSession]/[loadPersisted] call on another thread. */
    fun stop() {
        synchronized(liveSessionCache) {
            liveSessionCache.values.forEach { it.destroy() }
            liveSessionCache.clear()
        }
        if (::dmProtocol.isInitialized) dmProtocol.stop()
        replenishmentExecutor.shutdownNow()
        cachedKeyLock.write { cachedKey.fill(0) }
    }

    companion object {
        /** Generous headroom, provisional magnitude - not derived from pilot data, same framing as
         * every sibling numeric cap in this codebase (e.g. `PeerRecordIndex.MAX_TRACKED_RECORDS`). */
        const val MAX_LIVE_SESSIONS = 4_096

        /** Bounds simultaneous in-flight [send] dials - a caller sending to thousands of recipients
         * at once cannot exhaust this node's outbound connection/thread capacity unboundedly. */
        const val MAX_CONCURRENT_OUTBOUND_DIALS = 32

        /** Bounds simultaneous in-flight [PrekeyStore.consumeOneTimePrekey] calls - see
         * [prekeyConsumptionSemaphore]'s own doc comment for the DoS this closes. Deliberately small
         * (unlike [MAX_CONCURRENT_OUTBOUND_DIALS]'s generous 32): each permit corresponds to one
         * concurrent 64 MiB Argon2id derivation plus contention on [PrekeyStore]'s single per-file
         * lock, so a larger bound buys little real throughput (calls still serialize on that one
         * lock) while raising worst-case concurrent memory use for zero benefit. */
        const val MAX_CONCURRENT_PREKEY_CONSUMPTIONS = 4

        /** See [prekeyConsumptionRateLimiter]'s own doc comment for the DoS this closes. Deliberately
         * small - same "generous headroom, provisional magnitude" framing as every sibling numeric
         * cap in this class - chosen so a legitimate burst of first-contact handshakes (e.g. several
         * peers coming online around the same time) is never throttled, while a sustained flood is. */
        const val MAX_PREKEY_CONSUMPTIONS_PER_WINDOW = 10

        /** The window [MAX_PREKEY_CONSUMPTIONS_PER_WINDOW] is measured over. */
        val PREKEY_CONSUMPTION_RATE_WINDOW: Duration = Duration.ofSeconds(60)

        /** [replenishOneTimePrekeysIfLow] triggers once [PrekeyStore.availableOneTimePrekeyCount]
         * drops to or below this many - well above zero, so replenishment starts before the pool is
         * actually exhausted (an in-flight replenishment still takes one Argon2id-guarded
         * [PrekeyStore.generateOneTimePrekeys] round trip, during which further legitimate or
         * attacker-triggered consumption can still occur). */
        const val PREKEY_REPLENISH_LOW_WATERMARK = 20

        /** [replenishOneTimePrekeysIfLow] tops the pool back up to this many AVAILABLE one-time
         * prekeys - matches [PrekeyStore.DEFAULT_ONE_TIME_PREKEY_COUNT], the same count a freshly
         * [PrekeyStore.create]d store starts with, so a replenished pool looks like a freshly
         * provisioned one, not an arbitrary different magnitude. */
        const val PREKEY_REPLENISH_TARGET_COUNT = PrekeyStore.DEFAULT_ONE_TIME_PREKEY_COUNT

        /** TTL for the [net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundle]
         * [replenishOneTimePrekeysIfLow] republishes after topping up the pool - well under
         * `PrekeyBundle.MAX_TTL_WINDOW_SECONDS` (7 days), generous enough that an auto-triggered
         * republish does not need a periodic heartbeat to stay fresh across a typical node uptime,
         * while still being bounded rather than claiming the maximum possible validity window. */
        val PREKEY_REPLENISH_BUNDLE_TTL: Duration = Duration.ofDays(1)

        /** Fixed lock-striping width for [peerLockStripes] - see that field's own doc comment for why
         * this replaces an unbounded per-identity monitor map. Generous headroom for realistic
         * concurrent-peer contention, same "provisional magnitude, not derived from pilot data"
         * framing as [MAX_LIVE_SESSIONS]. */
        const val PEER_LOCK_STRIPE_COUNT = 2_048

        /** `LapisNode`'s own default dial timeout (10s) plus headroom for X3DH-first-contact latency
         * on top of the dial itself. */
        val DIAL_TIMEOUT: Duration = Duration.ofSeconds(15)

        /**
         * Bootstraps a [DmSessionManager]: loads or generates a persisted `.salt` file (0600 where
         * POSIX permissions are supported), derives [cachedKey] ONCE via
         * [KeystoreEncryption.deriveKey]`(passphrase, params)`, attaches [DmProtocol] to [node]'s
         * host wired to the new manager's [handleInboundEnvelope], and returns the manager.
         */
        fun attach(
            localIdentity: DualKeyIdentity,
            localPrekeyStore: PrekeyStore,
            node: LapisNode,
            peerDirectory: PeerDirectoryGossip,
            prekeyBundleGossip: PrekeyBundleGossip,
            sessionStoreDirectory: Path,
            passphrase: CharArray,
            random: SecureRandom = SecureRandom(),
        ): DmSessionManager {
            Files.createDirectories(sessionStoreDirectory)
            if ("posix" in sessionStoreDirectory.fileSystem.supportedFileAttributeViews()) {
                runCatching {
                    Files.setPosixFilePermissions(sessionStoreDirectory, PosixFilePermissions.fromString("rwx------"))
                }
            }
            val saltFile = sessionStoreDirectory.resolve(".salt")
            val salt =
                if (Files.exists(saltFile)) {
                    val existing = Files.readAllBytes(saltFile)
                    require(existing.size == KeystoreEncryption.SALT_SIZE) {
                        "existing .salt file at $saltFile has unexpected size ${existing.size}"
                    }
                    existing
                } else {
                    val fresh = ByteArray(KeystoreEncryption.SALT_SIZE).also(random::nextBytes)
                    if ("posix" in sessionStoreDirectory.fileSystem.supportedFileAttributeViews()) {
                        val attr = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))
                        Files.createFile(saltFile, attr)
                        Files.write(saltFile, fresh)
                    } else {
                        Files.write(saltFile, fresh)
                    }
                    fresh
                }
            val params =
                KeystoreEncryption.Params(
                    memoryKiB = KeystoreEncryption.DEFAULT_MEMORY_KIB,
                    iterations = KeystoreEncryption.DEFAULT_ITERATIONS,
                    parallelism = KeystoreEncryption.DEFAULT_PARALLELISM,
                    salt = salt,
                )
            // passphrase is zeroed the instant deriveKey no longer needs it - mirrors every other
            // passphrase-consuming call site in this codebase (FileIdentityRepository.load/save,
            // PrekeyStore's own passphraseProvider.get() usages) - a caller must not reuse this
            // CharArray after calling attach().
            val cachedKey =
                try {
                    KeystoreEncryption.deriveKey(passphrase, params)
                } finally {
                    passphrase.fill('\u0000')
                }
            val manager =
                DmSessionManager(
                    localIdentity,
                    localPrekeyStore,
                    node,
                    peerDirectory,
                    prekeyBundleGossip,
                    sessionStoreDirectory,
                    cachedKey,
                    params,
                    random,
                )
            manager.dmProtocol = DmProtocol.attach(node, manager::handleInboundEnvelope)
            return manager
        }
    }
}
