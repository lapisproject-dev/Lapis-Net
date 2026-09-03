package net.lapisphilosophorum.lapisnet.dm

import io.github.oshai.kotlinlogging.KotlinLogging
import io.ipfs.cid.Cid
import io.libp2p.core.PeerId
import net.lapisphilosophorum.lapisnet.core.ratelimit.FixedWindowRateLimiter
import net.lapisphilosophorum.lapisnet.directory.PeerDirectoryGossip
import net.lapisphilosophorum.lapisnet.directory.PeerRecord
import net.lapisphilosophorum.lapisnet.directory.PrekeyBundleGossip
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.EncryptionKeyBinding
import net.lapisphilosophorum.lapisnet.identity.KeystoreDecryptionException
import net.lapisphilosophorum.lapisnet.identity.KeystoreEncryption
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
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
import net.lapisphilosophorum.lapisnet.ratchet.X3dhPreKeyMessageHeader
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
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

/** V0.8.7 - thrown by [DmSessionManager.sendCallSignal] when no session with the recipient exists
 * yet. Deliberately a DIFFERENT, more specific exception than [DmUnknownRecipientException] (which
 * means "no directory/prekey-bundle record at all") - this one means "a record may well exist, but
 * there is no ratchet session to carry a call signal over, and [sendCallSignal] will never bootstrap
 * one." A call never begins a first contact: [DmSessionManager]'s own class doc comment states this
 * as a deliberate design choice, not an oversight - calling a stranger you have never exchanged a
 * text message (or at least an X3DH handshake) with is not a supported flow in this wave. */
class DmNoSessionException(
    message: String,
) : DmSessionException(message)

/** One decrypted, delivered direct message - [sender] is trustworthy ONLY because it is handed out
 * here, after [DmSessionManager.handleInboundEnvelope]'s ratchet decryption already succeeded under
 * a session bootstrapped with this exact identity - see that function's own doc comment. [dedupKey]
 * is V0.8.5's forward-compatible hook (see [DmDedupKey]'s own doc comment) - NOT deduplicated
 * against anything in this wave.
 *
 * **V0.8.6**: [plaintext] is the raw ratchet plaintext (== [DmContentCodec.encode]`(content)`,
 * unchanged, kept for callers that still want the raw bytes); [content] is that same plaintext,
 * already decoded - see [DmContentCodec]. [quarantined] is `true` iff [DmAcceptancePolicy
 * .classifyDelivered] rejected this sender against every configured gate AFTER decryption already
 * succeeded (see that object's class doc comment for why this is `Quarantine`, never `Reject`, at
 * this point in the pipeline) - always `false` when no [DmAcceptanceCheck] is configured. */
data class DmInboundMessage(
    val sender: Secp256k1PublicKey,
    val plaintext: ByteArray,
    val content: DmContent,
    val quarantined: Boolean,
    val dedupKey: ByteArray,
    val receivedAtEpochSecond: Long,
)

/** V0.8.7 - one decrypted, delivered call signal. [sender] carries the SAME identity-authority
 * guarantee [DmInboundMessage.sender] documents: trustworthy only because it is handed out here,
 * after the ratchet decryption in [DmSessionManager.processInboundDmEnvelope] already succeeded
 * under a session bootstrapped with this exact identity.
 *
 * **[payload] is OPAQUE to this module - deliberately.** It is the raw ratchet plaintext, which for a
 * `CALL_SIGNAL` envelope is a `net.lapisphilosophorum.lapisnet.call.CallSignalCodec`-encoded frame -
 * but `lapis-net-dm` never imports `lapis-net-call` (the dependency edge runs the other way: see
 * `lapis-net-call/build.gradle.kts`'s own header comment) and must never learn that codec's shape.
 * Decoding [payload] is entirely `lapis-net-call`'s `CallManager`'s job.
 *
 * [quarantined] mirrors [DmInboundMessage.quarantined]'s exact semantics - `true` iff
 * [DmAcceptancePolicy.classifyDelivered] rejected this sender against every configured gate AFTER
 * decryption already succeeded, always `false` when no [DmAcceptanceCheck] is configured. Unlike
 * [DmInboundMessage], there is no `dedupKey` field here - a call signal is never redelivered via the
 * offline mailbox (see [DmSessionManager.handleOfflineEnvelope]'s own doc comment), so the cross-path
 * dedup key this module computes for every inbound envelope is consumed internally
 * ([DmSessionManager] still calls [markRecentlyDelivered] on it) but never needs to be handed to a
 * caller who has no second delivery path to reconcile it against. */
data class DmInboundCallSignal(
    val sender: Secp256k1PublicKey,
    val payload: ByteArray,
    val quarantined: Boolean,
    val receivedAtEpochSecond: Long,
)

/** [DmSessionManager.sendAuto]'s result - which transport actually carried the message. */
enum class DmSendOutcome {
    SENT_ONLINE,
    QUEUED_FOR_PICKUP,
}

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
 * - **V0.8.5: offline/mailbox redelivery is implemented** - [sendOffline] deposits an encrypted
 *   message as a Nabu blob plus a signed [MailboxPointer] gossiped on the recipient's own mailbox
 *   topic ([MailboxGossip]), periodically re-announced ([MailboxRedeliveryScheduler]) so a
 *   recipient who returns online later can still discover it; [MailboxPoller] fetches the
 *   referenced blob via a direct Bitswap request to the sender's currently-gossiped address, never
 *   via `NabuStorage.findProviders` (broken since V0.1.4), and routes a successful fetch through
 *   the SAME [processInboundDmEnvelope] core the online path uses. [DmDedupKey] - computed by this
 *   wave specifically so V0.8.5 would not have to retrofit one - is what [processInboundDmEnvelope]
 *   uses for the cross-path dedup pre-check; see that function's own doc comment.
 * - **No multi-device/session migration** (inherited limitation from [DoubleRatchetSession] itself).
 * - **Session registry: a second, DIFFERENT-ephemeral-key `X3DH_INITIAL` from the same peer (e.g.
 *   because they lost local state) still simply creates a new session, overwriting the persisted one
 *   - the same residual gap `X3dh`'s own doc comment already discloses, not something this wave
 *   closes.** What IS closed (security audit round 1 finding, 2026-08-27, PROVEN with an executable
 *   probe: stop this manager, rebuild a second instance over the SAME identity/session directory,
 *   replay the identical `X3DH_INITIAL` bytes - delivered a SECOND time before this fix): a LITERAL
 *   replay of an ALREADY-ACCEPTED `X3DH_INITIAL` - same ephemeral key, same everything - surviving a
 *   process restart. [recentlyDeliveredDedupKeys] alone cannot catch this (in-memory-only, empty
 *   after a restart), and when `header.oneTimePrekeyId == null` (a bundle-exhaustion degradation,
 *   see [processInboundDmEnvelope]'s own doc comment on that branch) [PrekeyStore]'s durable
 *   consumption tracking never even runs, so nothing else stood in the way either. Closed by a
 *   DURABLE, per-peer registry of already-accepted `X3DH_INITIAL` ephemeral public keys, persisted
 *   alongside the session file (see [recordAcceptedX3dhInitialEphemeralKey]'s own doc comment) and
 *   checked BEFORE ever bootstrapping a session - [X3dh.initiate] mints a FRESH ephemeral key on
 *   every call, so this closes only literal-byte replay, never a genuinely new (if still redundant)
 *   second handshake attempt.
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
    private val nabuStorage: NabuStorage,
    private val pubsub: GossipPubSub,
    private val sessionStoreDirectory: Path,
    private val cachedKey: ByteArray,
    private val kdfParams: KeystoreEncryption.Params,
    private val random: SecureRandom,
    private val mailboxRedeliveryScheduler: MailboxRedeliveryScheduler,
    initialAcceptance: DmAcceptanceCheck?,
    /** V0.8.6 - see [DmAcceptedContacts]'s own doc comment. `null` (the default everywhere no
     * caller opts in) means outbound sends never mark a recipient accepted - identical to every
     * prior wave's behavior. When non-null, [prepareEnvelopeLocked] calls [DmAcceptedContacts.accept]
     * on every outbound send (online, offline, or via [sendAuto]) - this is the "OR because this
     * node itself sent that peer a message" half of [DmAcceptedContacts]'s own class doc comment,
     * made reachable. A caller that wants BOTH halves (the send-side auto-accept AND an explicit
     * future UI accept button) passes the SAME [DmAcceptedContacts] instance here and into the
     * [DmAcceptanceCheck.isAcceptedContact] lambda of whatever [DmAcceptanceCheck] it configures via
     * [initialAcceptance]/[updateAcceptanceCheck]. */
    private val acceptedContacts: DmAcceptedContacts?,
) {
    private lateinit var dmProtocol: DmProtocol

    /** V0.8.5 - lateinit for the exact same reason as [dmProtocol]: [MailboxPoller.attach] needs a
     * bound method reference to this manager (`this::handleOfflineEnvelope`) that does not fully
     * exist until after this primary constructor has already run. Assigned once, immediately after
     * construction, in [attach]. */
    private lateinit var mailboxPoller: MailboxPoller

    /** V0.8.6 - the post-AEAD acceptance policy [classifyQuarantined] consults, `null` meaning "no
     * check configured, deliver everything unquarantined" (V0.8.5's behavior, unchanged). `@Volatile`,
     * not guarded by any [withPeerLock] stripe: [updateAcceptanceCheck] is the sole writer, called
     * from a caller's own thread (e.g. a future UI handler reacting to newly-learned trust, not yet
     * built this wave) entirely outside any per-peer critical section, and [classifyQuarantined]
     * only ever needs a single consistent read of the CURRENT reference, never a multi-field
     * snapshot. */
    @Volatile
    private var acceptance: DmAcceptanceCheck? = initialAcceptance

    /** Replaces the acceptance-policy check this manager consults post-AEAD - a fresh [TrustGraph]
     * means a fresh, empty [net.lapisphilosophorum.lapisnet.policy.VeritasPathCache], since a
     * [TrustGraph] is an immutable snapshot that is never mutated in place (see that class's own doc
     * comment): reflecting newly-learned trust means constructing a brand NEW [DmAcceptanceCheck],
     * never mutating an existing one's graph. Pass `null` to disable acceptance checking entirely
     * (every message delivered unquarantined). */
    fun updateAcceptanceCheck(check: DmAcceptanceCheck?) {
        acceptance = check
    }

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

    /** V0.8.7 - see [addCallSignalListener]/[DmInboundCallSignal]'s own doc comments. A completely
     * separate list from [inboundListeners]: a `CALL_SIGNAL` envelope is NEVER also handed to
     * [inboundListeners] - see [processInboundDmEnvelope]'s own doc comment on why calling never
     * touches [DmContentCodec]/`DmStore`/the browser DM history. */
    private val callSignalListeners = CopyOnWriteArrayList<(DmInboundCallSignal) -> Unit>()

    /** V0.8.5 cross-path dedup key wrapper - mirrors `PeerRecordContentId`/`MailContentId`/
     * `MailboxPointerContentId` exactly (value equality over the key bytes). */
    private data class DedupKeyId(
        private val bytes: ByteArray,
    ) {
        override fun equals(other: Any?): Boolean = other is DedupKeyId && bytes.contentEquals(other.bytes)

        override fun hashCode(): Int = bytes.contentHashCode()
    }

    /** Bounded, LRU-evicting, GLOBAL (not per-peer) cross-path dedup cache - an efficiency/
     * belt-and-braces pre-check, NOT the load-bearing correctness guarantee for "no double
     * delivery" between the online ([handleInboundEnvelope]) and offline ([handleOfflineEnvelope])
     * paths, for the `TEXT` case. That guarantee is structural for `TEXT`:
     * [DoubleRatchetSession.decrypt]'s own commit-only-after-AEAD-verifies state machine already
     * rejects a literal replay of the same ratchet message
     * (`RatchetMessageRejectedException("message number ... already been consumed")`) regardless of
     * which path re-delivers it, since both paths share the SAME [liveSessionCache]/persisted-
     * session-file for a given peer - see [processInboundDmEnvelope]'s own doc comment.
     *
     * **Corrected 2026-08-27, security audit round 1 finding: this "regardless of which path"
     * framing does NOT extend to `X3DH_INITIAL`, and this class's own doc comment previously
     * overclaimed that it did.** `X3DH_INITIAL` resolves NO existing session at all - it always
     * builds a brand-new [DoubleRatchetSession] first, so [liveSessionCache]/the persisted session
     * file cannot reject a replay of it the way they reject a `TEXT` replay; this in-memory,
     * restart-losable cache was, until this fix, the ONLY thing standing between a replayed
     * `X3DH_INITIAL` (when `header.oneTimePrekeyId == null`, so [PrekeyStore]'s own durable
     * consumption tracking never runs either) and a resurrected message plus a rewound persisted
     * session, PROVEN exploitable by a restart (which empties this cache) - see
     * [recordAcceptedX3dhInitialEphemeralKey]'s own doc comment for the DURABLE fix that now closes
     * that specific gap independently of this cache's own (still in-memory-only) state.
     *
     * This registry exists so a KNOWN-duplicate delivery (e.g. a re-gossiped/replayed mailbox
     * pointer already fetched-and-acked once, within the SAME process lifetime) is skipped WITHOUT
     * even attempting a wasted AEAD decrypt or, for a replayed `X3DH_INITIAL`, a wasted
     * one-time-prekey-consumption attempt. Lost on restart - an accepted, documented limitation for
     * the `TEXT` case (an optimization layer over a guarantee that holds regardless of its own
     * state), but NOT accepted for `X3DH_INITIAL`, which is why that case now has its own,
     * independent, durable registry rather than relying on this one. */
    private val recentlyDeliveredDedupKeys =
        object : LinkedHashMap<DedupKeyId, Boolean>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<DedupKeyId, Boolean>): Boolean =
                size > MAX_RECENT_DEDUP_KEYS
        }

    private fun isRecentlyDelivered(key: ByteArray): Boolean =
        synchronized(recentlyDeliveredDedupKeys) { recentlyDeliveredDedupKeys.containsKey(DedupKeyId(key)) }

    private fun markRecentlyDelivered(key: ByteArray) {
        synchronized(recentlyDeliveredDedupKeys) { recentlyDeliveredDedupKeys[DedupKeyId(key)] = true }
    }

    /** Registers a listener invoked for every successfully decrypted inbound message, from within
     * the same [withPeerLock] critical section that persisted it - see
     * [handleInboundEnvelope]'s doc comment. A listener that throws is caught and logged; it never
     * prevents delivery to other listeners or corrupts this manager's own state. */
    fun addInboundListener(listener: (DmInboundMessage) -> Unit) {
        inboundListeners.add(listener)
    }

    /** V0.8.7 - registers a listener invoked for every successfully decrypted inbound
     * [DmInboundCallSignal], from within the same [withPeerLock] critical section that persisted the
     * underlying session - mirrors [addInboundListener]'s exact contract. A listener that throws is
     * caught and logged; it never prevents delivery to other listeners or corrupts this manager's
     * own state. The intended (today, sole expected) caller is
     * `net.lapisphilosophorum.lapisnet.call.DmCallSignalTransport`. */
    fun addCallSignalListener(listener: (DmInboundCallSignal) -> Unit) {
        callSignalListeners.add(listener)
    }

    /**
     * V0.8.5 extraction: the first-contact X3DH bootstrap block [send] and [sendOffline] both need,
     * factored out so the two call sites produce byte-identical crypto behavior for "first contact"
     * mechanically (via one shared implementation), not merely by convention. Resolves
     * [recipient]'s [PrekeyBundleGossip] bundle, runs [X3dh.initiate] against it, and initializes a
     * fresh sender-side [DoubleRatchetSession] - exactly [send]'s own former inline first-contact
     * block, unchanged in substance.
     *
     * @throws DmUnknownRecipientException if [prekeyBundleGossip] has no bundle for [recipient].
     * @throws DmHandshakeFailedException if X3DH initiation against that bundle fails.
     */
    private fun bootstrapSenderSession(
        recipient: Secp256k1PublicKey,
    ): Pair<DoubleRatchetSession, X3dhPreKeyMessageHeader> {
        val bundle =
            prekeyBundleGossip.lookup(recipient)
                ?: throw DmUnknownRecipientException("no prekey bundle for recipient ${recipient.fingerprint()}")
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
        return newSession to initiation.header
    }

    /**
     * Sends [content] to [recipient]: resolves [recipient]'s [PeerDirectoryGossip] record FIRST
     * (before any session state is touched - see this function's body for why), then resolves or
     * bootstraps a session (X3DH first contact, or reuse of an existing/persisted session), persists
     * the post-encrypt session state BEFORE putting the ciphertext on the wire (mirroring
     * [DoubleRatchetSession]'s own "persist and destroy ordering" rule 3), then dials [recipient]'s
     * current address via [DmProtocol] and writes exactly one [DmEnvelope] frame.
     *
     * **V0.8.6: takes a [DmContent], not a raw [ByteArray]** - the former `plaintext: ByteArray`
     * overload has been REMOVED, not kept as a convenience wrapper (a `ByteArray` -> `DmContent`
     * bridge would need to invent a body/attachment split on the caller's behalf, silently
     * misinterpreting arbitrary binary as UTF-8 text). [DmContentCodec.encode] is called ONCE,
     * outside [withPeerLock], before any session work - a pure, side-effect-free encode never needs
     * the per-peer lock.
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
        content: DmContent,
    ) {
        val plaintext = DmContentCodec.encode(content)
        withPeerLock(recipient) {
            // Directory lookup happens FIRST, before any X3DH/encrypt/persist work below - see this
            // function's own doc comment and the CRITICAL review finding it fixes. PeerRecord and
            // PrekeyBundle have independent TTL/propagation lifecycles, so it is realistic for the
            // bundle lookup (inside prepareEnvelopeLocked) to succeed while this lookup fails; if
            // that check ran AFTER a brand-new session was already persisted+cached, this recipient
            // would end up with a durable phantom session here that the recipient never received the
            // X3DH_INITIAL envelope to bootstrap their own side of - every subsequent send() would
            // then silently reuse that phantom session forever. Failing here, before any session
            // state exists yet, makes the whole first-contact attempt a no-op on failure.
            val record =
                peerDirectory.lookup(recipient)
                    ?: throw DmUnknownRecipientException("no directory record for ${recipient.fingerprint()}")

            val envelope = prepareEnvelopeLocked(recipient, plaintext)
            dispatchOnlineLocked(recipient, record, DmEnvelopeCodec.encode(envelope))
        }
    }

    /**
     * V0.8.5: deposits [content] for [recipient] via the offline Nabu mailbox (V0.8.6: takes a
     * [DmContent], same removed-`ByteArray`-overload reasoning as [send]'s own doc comment):
     * encrypts exactly as [send] does (same [X3dh.initiate]-on-first-contact / [DoubleRatchetSession.encrypt] reuse,
     * via the SAME [bootstrapSenderSession] helper [send] uses - so first contact bootstraps a
     * byte-identical session either way), durably stores the resulting [DmEnvelope] bytes in Nabu
     * ([NabuStorage.put]) BEFORE announcing a [MailboxPointer] referencing that blob's CID -
     * "persist then publish, publish strictly last": a fast-arriving pointer can never reference a
     * not-yet-fetchable blob. **The pointer itself is NOT ALSO put into Nabu** (a prior revision did;
     * removed as a V0.8.5 hardening-pass finding - see the `nabuStorage.put`/`mailboxRedeliveryScheduler.track`
     * call site below for the full reasoning): the pointer's own durability for redelivery comes
     * entirely from [mailboxRedeliveryScheduler]'s bounded in-memory copy, and nothing ever reads a
     * `MailboxPointer` back from Nabu by its own content id.
     *
     * Unlike [send], this method never dials [recipient] and therefore never needs
     * [PeerDirectoryGossip.lookup] for the RECIPIENT - it only needs [PrekeyBundleGossip.lookup] for
     * first contact, exactly mirroring [send]'s own inner X3DH branch (via [bootstrapSenderSession]).
     *
     * The announced pointer is re-published periodically (via [mailboxRedeliveryScheduler]) until
     * [notValidAfterEpochSecond] passes - see [MailboxRedeliveryScheduler]'s own class doc comment
     * for why this is load-bearing, not an optimization: GossipSub never replays a message to a
     * subscriber that joins after the original publish, so a recipient offline during THIS call can
     * only ever learn the pointer exists via a LATER live re-publish. **This means the sender must
     * remain reachable, or at least come back online periodically, for offline delivery to complete
     * at all** - not only to serve the eventual Bitswap fetch, but, more fundamentally, for the
     * recipient to ever discover the pointer in the first place. A real, inherent limitation of
     * routing around the broken DHT (`NabuStorage.findProviders`, broken since V0.1.4) with gossip
     * alone - not a bug.
     *
     * **Explicit, deliberate scope cuts for V0.8.5 (stated here rather than silently omitted,
     * mirroring this class's own established practice above):**
     * - **No onion routing for mailbox pointers.** The original DM concept note's own open question
     *   - left open here, not attempted.
     * - **No DHT mailbox record** - same broken-Kademlia limitation as everything else in this
     *   class; gossip + explicit peer-hint-based Bitswap fetch instead.
     * - **No pin-lifetime management.** Nabu has no pin/GC anywhere in this project (V0.1.4's own
     *   documented state) - "pinning" a mailbox blob is currently a no-op, stated plainly rather than
     *   implying a pinning economy exists.
     * - **No re-delivery guarantee beyond the TTL window.** Once a pointer expires or is evicted
     *   from [MailboxPointerIndex], that message is genuinely gone if the recipient never came
     *   online in time - an accepted, bounded-storage tradeoff, not a bug.
     * - **A smaller, un-closed sibling of the "phantom session" hazard [send] guards against - V0.8.5
     *   hardening pass finding, 2026-08-27, acknowledged here rather than silently carried.** [send]'s
     *   own doc comment explains WHY it resolves [peerDirectory] BEFORE touching any session state:
     *   persisting a brand-new session and only THEN discovering the recipient is undialable would
     *   leave a durable session this node thinks is live but the recipient never bootstrapped their
     *   side of (no `X3DH_INITIAL` ever reached them), silently poisoning every later [send]/
     *   [sendOffline] to that recipient. `sendOffline` has no directory lookup to sequence against (it
     *   never dials [recipient] - see this doc comment's own paragraph above), so that SPECIFIC
     *   ordering fix does not apply here. What DOES remain: `persistSession`/`putCached` still commit
     *   BEFORE `nabuStorage.put(envelopeBytes)`/`mailboxRedeliveryScheduler.track`/`pubsub.publish`
     *   below - a THIS-node-local, no-network-round-trip window (unlike [send]'s dial, which crosses
     *   the network and can time out or fail for reasons entirely outside this node's control) between
     *   "session persisted" and "blob durably stored". A crash or process kill in that narrow window
     *   (a `nabuStorage.put` I/O failure propagating as an uncaught exception, or the process dying
     *   between the two calls) leaves a session this node believes is live with no corresponding blob
     *   ever deposited - the SAME class of inconsistency [send]'s fix targets, just with a
     *   dramatically smaller and non-adversarial failure window (local disk I/O vs. a full network
     *   round trip an unreachable/malicious-seeming peer can trivially trigger). Not fixed in this
     *   pass - re-ordering `persistSession` after `nabuStorage.put` would itself violate
     *   [DoubleRatchetSession]'s own "persist and destroy ordering" rule 3 (persist ratchet state
     *   before any externally observable effect of having advanced it), the same rule [send] and this
     *   method both already follow; closing this residual properly would need a different mechanism
     *   (e.g. a session-state rollback on a failed deposit) judged out of scope for a hardening pass
     *   over already-shipped, already-audited code. Stated here so the asymmetry with [send] is
     *   documented, not silently inherited.
     *
     * @throws DmUnknownRecipientException (first contact only) if no [PrekeyBundleGossip] bundle
     *   exists for [recipient].
     * @throws DmHandshakeFailedException as [send].
     */
    fun sendOffline(
        recipient: Secp256k1PublicKey,
        content: DmContent,
        notValidAfterEpochSecond: Long = Instant.now().epochSecond + MailboxPointer.DEFAULT_TTL_SECONDS,
    ) {
        val plaintext = DmContentCodec.encode(content)
        withPeerLock(recipient) {
            val envelope = prepareEnvelopeLocked(recipient, plaintext)
            depositOfflineLocked(recipient, DmEnvelopeCodec.encode(envelope), notValidAfterEpochSecond)
        }
    }

    /**
     * V0.8.6: builds and sends [content] to [recipient], choosing online delivery when a
     * [PeerDirectoryGossip] record exists and the dial succeeds, falling back to the offline Nabu
     * mailbox ([sendOffline]'s own mechanism) otherwise - the "one send button" a future UI's send
     * action is intended to call (not yet built this wave), so a caller never has to choose a
     * transport itself.
     *
     * **This is the security-critical reason [sendAuto] cannot be `try { send(...) } catch (...)
     * { sendOffline(...) }` composed from the OUTSIDE.** [send] persists the session BEFORE it ever
     * touches the network ([prepareEnvelopeLocked]'s ordering) - so a caller-level retry after a
     * failed [send] would find `getCachedOrLoad(recipient) != null` and emit `TEXT`, not
     * `X3DH_INITIAL`, for what the recipient's mailbox would receive as their FIRST message from
     * this sender - a `TEXT` envelope the recipient can never bootstrap a session to decrypt (see
     * [sendOffline]'s own doc comment, which already documents this exact trap for a caller retry).
     * [sendAuto] avoids it entirely by building the envelope via [prepareEnvelopeLocked] EXACTLY
     * ONCE per call, then reusing those SAME encoded bytes for whichever delivery path is actually
     * taken - there is no second encrypt, so there is no second, wrong-typed envelope to leak.
     */
    fun sendAuto(
        recipient: Secp256k1PublicKey,
        content: DmContent,
    ): DmSendOutcome {
        val plaintext = DmContentCodec.encode(content)
        return withPeerLock(recipient) {
            val envelope = prepareEnvelopeLocked(recipient, plaintext)
            val envelopeBytes = DmEnvelopeCodec.encode(envelope)

            val record = peerDirectory.lookup(recipient)
            if (record != null) {
                try {
                    dispatchOnlineLocked(recipient, record, envelopeBytes)
                    return@withPeerLock DmSendOutcome.SENT_ONLINE
                } catch (e: DmSessionException) {
                    logger.debug(e) {
                        "sendAuto: online dial/send to ${recipient.fingerprint()} failed - falling back to an " +
                            "offline mailbox deposit of the SAME already-built envelope (no re-encrypt)"
                    }
                }
            }
            depositOfflineLocked(
                recipient,
                envelopeBytes,
                Instant.now().epochSecond + MailboxPointer.DEFAULT_TTL_SECONDS,
            )
            DmSendOutcome.QUEUED_FOR_PICKUP
        }
    }

    /**
     * V0.8.7 - sends a raw [payload] (opaque to this module - see [DmInboundCallSignal]'s own doc
     * comment) to [recipient] as a `CALL_SIGNAL` envelope, over an EXISTING session only - unlike
     * [send]/[sendOffline]/[sendAuto], this method NEVER bootstraps a fresh session via
     * [bootstrapSenderSession]/X3DH: a call never begins a first contact (see [DmSessionManager]'s
     * own class doc comment). Always delivered ONLINE - there is no offline/mailbox variant, and
     * never will be (see [handleOfflineEnvelope]'s own doc comment for the metadata-minimization and
     * "a call ringing hours late is a bug, not a feature" reasoning).
     *
     * The intended (today, sole expected) caller is
     * `net.lapisphilosophorum.lapisnet.call.DmCallSignalTransport`, itself called only from
     * `CallManager`'s own dedicated media thread - NEVER synchronously from a
     * [addCallSignalListener] callback, which runs inside [withPeerLock] for the SAME peer and would
     * otherwise deadlock-adjacently block that peer's entire DM traffic for the duration of this
     * call's dial (see `CallManager`'s own class doc comment on its three-executor concurrency model
     * for why this is load-bearing, not merely a style preference).
     *
     * [marksAcceptance] MUST be `true` only for a signal [CallManager] sends in direct response to a
     * LOCAL user decision to COMMUNICATE with [recipient] - an outgoing INVITE from `placeCall`, an
     * outgoing ACCEPT from `acceptCall`, or a HANGUP for a call this node already placed (OUTGOING)
     * or already accepted (INCOMING past ringing) - and `false` for every signal `CallManager` emits
     * on its own, driven by protocol state rather than a user's choice (a BUSY/malformed-SDP
     * auto-reject, a ring/connect timeout, or a media-failure hangup), AND for a REJECT or an
     * unanswered HANGUP: declining or dismissing a call the user never accepted is a decision NOT to
     * communicate with [recipient], not a decision to. SECURITY (round-11/round-12 review findings,
     * 2026-09-03): only the `true` case may call [DmAcceptedContacts.accept] below - promoting
     * [recipient] to an accepted contact is, by [DmAcceptedContacts]'s own class doc comment, "a
     * deliberate local decision, never inferred from protocol state alone", and neither an
     * automatically emitted call signal NOR the user's own REJECT/unanswered-HANGUP is such a
     * decision. Getting this wrong (as the round-11 fix still did for REJECT, fixed in round-12) lets
     * a remote peer with an existing session force its own promotion to accepted contact merely by
     * inviting this node and having the user press "reject" or dismiss the still-ringing call,
     * permanently bypassing every configured [DmAcceptancePolicy] gate for that peer's later DMs and
     * mailbox pickups.
     *
     * @throws DmUnknownRecipientException if [recipient] has no [PeerDirectoryGossip] record.
     * @throws DmNoSessionException if no session with [recipient] exists yet.
     * @throws DmSessionException if [payload] exceeds [MAX_CALL_SIGNAL_PAYLOAD_BYTES], or for a
     *   dial/send timeout or failure.
     */
    fun sendCallSignal(
        recipient: Secp256k1PublicKey,
        payload: ByteArray,
        marksAcceptance: Boolean,
    ) {
        if (payload.size > MAX_CALL_SIGNAL_PAYLOAD_BYTES) {
            throw DmSessionException(
                "call signal payload (${payload.size} bytes) exceeds $MAX_CALL_SIGNAL_PAYLOAD_BYTES bytes",
            )
        }
        withPeerLock(recipient) {
            val record =
                peerDirectory.lookup(recipient)
                    ?: throw DmUnknownRecipientException("no directory record for ${recipient.fingerprint()}")
            val envelope = prepareCallEnvelopeLocked(recipient, payload, marksAcceptance)
            dispatchOnlineLocked(recipient, record, DmEnvelopeCodec.encode(envelope))
        }
    }

    /**
     * MUST be called from within a [withPeerLock] critical section for [recipient] - the shared
     * "build the envelope, persist, cache" core [send], [sendOffline], and [sendAuto] all funnel
     * through (V0.8.6 extraction of what used to be each function's own duplicated inline body).
     * Resolves or bootstraps a session (X3DH first contact via [bootstrapSenderSession], or reuse of
     * an existing/persisted session), encrypts [plaintext] under it, persists the resulting session
     * state, and caches it - identical substance to [send]'s/[sendOffline]'s former bodies.
     */
    private fun prepareEnvelopeLocked(
        recipient: Secp256k1PublicKey,
        plaintext: ByteArray,
    ): DmEnvelope {
        var session = getCachedOrLoad(recipient)
        val envelope: DmEnvelope
        if (session == null) {
            val (newSession, header) = bootstrapSenderSession(recipient)
            val ratchetMessage = newSession.encrypt(plaintext)
            envelope =
                DmEnvelope(DmMessageType.X3DH_INITIAL, localIdentity.secp256k1KeyPair.publicKey, header, ratchetMessage)
            session = newSession
        } else {
            // NOTE (V0.8.5 hardening pass finding, 2026-08-27, tracked not fixed here): this
            // check(...) throws a bare IllegalStateException, outside this class's documented
            // @throws taxonomy - pre-existing, not introduced by this wave. See the historical note
            // this comment used to carry in send()'s/sendOffline()'s own former inline bodies.
            check(session.canSend) {
                "session with ${recipient.fingerprint()} cannot currently send (receiver-only, awaiting first inbound reply)"
            }
            val ratchetMessage = session.encrypt(plaintext)
            envelope = DmEnvelope(DmMessageType.TEXT, localIdentity.secp256k1KeyPair.publicKey, null, ratchetMessage)
        }

        // Persist BEFORE any externally-observable effect (network write or Nabu deposit) - see
        // DoubleRatchetSession's own persist/destroy-ordering rule 3.
        persistSession(recipient, session)
        putCached(recipient, session)
        // V0.8.6 - "this node itself sent that peer a message" half of DmAcceptedContacts' own
        // class doc comment, made reachable. A no-op when this manager was attach()ed without an
        // acceptedContacts instance (every prior wave's behavior, unchanged).
        acceptedContacts?.accept(recipient)
        return envelope
    }

    /**
     * MUST be called from within a [withPeerLock] critical section for [recipient] - [sendCallSignal]'s
     * own "build the envelope, persist, cache" core, structurally similar to [prepareEnvelopeLocked]
     * but deliberately NOT sharing its implementation: unlike that function, this one (a) NEVER
     * bootstraps a fresh session via [bootstrapSenderSession] - a missing session is
     * [DmNoSessionException], not a first-contact opportunity, (b) always emits
     * [DmMessageType.CALL_SIGNAL], never `TEXT`/`X3DH_INITIAL`, and (c) encrypts [payload] directly -
     * no [DmContentCodec] framing (see [DmInboundCallSignal]'s own doc comment on why the payload
     * stays opaque to this module).
     *
     * @param marksAcceptance see [sendCallSignal]'s own doc comment - the SECURITY-load-bearing
     *   distinction between a user-decided signal and an automatic, protocol-driven one.
     * @throws DmNoSessionException if no session with [recipient] exists yet.
     */
    private fun prepareCallEnvelopeLocked(
        recipient: Secp256k1PublicKey,
        payload: ByteArray,
        marksAcceptance: Boolean,
    ): DmEnvelope {
        val session =
            getCachedOrLoad(recipient)
                ?: throw DmNoSessionException(
                    "no established session with ${recipient.fingerprint()} - a call never begins a first contact",
                )
        check(session.canSend) {
            "session with ${recipient.fingerprint()} cannot currently send (receiver-only, awaiting first inbound reply)"
        }
        val ratchetMessage = session.encrypt(payload)
        val envelope =
            DmEnvelope(DmMessageType.CALL_SIGNAL, localIdentity.secp256k1KeyPair.publicKey, null, ratchetMessage)

        // Persist BEFORE any externally-observable effect - see prepareEnvelopeLocked's own
        // identical comment and DoubleRatchetSession's persist/destroy-ordering rule 3.
        persistSession(recipient, session)
        putCached(recipient, session)
        // SECURITY (round-11 review finding, 2026-09-03): unlike prepareEnvelopeLocked's identical
        // call, this one is CONDITIONAL - an automatically emitted call signal (BUSY/SDP-policy
        // auto-reject, ring/connect timeout, media-failure hangup) is protocol state, not a local
        // decision, and must NEVER promote its remote peer to accepted contact. See
        // [sendCallSignal]'s own doc comment on [marksAcceptance] for the full reasoning and the
        // concrete escape-path attack this guards against.
        if (marksAcceptance) {
            acceptedContacts?.accept(recipient)
        }
        return envelope
    }

    /** MUST be called from within a [withPeerLock] critical section for [recipient] - the online
     * dial-and-write tail [send] and [sendAuto] share. */
    private fun dispatchOnlineLocked(
        recipient: Secp256k1PublicKey,
        record: PeerRecord,
        envelopeBytes: ByteArray,
    ) {
        if (!dialSemaphore.tryAcquire(DIAL_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS)) {
            throw DmSessionException(
                "timed out waiting for an available outbound dial slot " +
                    "(MAX_CONCURRENT_OUTBOUND_DIALS=$MAX_CONCURRENT_OUTBOUND_DIALS)",
            )
        }
        try {
            val promise =
                try {
                    dmProtocol.dial(node, record.peerId, *record.addresses.toTypedArray())
                } catch (e: DmSessionException) {
                    throw e
                } catch (e: RuntimeException) {
                    // V0.8.6 hardening-pass finding: dmProtocol.dial(...) can throw SYNCHRONOUSLY
                    // (e.g. jvm-libp2p's TransportNotSupportedException when a peer gossips a
                    // PeerRecord whose addresses use a transport this node never bound) rather than
                    // failing the returned future - unlike await(...) below, which only translates
                    // ExecutionException/TimeoutException from an already-obtained future. Without
                    // this translation, such a synchronous throw would propagate straight out of
                    // sendAuto's `catch (e: DmSessionException)`, past the offline-deposit fallback,
                    // even though prepareEnvelopeLocked has already persisted/cached the session -
                    // a caller-level retry would then see getCachedOrLoad(recipient) != null and
                    // deposit a TEXT (not X3DH_INITIAL) envelope offline: the exact wrong-typed
                    // first-message trap sendAuto's own doc comment says it eliminates.
                    throw DmSessionException("failed to dial ${recipient.fingerprint()} for DM send", e)
                }
            val controller = await(promise.controller, "dial ${recipient.fingerprint()} for DM send")
            val sendHandle =
                controller as? DmSendHandle
                    ?: throw DmSessionException(
                        "dial controller for ${recipient.fingerprint()} was a " +
                            "${controller::class.qualifiedName}, not a DmSendHandle",
                    )
            sendHandle.sendEnvelope(envelopeBytes)
        } finally {
            dialSemaphore.release()
        }
    }

    /**
     * MUST be called from within a [withPeerLock] critical section for [recipient] - the offline
     * Nabu-mailbox deposit tail [sendOffline] and [sendAuto] share: durably stores [envelopeBytes]
     * in Nabu ([NabuStorage.put]) BEFORE announcing a [MailboxPointer] referencing that blob's CID -
     * "persist then publish, publish strictly last": a fast-arriving pointer can never reference a
     * not-yet-fetchable blob.
     *
     * **The pointer itself is NOT ALSO put into Nabu** (V0.8.5 hardening-pass finding) - the
     * pointer's own durability for redelivery comes entirely from [mailboxRedeliveryScheduler]'s
     * bounded in-memory copy; nothing ever reads a [MailboxPointer] back from Nabu by its own
     * content id.
     *
     * `track` runs BEFORE `publish` (V0.8.5 security-audit-round-2 finding): [GossipPubSub.publish]
     * can throw, and by the time that call runs, [prepareEnvelopeLocked] has already persisted the
     * session above - a propagating publish failure must not also skip registering the periodic
     * re-announcement [MailboxRedeliveryScheduler]'s own class doc establishes as the ONLY way an
     * offline recipient ever learns a pointer exists.
     */
    private fun depositOfflineLocked(
        recipient: Secp256k1PublicKey,
        envelopeBytes: ByteArray,
        notValidAfterEpochSecond: Long,
    ) {
        val blobCid: Cid = nabuStorage.put(envelopeBytes)
        val pointer =
            MailboxPointer.create(
                sender = localIdentity.secp256k1KeyPair,
                recipientIdentity = recipient,
                blobCid = blobCid,
                notValidAfterEpochSecond = notValidAfterEpochSecond,
            )
        val pointerBytes = MailboxPointerCodec.encode(pointer)
        mailboxRedeliveryScheduler.track(recipient, pointer, pointerBytes)
        pubsub.publish(MailboxTopics.forRecipient(recipient), pointerBytes)
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
        processInboundDmEnvelope(envelope, "peer $fromPeerId")
    }

    /**
     * V0.8.5 reuse point. [MailboxPoller] calls this after a successful Bitswap fetch + structural
     * decode of an offline-mailbox blob ([DmEnvelopeCodec.decode] already ran in
     * [MailboxPoller.attemptOne] to distinguish "garbage frame, mark resolved" from "worth
     * attempting"). Routes through the IDENTICAL session-resolution/decrypt/persist/dedup/listener-
     * notification logic [processInboundDmEnvelope] already provides for the online path - one
     * trust boundary for both transports, not two independently-reasoned-about ones. Never throws.
     *
     * Returns whether [MailboxPoller] should call `MailboxGossip.markResolved` for the pointer this
     * envelope was fetched from - see [processInboundDmEnvelope]'s own doc comment on the return
     * value for exactly which outcomes are final (`true`) vs. retryable (`false`). The online path
     * ([handleInboundEnvelope]) has no equivalent "try again later" concept - a dropped live message
     * is simply gone - so it discards this same return value.
     *
     * **V0.8.7: a `CALL_SIGNAL` envelope is rejected here OUTRIGHT, before
     * [processInboundDmEnvelope] - and therefore any decryption attempt - ever runs.** Two
     * independent reasons, either alone sufficient:
     * 1. A call ringing hours after it was placed, once the recipient happens to poll their mailbox,
     *    is a malfunction, not a feature - [sendCallSignal] never deposits one for exactly this
     *    reason (it has no offline path at all), so this rejection is defense in depth against a
     *    HAND-CRAFTED `CALL_SIGNAL` blob an attacker deposits directly, not something the normal
     *    send path could ever produce.
     * 2. A mailbox blob is a Nabu blob referenced by a PUBLICLY gossiped [MailboxPointer] - anyone
     *    watching [MailboxTopics.forRecipient] learns a pointer exists (though not its contents).
     *    The plaintext `messageType` byte inside the fetched, still-undecrypted [DmEnvelope] would
     *    tell an observer who fetches the SAME blob "a call was signaled here", a metadata leak this
     *    node's DM traffic otherwise never produces. Rejecting before decryption avoids touching any
     *    ratchet state - a tampered/forged `CALL_SIGNAL` mailbox blob never burns a message-number
     *    slot in a real session.
     *
     * Returns `true` (final, mirroring [DmMessageType.RECEIPT]'s own "never accepted regardless of
     * node state" rejection immediately below in [processInboundDmEnvelope]) - there is no
     * retryable state that would ever make a `CALL_SIGNAL` acceptable via this path; [MailboxPoller]
     * marks the pointer resolved and moves on. */
    internal fun handleOfflineEnvelope(envelope: DmEnvelope): Boolean {
        if (envelope.messageType == DmMessageType.CALL_SIGNAL) {
            logger.debug {
                "call signal arrived via the offline mailbox - rejected outright (calls are online-only, " +
                    "see this function's own doc comment)"
            }
            return true
        }
        return processInboundDmEnvelope(envelope, "offline mailbox")
    }

    /**
     * The shared core [handleInboundEnvelope] and [handleOfflineEnvelope] both funnel through -
     * everything below was [handleInboundEnvelope]'s own inline body before V0.8.5 extracted this
     * function to give the offline-mailbox path a second, structurally identical entry point.
     * [sourceDescription] is used ONLY for logging (`"peer $fromPeerId"` for the online path,
     * `"offline mailbox"` for V0.8.5's) - never for any accept/reject decision, mirroring this
     * class's own CRITICAL IDENTITY-AUTHORITY RULE for `fromPeerId` itself.
     *
     * **V0.8.5 cross-path dedup check, inserted at the very top, before session resolution even
     * begins.** [DmDedupKey.of] is safe to compute pre-decrypt: the ratchet message header's
     * `ratchetPublicKey`/`messageNumber` fields are unencrypted this wave (see
     * [DoubleRatchetSession]'s own doc comment). Checking [isRecentlyDelivered] here - before the
     * `X3DH_INITIAL` branch's one-time-prekey consumption, and before any AEAD attempt - means a
     * KNOWN-duplicate delivery (case (c) in `MailboxAbuseTest`: an already-fetched-and-acked pointer
     * re-gossiped/replayed) costs this node neither. See [recentlyDeliveredDedupKeys]'s own doc
     * comment for why this is a belt-and-braces optimization layer, not the load-bearing guarantee
     * against double delivery - that guarantee is [DoubleRatchetSession.decrypt]'s own commit-only-
     * after-AEAD-verifies state machine, which structurally rejects a literal replay of the same
     * ratchet message regardless of this cache's own state, since both [handleInboundEnvelope] and
     * [handleOfflineEnvelope] resolve the SAME session (via [getCachedOrLoad]/[liveSessionCache])
     * for a given claimed sender.
     *
     * **Return value (V0.8.5, consumed by [handleOfflineEnvelope]/[MailboxPoller] only - the online
     * path via [handleInboundEnvelope] ignores it, there being no "retry later" concept for a live
     * transport delivery): `true` means this outcome is FINAL for this exact envelope's bytes - the
     * message was delivered, cleanly rejected as tamper/garbage/replay, or rejected on grounds that
     * will never change no matter how many times the SAME bytes are re-attempted, so the caller
     * should stop retrying (mark the mailbox pointer resolved). `false` means the rejection reason is
     * about THIS node's own current, mutable state rather than about the envelope's bytes - today,
     * exactly one case: the `TEXT` branch's "no session yet for claimed sender," which becomes
     * processable once a session is bootstrapped from a DIFFERENT pointer (typically an
     * `X3DH_INITIAL` from the same sender). [MailboxPoller.pending]'s iteration order tracks gossip
     * arrival order, not send order, so a `TEXT` pointer sent second can easily be fetched+attempted
     * BEFORE the `X3DH_INITIAL` pointer that would establish the session it needs - marking it
     * resolved on that specific rejection would silently and permanently lose a message that is
     * genuinely fetchable and cryptographically valid, once the session exists. The unexpected-
     * exception catch at the bottom of this function also returns `false`, for the same "unknown, so
     * don't foreclose a retry" reasoning [pollOnce]'s own top-level `catch (e: RuntimeException)`
     * already applies to a pointer attempt that throws.
     */
    private fun processInboundDmEnvelope(
        envelope: DmEnvelope,
        sourceDescription: String,
    ): Boolean {
        val claimedSender = envelope.senderIdentity
        return try {
            withPeerLock(claimedSender) {
                val dedupKey = DmDedupKey.of(claimedSender, envelope.ratchetMessage)
                if (isRecentlyDelivered(dedupKey)) {
                    logger.debug {
                        "skipping envelope from $sourceDescription claimed sender ${claimedSender.fingerprint()} " +
                            "- already delivered (dedup key match)"
                    }
                    return@withPeerLock true
                }

                // Set ONLY inside the X3DH_INITIAL branch below, to the accepted header's ephemeral
                // key - recorded into the durable per-peer registry AFTER decrypt succeeds (commit-
                // only-after-AEAD-verifies, same discipline as persistSession's own call sites below).
                // See recordAcceptedX3dhInitialEphemeralKey's own doc comment.
                var freshX3dhInitialEphemeralKeyToRecord: ByteArray? = null
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
                                return@withPeerLock true // garbage/tamper - these exact bytes will never verify
                            }
                            // **Security audit round 1 fix (2026-08-27): DURABLE, per-peer replay guard
                            // for X3DH_INITIAL - see [recentlyDeliveredDedupKeys]'s own doc comment for
                            // the full story of the gap this closes, PROVEN exploitable by a restart
                            // (which empties that in-memory-only cache) via an executable probe.**
                            // Checked here - BEFORE any one-time-prekey consumption, BEFORE X3dh.respond,
                            // BEFORE a new session is ever built - because [X3dh.initiate] mints a FRESH
                            // ephemeral X25519 keypair on EVERY call (see that function's own body), so a
                            // genuinely repeated, legitimate handshake from the same peer (the accepted
                            // residual "no session registry" gap this class's own doc comment discloses)
                            // always carries a DIFFERENT [X3dhPreKeyMessageHeader.ephemeralPublicKey] -
                            // only a literal byte-for-byte replay of an ALREADY-ACCEPTED handshake ever
                            // collides here. Loaded fresh from disk on every attempt (not cached in
                            // memory) specifically so this survives this manager's own restart -
                            // [loadAcceptedX3dhInitialEphemeralKeys]'s own doc comment.
                            if (loadAcceptedX3dhInitialEphemeralKeys(claimedSender).any {
                                    it.contentEquals(header.ephemeralPublicKey.bytes)
                                }
                            ) {
                                logger.debug {
                                    "rejecting X3DH_INITIAL from claimed sender ${claimedSender.fingerprint()} - " +
                                        "this exact ephemeral key was already accepted for a prior handshake " +
                                        "(durable, survives a restart) - replay, not a legitimate re-handshake"
                                }
                                return@withPeerLock true // this exact handshake will never become acceptable again
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
                                        return@withPeerLock true
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
                                        return@withPeerLock true
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
                                        // this specific one-time-prekey id will never become valid again
                                        return@withPeerLock true
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
                                            // crypto verification failure - these exact bytes will never verify
                                            return@withPeerLock true
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
                            freshX3dhInitialEphemeralKeyToRecord = header.ephemeralPublicKey.bytes
                            newSession to true
                        }
                        DmMessageType.TEXT -> {
                            val existing = getCachedOrLoad(claimedSender)
                            if (existing == null) {
                                // NOT foreclosed with `true` (see this function's own doc comment on the
                                // return value) - a session for claimed_sender may simply not exist YET on
                                // THIS node. Concretely, via MailboxPoller: a sender who calls sendOffline()
                                // twice to the same still-offline recipient produces one X3DH_INITIAL pointer
                                // (bootstraps the session) and one TEXT pointer (reuses it) - MailboxPoller's
                                // pending() iteration order tracks gossip arrival order, not send order, so
                                // the TEXT pointer can easily be fetched+attempted first. Returning `false`
                                // leaves its mailbox pointer pending so a later poll pass - after the
                                // X3DH_INITIAL pointer has been processed and installed a session - can
                                // deliver it, instead of permanently losing a genuinely valid message.
                                logger.debug {
                                    "no session for claimed sender ${claimedSender.fingerprint()} - rejecting TEXT " +
                                        "envelope for now, not marking permanently resolved"
                                }
                                return@withPeerLock false
                            }
                            existing to false
                        }
                        // V0.8.7: a CALL_SIGNAL resolves an EXISTING session only - just like TEXT
                        // above - but, unlike TEXT, a missing session is FORECLOSED with `true`, not
                        // retried with `false`. There is no X3DH_INITIAL-carrying "other pointer" that
                        // could ever arrive later to establish one for this exact path: sendCallSignal
                        // never deposits offline (handleOfflineEnvelope already rejects CALL_SIGNAL
                        // before this function is ever reached for that transport - see that
                        // function's own doc comment), so the only way this branch is ever reached at
                        // all is via the ONLINE path, where "no session yet" can never self-resolve by
                        // waiting for a second delivery attempt the way an out-of-order mailbox pointer
                        // pair can for TEXT.
                        DmMessageType.CALL_SIGNAL -> {
                            val existing =
                                getCachedOrLoad(claimedSender)
                                    ?: run {
                                        logger.debug {
                                            "call signal from ${claimedSender.fingerprint()} without an " +
                                                "established session - rejected (a call never begins a " +
                                                "first contact)"
                                        }
                                        return@withPeerLock true
                                    }
                            existing to false
                        }
                        DmMessageType.RECEIPT -> {
                            logger.debug { "reserved messageType ${envelope.messageType} rejected outright" }
                            return@withPeerLock true // never accepted, regardless of node state
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
                        return@withPeerLock true // tamper/garbage against this exact session state - not retryable
                    } catch (e: RatchetMessageRejectedException) {
                        logger.debug(e) { "message rejected on public-data grounds: ${e.message}" }
                        if (isFreshHandshake) session.destroy()
                        return@withPeerLock true // public-data rejection (e.g. replay) - not retryable
                    }

                persistSession(claimedSender, session)
                putCached(claimedSender, session)
                // Durable X3DH_INITIAL replay guard commit - see recordAcceptedX3dhInitialEphemeralKey's
                // own doc comment. Only set (non-null) on the X3DH_INITIAL branch above, and only
                // reached here after session.decrypt already succeeded - never burns the durable
                // registry on a tampered/garbage attempt.
                freshX3dhInitialEphemeralKeyToRecord?.let { recordAcceptedX3dhInitialEphemeralKey(claimedSender, it) }

                // V0.8.7: a CALL_SIGNAL's ratchet plaintext is NOT a DmContentCodec frame - see
                // DmInboundCallSignal's own doc comment for why this module never even imports the
                // codec that DOES decode it (net.lapisphilosophorum.lapisnet.call.CallSignalCodec,
                // lives in a downstream module). Branches off here, AFTER the ratchet state is
                // already committed above (same "commit never depends on this branch's outcome"
                // ordering DmContentCodec.decode's own placement below follows), and BEFORE ever
                // reaching DmContentCodec.decode - a CALL_SIGNAL payload is never handed to that
                // codec, which has no idea what shape it is. Routed to callSignalListeners ONLY -
                // NEVER to inboundListeners, NEVER through DmContentCodec, so a call signal can never
                // reach DmStore or a browser's DM history (see this class's own doc comment on
                // lapis-net-dm staying WebRTC-free). Always `true` (final) - processInboundDmEnvelope's
                // own doc comment on the return value's "false means later retryable" case does not
                // apply here: this branch is reached only via the online path (handleOfflineEnvelope
                // already rejects CALL_SIGNAL before this function ever runs for that transport), and
                // a live delivery that already decrypted successfully has nothing left to retry.
                if (envelope.messageType == DmMessageType.CALL_SIGNAL) {
                    val quarantined = classifyQuarantinedSender(claimedSender)
                    markRecentlyDelivered(dedupKey)
                    val signal =
                        DmInboundCallSignal(claimedSender, plaintext, quarantined, Instant.now().epochSecond)
                    callSignalListeners.forEach { listener ->
                        try {
                            listener(signal)
                        } catch (e: RuntimeException) {
                            logger.warn(e) { "inbound call signal listener threw - other listeners still notified" }
                        }
                    }
                    return@withPeerLock true
                }

                // V0.8.6: decode the DmContent framing the ratchet plaintext now carries - AFTER the
                // ratchet state has already been committed above (persistSession/putCached), since
                // that commit must never depend on this decode's outcome (a malformed DmContent is a
                // property of THIS message, not of the session). The Ratchet's own bytes never
                // change, so a decode failure here is permanent for these exact envelope bytes.
                val content =
                    try {
                        DmContentCodec.decode(plaintext)
                    } catch (e: MalformedDmContentException) {
                        logger.debug(e) {
                            "authenticated peer ${claimedSender.fingerprint()} sent an unparseable DmContent - dropping"
                        }
                        return@withPeerLock true // final - the bytes never change
                    }

                // V0.8.6: acceptance-policy classification wires in DmAcceptanceCheck (see
                // updateAcceptanceCheck) - `quarantined` becomes non-false once that is attached.
                // depositBinding is only constructible for a FIRST-CONTACT (X3DH_INITIAL) message -
                // see DmFirstContactDepositVerifier's own class doc comment for why the binding is
                // keyed to the session's X3DH ephemeral key, not to a per-message value: a TEXT
                // message reusing an already-established session has no fresh ephemeral key to bind
                // to, so a deposit riding on it (an odd, off-label shape DmContent's own field never
                // rules out structurally) simply cannot verify - `null` here, not a special case.
                val depositBinding =
                    envelope.x3dhInitialHeader?.let { header ->
                        DmDepositBinding(
                            x3dhEphemeralPublicKey = header.ephemeralPublicKey,
                            initiatorIdentity = claimedSender,
                            recipientIdentity = localIdentity.secp256k1KeyPair.publicKey,
                        )
                    }
                val quarantined = classifyQuarantined(claimedSender, content, depositBinding)

                markRecentlyDelivered(dedupKey)
                val message =
                    DmInboundMessage(
                        claimedSender,
                        plaintext,
                        content,
                        quarantined,
                        dedupKey,
                        Instant.now().epochSecond,
                    )
                inboundListeners.forEach { listener ->
                    try {
                        listener(message)
                    } catch (e: RuntimeException) {
                        logger.warn(e) { "inbound DM listener threw - other listeners still notified" }
                    }
                }
                true // delivered - final
            }
        } catch (e: RuntimeException) {
            // Final defense-in-depth catch: every known failure mode above already funnels itself
            // into a logged `return@withPeerLock`, so nothing should reach here today - but
            // handleInboundEnvelope is called directly from a Netty callback and handleOfflineEnvelope
            // directly from MailboxPoller, and neither may ever let an exception escape (adversarial
            // test case (f), and its offline-path mirror in MailboxAbuseTest). Returns `false`
            // (retryable) rather than `true`: an UNEXPECTED exception gives no evidence one way or the
            // other about whether the envelope's bytes are actually the problem, and the offline path
            // ([handleOfflineEnvelope]/[MailboxPoller]) leaving the pointer pending mirrors exactly
            // what [MailboxPoller.pollOnce]'s own top-level `catch (e: RuntimeException)` already does
            // for a pointer attempt that throws ("leaving pending, will retry next poll").
            logger.warn(e) {
                "unexpected exception handling inbound DM envelope from $sourceDescription " +
                    "(claimed sender ${claimedSender.fingerprint()})"
            }
            false
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

    /** The post-AEAD classification [processInboundDmEnvelope] runs for every successfully
     * decrypted, successfully DmContent-decoded message - see [DmAcceptancePolicy.classifyDelivered]'s
     * own class doc comment for why this can only ever quarantine, never reject, at this point in
     * the pipeline (the prekey is already spent, the plaintext already decrypted). `false` when no
     * [acceptance] check is configured - V0.8.5's unchanged behavior. */
    private fun classifyQuarantined(
        sender: Secp256k1PublicKey,
        content: DmContent,
        depositBinding: DmDepositBinding?,
    ): Boolean = classifyQuarantinedCore(sender, content.firstContactDeposit, depositBinding)

    /** V0.8.7 - [classifyQuarantined]'s CALL_SIGNAL-shaped sibling: an inbound call signal carries no
     * [DmContent]/[DmFirstContactDeposit] at all (a call is never a first-contact deposit carrier -
     * see [DmDepositBinding]'s and [DmFirstContactDepositVerifier]'s own class doc comments), so
     * there is nothing to pass for those two parameters other than the same "absent" values
     * [classifyQuarantinedCore] already treats as ordinary inputs. Reuses the EXACT same
     * [DmAcceptancePolicy.classifyDelivered] evaluation [classifyQuarantined] does - refactored out
     * as [classifyQuarantinedCore] specifically so these two callers cannot drift into two
     * independently-reasoned-about acceptance checks. */
    private fun classifyQuarantinedSender(sender: Secp256k1PublicKey): Boolean =
        classifyQuarantinedCore(sender, deposit = null, depositBinding = null)

    private fun classifyQuarantinedCore(
        sender: Secp256k1PublicKey,
        deposit: DmFirstContactDeposit?,
        depositBinding: DmDepositBinding?,
    ): Boolean {
        val check = acceptance ?: return false
        val decision =
            DmAcceptancePolicy.classifyDelivered(
                sender = sender,
                localRecipient = localIdentity.secp256k1KeyPair.publicKey,
                gates = check.gates,
                hasVeritasPath = check.cachedVeritasPathCheck(localIdentity.secp256k1KeyPair.publicKey),
                karmaScoreOf = check.karmaScoreOf,
                isAcceptedContact = check.isAcceptedContact,
                minDepositMsat = check.minDepositMsat,
                deposit = deposit,
                depositBinding = depositBinding,
            )
        return decision is DmAcceptanceDecision.Quarantine
    }

    private fun sessionFilePath(peer: Secp256k1PublicKey): Path {
        val hex = peer.bytes.joinToString("") { "%02x".format(it) }
        return sessionStoreDirectory.resolve("$hex.lndm")
    }

    /** Sidecar path for [peer]'s durable X3DH_INITIAL ephemeral-key replay registry - see
     * [loadAcceptedX3dhInitialEphemeralKeys]/[recordAcceptedX3dhInitialEphemeralKey]'s own doc
     * comments. Deliberately a DIFFERENT file from [sessionFilePath] (`.x3dhinit` suffix, not
     * `.lndm`) rather than folded into the session file itself: this registry must keep working -
     * and keep rejecting an already-accepted ephemeral key - even across the "corrupt/undecryptable
     * session file, treat as absent, re-handshake" recovery path [loadPersisted] already documents,
     * which would otherwise silently reset it if the two were the same file. */
    private fun x3dhInitialEphemeralKeyRegistryPath(peer: Secp256k1PublicKey): Path {
        val hex = peer.bytes.joinToString("") { "%02x".format(it) }
        return sessionStoreDirectory.resolve("$hex.lndm.x3dhinit")
    }

    /** Loads the durable set of `X3DH_INITIAL` ephemeral public keys ALREADY ACCEPTED for [peer] -
     * see [recordAcceptedX3dhInitialEphemeralKey]'s own doc comment for why this exists and why it
     * must be durable (survive THIS manager's own restart), unlike [recentlyDeliveredDedupKeys].
     * Read fresh from disk on every call, deliberately NOT cached in memory - an in-memory cache is
     * exactly the property that made the original gap this closes possible in the first place (see
     * [recentlyDeliveredDedupKeys]'s own doc comment). No file - "never accepted anything from this
     * peer yet" - returns an empty list, mirroring [loadPersisted]'s own "no file, no prior state"
     * convention. A structurally corrupt file (size not a whole multiple of
     * [X3DH_INITIAL_EPHEMERAL_KEY_SIZE], or unreadable) is treated the SAME way as "no prior
     * state", never thrown - this is a replay GUARD, not a source of truth a caller must be able to
     * trust unconditionally; failing open here at worst re-admits one already-processed handshake
     * for re-attempt (no worse than this fix not existing at all), while failing closed (throwing)
     * would let a corrupted bookkeeping file permanently block a peer's legitimate future
     * `X3DH_INITIAL` entirely - a strictly worse outcome for a file that holds no secret material. */
    private fun loadAcceptedX3dhInitialEphemeralKeys(peer: Secp256k1PublicKey): List<ByteArray> {
        val target = x3dhInitialEphemeralKeyRegistryPath(peer)
        if (!Files.exists(target)) return emptyList()
        val bytes =
            try {
                Files.readAllBytes(target)
            } catch (e: java.io.IOException) {
                logger.warn(e) {
                    "failed to read X3DH_INITIAL ephemeral-key replay registry for " +
                        "${peer.fingerprint()} at $target - treating as empty (fails open, not closed - " +
                        "see this function's own doc comment)"
                }
                return emptyList()
            }
        if (bytes.size % X3DH_INITIAL_EPHEMERAL_KEY_SIZE != 0) {
            logger.warn {
                "X3DH_INITIAL ephemeral-key replay registry for ${peer.fingerprint()} at $target has an " +
                    "unexpected size (${bytes.size}, not a multiple of $X3DH_INITIAL_EPHEMERAL_KEY_SIZE) - " +
                    "treating as empty"
            }
            return emptyList()
        }
        val count = bytes.size / X3DH_INITIAL_EPHEMERAL_KEY_SIZE
        return (0 until count).map { i ->
            bytes.copyOfRange(i * X3DH_INITIAL_EPHEMERAL_KEY_SIZE, (i + 1) * X3DH_INITIAL_EPHEMERAL_KEY_SIZE)
        }
    }

    /** Durably records [ephemeralKeyBytes] - an accepted `X3DH_INITIAL` header's
     * [X3dhPreKeyMessageHeader.ephemeralPublicKey] bytes - into [peer]'s replay registry, closing
     * the security-audit round 1 major finding (2026-08-27): a replayed `X3DH_INITIAL` naming NO
     * one-time prekey (`header.oneTimePrekeyId == null`, see [processInboundDmEnvelope]'s own doc
     * comment on that branch for why [PrekeyStore]'s own durable consumption tracking never runs
     * for it) could otherwise resurrect an already-delivered message and rewind the persisted
     * ratchet session AFTER a restart of this manager - PROVEN with an executable probe: stop this
     * manager, rebuild a second instance over the SAME identity/session directory/prekey store,
     * replay the identical `X3DH_INITIAL` bytes, observe a second delivery. [recentlyDeliveredDedupKeys]
     * is in-memory-only and empty after exactly the restart that makes this exploitable, so it
     * cannot close this gap by itself.
     *
     * **Called ONLY after [processInboundDmEnvelope]'s `X3DH_INITIAL` branch has ALREADY
     * committed** - i.e. `session.decrypt` already returned successfully and the resulting session
     * was already persisted via [persistSession] - the same "commit only after AEAD verifies"
     * discipline every other durable write in this class follows. A tampered/garbage `X3DH_INITIAL`
     * therefore never burns a slot in this registry.
     *
     * FIFO-capped at [MAX_TRACKED_X3DH_INITIAL_EPHEMERAL_KEYS_PER_PEER] - generous headroom for the
     * legitimate "peer lost local state and re-handshakes" case (each such re-handshake uses a
     * genuinely DIFFERENT ephemeral key, since [X3dh.initiate] mints a fresh one every call, so it
     * is never blocked by this registry - only a LITERAL replay of an already-accepted key is),
     * same "provisional magnitude, not derived from pilot data" framing as every sibling cap in
     * this class. A no-op if [ephemeralKeyBytes] is already present (avoids a pointless duplicate
     * disk write on, e.g., a redundant call - not expected in practice given the call site, but
     * cheap to guard against). Atomic temp-file-then-[Files.move] write, same durability discipline
     * as [persistSession] - this is what makes the check in [processInboundDmEnvelope] survive a
     * process restart. Never encrypted under [cachedKey] - unlike a session file, this registry
     * holds only PUBLIC key material (an X25519 public key is not secret), so it carries none of
     * [persistSession]'s [cachedKeyLock] key-hygiene concerns. */
    private fun recordAcceptedX3dhInitialEphemeralKey(
        peer: Secp256k1PublicKey,
        ephemeralKeyBytes: ByteArray,
    ) {
        require(ephemeralKeyBytes.size == X3DH_INITIAL_EPHEMERAL_KEY_SIZE) {
            "ephemeralKeyBytes must be $X3DH_INITIAL_EPHEMERAL_KEY_SIZE bytes, was ${ephemeralKeyBytes.size}"
        }
        val existing = loadAcceptedX3dhInitialEphemeralKeys(peer)
        if (existing.any { it.contentEquals(ephemeralKeyBytes) }) return
        val updated = (existing + listOf(ephemeralKeyBytes)).takeLast(MAX_TRACKED_X3DH_INITIAL_EPHEMERAL_KEYS_PER_PEER)
        val bytes = ByteArray(updated.size * X3DH_INITIAL_EPHEMERAL_KEY_SIZE)
        updated.forEachIndexed { index, key -> key.copyInto(bytes, index * X3DH_INITIAL_EPHEMERAL_KEY_SIZE) }
        val target = x3dhInitialEphemeralKeyRegistryPath(peer)
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
     * [persistSession]/[loadPersisted] call on another thread.
     *
     * **V0.8.5 addition: also stops [mailboxPoller] and [mailboxRedeliveryScheduler].** Ownership
     * mirrors [dmProtocol]'s own convention exactly: both are constructed BY [attach] (mailboxPoller
     * lazily, right after this manager's primary constructor runs; mailboxRedeliveryScheduler
     * eagerly, passed into the primary constructor), so both are stopped BY this method. By
     * contrast, `mailboxGossip`/[peerDirectory]/[prekeyBundleGossip]/[nabuStorage] are constructed
     * by the CALLER and stopped by the caller, mirroring the existing convention exactly - see
     * `DmTestNode.stop()` for the concrete pattern this follows (it calls `peerDirectory.stop()`/
     * `prekeyBundleGossip.stop()` independently of `dmSessionManager.stop()`). `mailboxGossip` itself
     * is not a stored field here (see [attach]'s own doc comment) - only [mailboxPoller] is, which is
     * why this class's own `stop()` does not (and structurally cannot) call `mailboxGossip.stop()`
     * directly; the caller who constructed it remains responsible for stopping it. */
    fun stop() {
        synchronized(liveSessionCache) {
            liveSessionCache.values.forEach { it.destroy() }
            liveSessionCache.clear()
        }
        if (::dmProtocol.isInitialized) dmProtocol.stop()
        if (::mailboxPoller.isInitialized) mailboxPoller.stop()
        mailboxRedeliveryScheduler.stop()
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

        /** Bounds [recentlyDeliveredDedupKeys] - generous headroom, same "provisional magnitude"
         * framing as [MAX_LIVE_SESSIONS]. */
        const val MAX_RECENT_DEDUP_KEYS = 8_192

        /** The fixed byte size of an X25519 ephemeral public key - see
         * [recordAcceptedX3dhInitialEphemeralKey]/[loadAcceptedX3dhInitialEphemeralKeys]. Matches
         * `X25519PublicKey`'s own internal size constant (not itself exposed as a public constant
         * on that class, hence duplicated here rather than referenced). */
        const val X3DH_INITIAL_EPHEMERAL_KEY_SIZE = 32

        /** Bounds [recordAcceptedX3dhInitialEphemeralKey]'s per-peer durable replay registry -
         * generous headroom for the legitimate "lost local state, re-handshake" case (see that
         * function's own doc comment for why a legitimate re-handshake is never blocked by this
         * cap), same "provisional magnitude, not derived from pilot data" framing as every sibling
         * cap in this class. */
        const val MAX_TRACKED_X3DH_INITIAL_EPHEMERAL_KEYS_PER_PEER = 8

        /** V0.8.7 - the ceiling [sendCallSignal] enforces on its `payload` parameter, well under
         * [net.lapisphilosophorum.lapisnet.ratchet.RatchetMessageCodec.MAX_PLAINTEXT_BYTES] (65,459) -
         * a `CallSignalCodec`-encoded frame's own `MAX_CALL_SIGNAL_BYTES` ceiling
         * (`net.lapisphilosophorum.lapisnet.call`) is smaller still (43 + 16,384 = 16,427 bytes), so
         * this generous headroom never actually constrains a legitimate call signal - it exists as
         * this module's OWN independent ceiling, not a duplicate of `lapis-net-call`'s, so
         * `lapis-net-dm` never needs to know that module's exact constant to stay safe. */
        const val MAX_CALL_SIGNAL_PAYLOAD_BYTES = 32_768

        /**
         * Bootstraps a [DmSessionManager]: loads or generates a persisted `.salt` file (0600 where
         * POSIX permissions are supported), derives [cachedKey] ONCE via
         * [KeystoreEncryption.deriveKey]`(passphrase, params)`, attaches [DmProtocol] to [node]'s
         * host wired to the new manager's [handleInboundEnvelope], attaches [MailboxPoller] wired to
         * [handleOfflineEnvelope] (V0.8.5), and returns the manager.
         *
         * [mailboxGossip] is caller-constructed (typically via
         * `MailboxGossip.attach(pubsub, nabuStorage, localIdentity.secp256k1KeyPair.publicKey)`) and
         * passed in already-attached - mirrors [peerDirectory]/[prekeyBundleGossip]'s own
         * "already-attached collaborator passed in" convention. **Unlike those two, [mailboxGossip]
         * is NOT retained as a field on the constructed manager** - it is used exactly once, to wire
         * [MailboxPoller.attach] below, and nothing on this class ever calls a `mailboxGossip` method
         * afterward, so keeping a copy would be dead state (confirmed 2026-08-27: a private field of
         * the same name existed until then with zero reads anywhere in this class - removed).
         * [mailboxRedeliverIntervalSeconds]/[mailboxPollIntervalSeconds] are test-overridable to small
         * values - see [MailboxRedeliveryScheduler]/[MailboxPoller]'s own defaults.
         */
        fun attach(
            localIdentity: DualKeyIdentity,
            localPrekeyStore: PrekeyStore,
            node: LapisNode,
            peerDirectory: PeerDirectoryGossip,
            prekeyBundleGossip: PrekeyBundleGossip,
            mailboxGossip: MailboxGossip,
            nabuStorage: NabuStorage,
            pubsub: GossipPubSub,
            sessionStoreDirectory: Path,
            passphrase: CharArray,
            random: SecureRandom = SecureRandom(),
            mailboxRedeliverIntervalSeconds: Long = MailboxRedeliveryScheduler.DEFAULT_REDELIVER_INTERVAL_SECONDS,
            mailboxPollIntervalSeconds: Long = MailboxPoller.DEFAULT_POLL_INTERVAL_SECONDS,
            /** V0.8.6 - see [DmAcceptanceCheck]/[updateAcceptanceCheck]'s own doc comments. `null`
             * (the default) preserves V0.8.5's behavior exactly: every message delivered
             * unquarantined.
             *
             * **This wires ONLY the post-AEAD gate ([classifyQuarantined]) - it does NOT also wire
             * [mailboxGossip]'s offline pre-check.** [mailboxGossip] is passed in already-attached
             * (see this function's own class doc comment), constructed by the CALLER via a separate
             * `MailboxGossip.attach(pubsub, nabuStorage, localIdentity, acceptance = ...)` call that
             * this function never makes or influences. Passing the SAME [DmAcceptanceCheck] instance
             * to BOTH this parameter AND that separate `MailboxGossip.attach` call is the caller's
             * own responsibility - nothing here enforces it, and nothing logs or fails if it is
             * skipped. Skipping it does not break anything observably: messages are still correctly
             * quarantined by this post-AEAD gate alone. It only silently forfeits the one real saving
             * [DmAcceptancePolicy]'s own class doc comment attributes to the pre-check (skipping the
             * Bitswap fetch and persistence-index reservation for a pointer this gate would have
             * rejected anyway) - so a node whose pointer-fetch cost seems higher than its configured
             * gates would predict should check for exactly this double-wiring gap first. */
            acceptance: DmAcceptanceCheck? = null,
            /** V0.8.6 - see [DmAcceptedContacts]/this class's own `acceptedContacts` field doc
             * comment. `null` (the default) preserves every prior wave's behavior exactly: outbound
             * sends never mark a recipient accepted. A caller that wants sends to auto-accept AND a
             * future UI's explicit accept button to agree passes the SAME instance here and into
             * [acceptance]'s own `isAcceptedContact` lambda. */
            acceptedContacts: DmAcceptedContacts? = null,
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
                    nabuStorage,
                    pubsub,
                    sessionStoreDirectory,
                    cachedKey,
                    params,
                    random,
                    MailboxRedeliveryScheduler.attach(pubsub, mailboxRedeliverIntervalSeconds),
                    acceptance,
                    acceptedContacts,
                )
            manager.dmProtocol = DmProtocol.attach(node, manager::handleInboundEnvelope)
            manager.mailboxPoller =
                MailboxPoller.attach(
                    mailboxGossip,
                    nabuStorage,
                    peerDirectory,
                    manager::handleOfflineEnvelope,
                    mailboxPollIntervalSeconds,
                )
            return manager
        }
    }
}
