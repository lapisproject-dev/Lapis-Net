package net.lapisphilosophorum.lapisnet.directory

import io.github.oshai.kotlinlogging.KotlinLogging
import io.libp2p.core.PeerId
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.networking.deriveLibp2pPrivKey
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundle
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundleCodec
import net.lapisphilosophorum.lapisnet.ratchet.verifyEncryptionBinding
import net.lapisphilosophorum.lapisnet.ratchet.verifySignedPrekey
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import net.lapisphilosophorum.lapisnet.storage.NabuStorageBusyException
import net.lapisphilosophorum.lapisnet.storage.NabuStorageException
import java.time.Duration
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap

private val logger = KotlinLogging.logger {}

/** What [DirectoryDht.resolve] found. */
sealed interface DirectoryDhtResolution {
    /** A valid value was found; the flags say whether each part was newer than what was already tracked. */
    data class Found(
        val peerRecordAccepted: Boolean,
        val prekeyBundleAccepted: Boolean,
        /** Outbox entries addressed to the local identity that were handed to a consumer (V0.9.14). */
        val outboxEntriesDispatched: Int = 0,
        /** Of those, how many the consumer accepted as new. */
        val outboxEntriesAccepted: Int = 0,
    ) : DirectoryDhtResolution

    /** Nothing (valid) is published under the name, or the lookup failed or ran out of time. */
    data object NotFound : DirectoryDhtResolution

    /** No libp2p peer ID is known for the identity and none was given: no network call was made. */
    data object NoPeerIdKnown : DirectoryDhtResolution

    /** A value was found but did not pass [DirectoryDhtValidator]; nothing of it was used. */
    data object Rejected : DirectoryDhtResolution

    /** Every DHT slot was taken; nothing was asked. */
    data object Busy : DirectoryDhtResolution

    /** The identity was looked up too recently; nothing was asked. */
    data object Throttled : DirectoryDhtResolution
}

/** Outcome of [DirectoryDht.publishOwn]; [skippedByRateLimit] means nothing was published at all. */
data class DirectoryDhtPublishResult(
    val acknowledged: Int,
    val attempted: Int,
    val skippedByRateLimit: Boolean,
    /** Outbox entries (V0.9.14) that went into the published value. */
    val outboxEntriesPublished: Int = 0,
    /** Live outbox entries that did not fit this publication (count or byte budget). */
    val outboxEntriesOmitted: Int = 0,
    /** Recipients for whom a rendezvous provider record was sent to at least one peer (delivery is unconfirmed). */
    val rendezvousAnnounced: Int = 0,
)

/**
 * Outcome of [DirectoryDht.discoverInbox]: [providersFound] peers announced something for the local identity,
 * [resolved] of their values were looked up successfully, [entriesAccepted] outbox entries were accepted by a
 * consumer, [skipped] providers were not asked (throttled, busy, ...), [throttled] means the whole discovery
 * was refused because the previous one was too recent.
 */
data class InboxDiscoveryReport(
    val providersFound: Int,
    val resolved: Int,
    val entriesAccepted: Int,
    val skipped: Int,
    val throttled: Boolean,
)

/**
 * Outcome of [DirectoryDht.catchUp] / [refreshStale]: [attempted] identities were looked up on the
 * network, [found] of them had a valid value, [skipped] were not asked (over the cap, no peer ID
 * known, throttled, busy or out of time).
 */
data class CatchUpReport(
    val attempted: Int,
    val found: Int,
    val skipped: Int,
)

/**
 * DHT fallback for the peer directory and prekey bundles (V0.9.13). GossipSub stays the fast path
 * ([PeerDirectoryGossip], [PrekeyBundleGossip]); this class adds the two things gossip cannot do: a node
 * that was offline during the gossip window can catch up, and a record that expired or was never seen
 * can be fetched on demand.
 *
 * A node publishes its [PeerRecord] and [PrekeyBundle] together, as one [DirectoryDhtValue] under the
 * IPNS name of its own Ed25519 key ([publishOwn]). A reader needs that Ed25519 peer ID to ask - from an
 * old record in the index, or from a contact (`lapisnet://connect` carries it) - and gives it as the
 * hint; with only a secp256k1 identity and nothing else known, nothing can be looked up
 * ([DirectoryDhtResolution.NoPeerIdKnown]). What comes back is verified in full ([DirectoryDhtValidator])
 * and then enters the same indexes and storage as a gossip-received record - but is never gossiped on.
 *
 * Everything is bounded by [DirectoryDhtLimits]. **Metadata**: a lookup tells every peer the walk asks
 * which peer ID is being looked for and who asks; a publication tells the peers it is sent to that the
 * node is online. This is the same class of exposure as the gossip topic, accepted until traffic
 * anonymisation exists (docs/architecture.adoc, "DHT fallback"). Nothing calls this class by itself:
 * publishing and refreshing are the caller's decision.
 */
class DirectoryDht internal constructor(
    private val values: IpnsValueStore,
    private val peerDirectory: PeerDirectoryGossip,
    private val prekeys: PrekeyBundleGossip,
    private val limits: DirectoryDhtLimits,
    private val clock: () -> Long = System::nanoTime,
    private val wallClock: () -> Instant = Instant::now,
    private val rendezvous: RendezvousStore? = null,
    private val localIdentity: Secp256k1PublicKey? = null,
    private val outbox: DhtOutbox? = null,
) {
    private class Attempt(
        val atNanos: Long,
        var negative: Boolean,
    )

    /**
     * Tracked per (identity, peer ID asked): a caller-supplied hint is unauthenticated, so a wrong hint
     * must not throttle or negatively cache the lookups of the correct peer ID of the same identity.
     */
    private data class AttemptKey(
        val identity: Secp256k1PublicKey?,
        val peerId: PeerId,
    )

    private val resolveAttempts =
        object : LinkedHashMap<AttemptKey, Attempt>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<AttemptKey, Attempt>): Boolean =
                size > limits.resolveTrackerCapacity
        }

    private val publishLock = Any()
    private var lastPublishAtNanos: Long? = null
    private var lastSequence: Long = -1

    /**
     * The last identity the previous [catchUp] actually asked; the next one continues after it in the order of the
     * given list. Identity-based (not an index) so throttle filtering between calls cannot shift it onto others.
     */
    private var catchUpCursor: Secp256k1PublicKey? = null

    private val consumers = ConcurrentHashMap<OutboxEntryKind, OutboxEntryConsumer>()

    /** Recipients a rendezvous record was recently announced for (LRU), guarded by [publishLock]. */
    private val rendezvousAnnounced =
        object : LinkedHashMap<Secp256k1PublicKey, Long>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Secp256k1PublicKey, Long>): Boolean =
                size > limits.rendezvousTrackerCapacity
        }

    private val discoveryLock = Any()
    private var lastDiscoveryAtNanos: Long? = null

    /**
     * Registers the consumer for entries of [kind] addressed to the local identity. One per kind.
     *
     * @throws IllegalArgumentException if a consumer is already registered for [kind].
     */
    fun registerOutboxConsumer(
        kind: OutboxEntryKind,
        consumer: OutboxEntryConsumer,
    ) {
        require(consumers.putIfAbsent(kind, consumer) == null) { "a consumer for $kind is already registered" }
    }

    /**
     * Publishes [peerRecord] and/or [prekeyBundle] of [identity] under the IPNS name of its Ed25519 key.
     *
     * Both must belong to [identity] and verify fully - a node never signs a value it would itself reject.
     * The value must fit [DirectoryDhtValueCodec.MAX_VALUE_BYTES]: both parts together leave room for a
     * bundle with a few one-time prekeys only, so publish a reduced bundle (or none) here. One-time prekeys
     * served from the DHT can have been used up since, in which case X3DH falls back to the handshake
     * without one. The IPNS record expires with the earlier of the parts (and after at most
     * [DirectoryDhtLimits.maxRecordValidity]); its sequence is `max(previous + 1, epoch milliseconds)`, so it
     * rises with every publication - and survives a restart as long as the clock does not go back.
     *
     * At most one network publication per [DirectoryDhtLimits.minRepublishInterval] (monotonic); a call
     * inside the window changes nothing and reports `skippedByRateLimit`.
     *
     * Since V0.9.14 the value also carries the selected entries of the [DhtOutbox] this instance was attached
     * with (see [DirectoryDhtValue]); after the IPNS publication a rendezvous provider record is announced for a
     * few of their recipients ([DirectoryDhtLimits.maxRendezvousAnnouncesPerPublish]), if enabled. The outbox is
     * the only way mail and direct messages reach the DHT: they never write an IPNS value themselves. Publish the
     * [peerRecord] together with an outbox: a recipient that does not know this node can only dial it from the
     * peer record of the same value.
     *
     * @throws IllegalArgumentException if nothing is given (no part and an empty outbox), a part is foreign or
     * invalid, the value is too large or a part has already expired.
     * @throws NabuStorageException if the DHT layer fails (busy, stopped, interrupted).
     */
    fun publishOwn(
        identity: DualKeyIdentity,
        peerRecord: PeerRecord?,
        prekeyBundle: PrekeyBundle?,
        timeout: Duration = limits.defaultTimeout,
    ): DirectoryDhtPublishResult {
        require(peerRecord != null || prekeyBundle != null || (outbox?.size() ?: 0) > 0) { "nothing to publish" }
        require(identity.verifyBinding()) { "the identity's own binding does not verify" }
        val identityKey = identity.secp256k1KeyPair.publicKey
        if (peerRecord != null) {
            require(peerRecord.identity == identityKey) { "the peer record belongs to another identity" }
            require(peerRecord.binding == identity.binding) { "the peer record carries another binding" }
            require(PeerRecord.verify(peerRecord) && peerRecord.verifyBinding() && peerRecord.verifyPossession()) {
                "the peer record does not verify"
            }
        }
        if (prekeyBundle != null) {
            require(prekeyBundle.identity == identityKey) { "the prekey bundle belongs to another identity" }
            require(
                PrekeyBundle.verify(prekeyBundle) &&
                    prekeyBundle.verifyEncryptionBinding() &&
                    prekeyBundle.verifySignedPrekey(),
            ) { "the prekey bundle does not verify" }
        }
        val now = wallClock()
        val directoryParts = peerRecord != null || prekeyBundle != null
        val directoryOnly =
            if (directoryParts) {
                DirectoryDhtValue(
                    identityKey,
                    identity.binding,
                    peerRecord?.let { PeerRecordCodec.encode(it) },
                    prekeyBundle?.let { PrekeyBundleCodec.encode(it) },
                )
            } else {
                null
            }
        val baseSize =
            if (directoryOnly !=
                null
            ) {
                DirectoryDhtValueCodec.encode(directoryOnly).size
            } else {
                DirectoryDhtValueCodec.FIXED_SIZE
            }
        // one count byte is part of the outbox section
        val outboxBudget = minOf(limits.maxOutboxBytes, DirectoryDhtValueCodec.MAX_VALUE_BYTES - baseSize) - 1
        val selection =
            if (outbox != null && outboxBudget > 0) {
                outbox.selectForPublication(now.epochSecond, limits.maxOutboxEntriesPerValue, outboxBudget)
            } else {
                OutboxSelection(emptyList(), 0)
            }
        require(directoryParts || selection.entries.isNotEmpty()) { "nothing to publish" }
        val encoded =
            DirectoryDhtValueCodec.encode(
                DirectoryDhtValue(
                    identityKey,
                    identity.binding,
                    peerRecord?.let { PeerRecordCodec.encode(it) },
                    prekeyBundle?.let { PrekeyBundleCodec.encode(it) },
                    selection.entries,
                ),
            )
        val innerExpiry =
            if (directoryParts) {
                listOfNotNull(peerRecord?.notValidAfterEpochSecond, prekeyBundle?.notValidAfterEpochSecond).min()
            } else {
                selection.entries.maxOf { it.notValidAfterEpochSecond }
            }
        require(innerExpiry > now.epochSecond) { "a part to publish has already expired" }
        val notValidAfter =
            minOf(
                Instant.ofEpochSecond(innerExpiry),
                now.plus(minOf(limits.maxRecordValidity, values.maxRecordValidity ?: limits.maxRecordValidity)),
            )

        synchronized(publishLock) {
            val deadlineNanos = clock() + timeout.toNanos()
            val last = lastPublishAtNanos
            if (last != null && clock() - last < limits.minRepublishInterval.toNanos()) {
                return DirectoryDhtPublishResult(
                    0,
                    0,
                    skippedByRateLimit = true,
                    outboxEntriesOmitted =
                        selection.entries.size + selection.omitted,
                )
            }
            val sequence = maxOf(lastSequence + 1, now.toEpochMilli())
            // advanced before the network call: a failed attempt must not be retried with the same sequence
            lastSequence = sequence
            val result =
                values.publish(
                    identity.deriveLibp2pPrivKey(),
                    encoded,
                    sequence,
                    notValidAfter,
                    IPNS_TTL,
                    timeout,
                )
            lastPublishAtNanos = clock()
            val announced = announceRendezvous(selection.entries, deadlineNanos)
            return DirectoryDhtPublishResult(
                result.acknowledged,
                result.attempted,
                skippedByRateLimit = false,
                outboxEntriesPublished = selection.entries.size,
                outboxEntriesOmitted = selection.omitted,
                rendezvousAnnounced = announced,
            )
        }
    }

    /**
     * Looks [identity] up in the DHT and takes what is valid into the gossip indexes. [peerIdHint] is the
     * Ed25519 peer ID to ask for; without one, the peer ID of the latest record tracked for [identity] is
     * used (see [PeerDirectoryGossip.knownPeerId]) - and if there is none either, nothing is asked.
     * A hint is unauthenticated, but cannot make a wrong value pass: the value must be signed by the
     * hinted key AND name [identity] with a binding by [identity] for that very key.
     *
     * @throws IllegalArgumentException if [timeout] is not positive.
     */
    fun resolve(
        identity: Secp256k1PublicKey,
        peerIdHint: PeerId? = null,
        timeout: Duration = limits.defaultTimeout,
    ): DirectoryDhtResolution {
        require(!timeout.isNegative && !timeout.isZero) { "timeout must be positive" }
        val peerId = peerIdHint ?: peerDirectory.knownPeerId(identity) ?: return DirectoryDhtResolution.NoPeerIdKnown
        return resolveInternal(identity, peerId, timeout)
    }

    /**
     * Looks up the value of the node with the Ed25519 [peerId] without knowing its identity (the rendezvous
     * path of [discoverInbox]: a provider announced something for the local identity, its identity is not
     * known yet). The identity is taken from the value; the full proof chain (publisher key, binding, parts)
     * is checked exactly as in [resolve], with the same throttle and negative cache keyed on the peer ID.
     */
    fun resolveByPeerId(
        peerId: PeerId,
        timeout: Duration = limits.defaultTimeout,
    ): DirectoryDhtResolution {
        require(!timeout.isNegative && !timeout.isZero) { "timeout must be positive" }
        return resolveInternal(null, peerId, timeout)
    }

    private fun resolveInternal(
        expectedIdentity: Secp256k1PublicKey?,
        peerId: PeerId,
        timeout: Duration,
    ): DirectoryDhtResolution {
        val attemptKey = AttemptKey(expectedIdentity, peerId)
        if (!tryBeginResolve(attemptKey)) return DirectoryDhtResolution.Throttled

        val resolved =
            try {
                values.resolve(peerId, timeout)
            } catch (_: IllegalArgumentException) {
                // a peer ID without an IPNS name (not Ed25519)
                forgetAttempt(attemptKey)
                return DirectoryDhtResolution.NoPeerIdKnown
            } catch (_: NabuStorageBusyException) {
                forgetAttempt(attemptKey)
                return DirectoryDhtResolution.Busy
            } catch (e: NabuStorageException) {
                logger.debug { "directory DHT lookup failed: ${e.javaClass.simpleName}" }
                markNegative(attemptKey)
                return DirectoryDhtResolution.NotFound
            }
        if (resolved == null) {
            markNegative(attemptKey)
            return DirectoryDhtResolution.NotFound
        }
        val entry = DirectoryDhtValidator.validate(resolved, expectedIdentity, wallClock().epochSecond)
        if (entry == null) {
            markNegative(attemptKey)
            return DirectoryDhtResolution.Rejected
        }
        if (expectedIdentity == null && entry.identity == localIdentity) {
            // our own value, found through our own rendezvous key: nothing to take from it
            markNegative(attemptKey)
            return DirectoryDhtResolution.NotFound
        }
        val recordAccepted =
            entry.peerRecord?.let { peerDirectory.ingestFromDht(it, entry.peerRecordBytes!!) } ?: false
        val bundleAccepted =
            entry.prekeyBundle?.let { prekeys.ingestFromDht(it, entry.prekeyBundleBytes!!) } ?: false
        // the peer record is ingested first (above): a consumer that dials the sender needs its address
        val (dispatched, accepted) = dispatchOutbox(entry)
        logger.debug { "directory DHT lookup for ${entry.identity.fingerprint()} found a valid value" }
        return DirectoryDhtResolution.Found(recordAccepted, bundleAccepted, dispatched, accepted)
    }

    /**
     * Hands the entries addressed to the local identity to the consumer of their kind - outside every lock of
     * this class, on the calling thread, each consumer call isolated. Entries for anybody else are ignored:
     * not stored, not forwarded. At most [DirectoryDhtLimits.maxDispatchedEntriesPerResolve] per value.
     */
    private fun dispatchOutbox(entry: ValidatedDirectoryEntry): Pair<Int, Int> {
        val local = localIdentity ?: return 0 to 0
        var dispatched = 0
        var accepted = 0
        for (outboxEntry in entry.outboxEntries) {
            if (dispatched >= limits.maxDispatchedEntriesPerResolve) break
            if (outboxEntry.recipient != local) continue
            val consumer = consumers[outboxEntry.kind] ?: continue
            dispatched++
            val outcome =
                try {
                    consumer.onDhtOutboxEntry(entry.identity, entry.publisher, outboxEntry)
                } catch (e: RuntimeException) {
                    logger.debug { "an outbox consumer failed: ${e.javaClass.simpleName}" }
                    OutboxIngestOutcome.REJECTED
                }
            if (outcome == OutboxIngestOutcome.ACCEPTED) accepted++
        }
        return dispatched to accepted
    }

    /**
     * Finds the nodes that announced a rendezvous provider record for the local identity and looks their values
     * up, so that mail and direct messages from senders the local node does not know yet (and that are not in
     * any contact list) can be found. At most one network discovery per [DirectoryDhtLimits.minDiscoveryInterval],
     * at most [DirectoryDhtLimits.maxRendezvousProviders] providers, all within one overall [timeout].
     * **Metadata**: the question "who has something for me" is visible to the DHT peers near the rendezvous key
     * (docs/architecture.adoc, "Metadata: recipient lookups reveal who talks to whom").
     *
     * @throws IllegalStateException if this instance has no local identity or rendezvous is disabled.
     */
    fun discoverInbox(timeout: Duration = limits.defaultTimeout): InboxDiscoveryReport {
        require(!timeout.isNegative && !timeout.isZero) { "timeout must be positive" }
        val local = checkNotNull(localIdentity) { "discoverInbox needs a local identity" }
        val store = rendezvous
        check(limits.rendezvousEnabled && store != null) { "rendezvous is not enabled" }
        synchronized(discoveryLock) {
            val last = lastDiscoveryAtNanos
            if (last != null && clock() - last < limits.minDiscoveryInterval.toNanos()) {
                return InboxDiscoveryReport(0, 0, 0, 0, throttled = true)
            }
            lastDiscoveryAtNanos = clock()
        }
        val deadline = clock() + timeout.toNanos()
        val providers =
            try {
                store.findProviders(
                    MessagingRendezvous.cidFor(local),
                    limits.maxRendezvousProviders,
                    Duration.ofNanos(timeout.toNanos() / 2),
                )
            } catch (e: NabuStorageException) {
                logger.debug { "rendezvous lookup failed: ${e.javaClass.simpleName}" }
                emptySet()
            }
        var resolved = 0
        var accepted = 0
        var skipped = 0
        for (provider in providers.take(limits.maxRendezvousProviders)) {
            val remaining = deadline - clock()
            if (remaining <= 0) {
                skipped++
                continue
            }
            when (val r = resolveByPeerId(provider, Duration.ofNanos(remaining))) {
                is DirectoryDhtResolution.Found -> {
                    resolved++
                    accepted += r.outboxEntriesAccepted
                }
                DirectoryDhtResolution.NotFound, DirectoryDhtResolution.Rejected -> Unit
                DirectoryDhtResolution.NoPeerIdKnown, DirectoryDhtResolution.Busy, DirectoryDhtResolution.Throttled ->
                    skipped++
            }
        }
        return InboxDiscoveryReport(providers.size, resolved, accepted, skipped, throttled = false)
    }

    /** Announces rendezvous provider records; failures are isolated per recipient. Called under [publishLock]. */
    private fun announceRendezvous(
        entries: List<OutboxEntry>,
        deadlineNanos: Long,
    ): Int {
        val store = rendezvous
        if (!limits.rendezvousEnabled || store == null || entries.isEmpty()) return 0
        val now = clock()
        val recipients = entries.map { it.recipient }.distinct()
        var announced = 0
        var attempts = 0
        for (recipient in recipients) {
            if (attempts >= limits.maxRendezvousAnnouncesPerPublish) break
            val previous = rendezvousAnnounced[recipient]
            if (previous != null && now - previous < limits.rendezvousReannounceInterval.toNanos()) continue
            val remaining = deadlineNanos - clock()
            if (remaining <= 0) break
            attempts++
            // recorded before the attempt: a failing recipient must not be hammered on every publication
            rendezvousAnnounced[recipient] = now
            try {
                if (store.provide(MessagingRendezvous.cidFor(recipient), Duration.ofNanos(remaining)) > 0) announced++
            } catch (e: RuntimeException) {
                logger.debug { "rendezvous announcement failed: ${e.javaClass.simpleName}" }
            }
        }
        return announced
    }

    /**
     * The still-valid [PeerRecord] for [identity]: the gossip index first (no network), and only if it has
     * none the DHT, via [resolve] with [peerIdHint]. The DHT is asked at most once per
     * [DirectoryDhtLimits.minResolveInterval] per identity.
     */
    fun lookupPeerRecord(
        identity: Secp256k1PublicKey,
        peerIdHint: PeerId? = null,
        nowEpochSecond: Long = Instant.now().epochSecond,
    ): PeerRecord? {
        peerDirectory.lookup(identity, nowEpochSecond)?.let { return it }
        resolve(identity, peerIdHint)
        return peerDirectory.lookup(identity, nowEpochSecond)
    }

    /** As [lookupPeerRecord], for the [PrekeyBundle]. */
    fun lookupPrekeyBundle(
        identity: Secp256k1PublicKey,
        peerIdHint: PeerId? = null,
        nowEpochSecond: Long = Instant.now().epochSecond,
    ): PrekeyBundle? {
        prekeys.lookup(identity, nowEpochSecond)?.let { return it }
        resolve(identity, peerIdHint)
        return prekeys.lookup(identity, nowEpochSecond)
    }

    /**
     * Looks up at most [DirectoryDhtLimits.maxIdentitiesPerCatchUp] distinct, not currently throttled
     * [identities] one after the other (the start rotates between calls, so a long list is covered over time) (the peer IDs come from the index), all within one overall [timeout]; what is left over is
     * counted as skipped. For a node that just came online, or a contact list that was imported.
     */
    fun catchUp(
        identities: Collection<Secp256k1PublicKey>,
        timeout: Duration,
    ): CatchUpReport {
        require(!timeout.isNegative && !timeout.isZero) { "timeout must be positive" }
        val deadline = clock() + timeout.toNanos()
        val distinct = identities.distinct()
        // rotate the full list to start after the last identity asked; throttled ones are skipped only afterwards,
        // so they cannot shift the start onto other identities
        val selected =
            synchronized(resolveAttempts) {
                val last = catchUpCursor
                val at = if (last == null) -1 else distinct.indexOf(last)
                val rotated = distinct.drop(at + 1) + distinct.take(at + 1)
                rotated.filterNot { isThrottled(it) }.take(limits.maxIdentitiesPerCatchUp)
            }
        var lastAsked: Secp256k1PublicKey? = null
        var attempted = 0
        var found = 0
        var skipped = distinct.size - selected.size
        for (identity in selected) {
            val remaining = deadline - clock()
            if (remaining <= 0) {
                skipped++
                continue
            }
            lastAsked = identity
            when (resolve(identity, null, Duration.ofNanos(remaining))) {
                is DirectoryDhtResolution.Found -> {
                    attempted++
                    found++
                }
                DirectoryDhtResolution.NotFound, DirectoryDhtResolution.Rejected -> attempted++
                DirectoryDhtResolution.NoPeerIdKnown, DirectoryDhtResolution.Busy, DirectoryDhtResolution.Throttled ->
                    skipped++
            }
        }
        if (lastAsked != null) {
            // moves on only past the entries actually asked, so deadline-skipped ones come first next time
            synchronized(resolveAttempts) { catchUpCursor = lastAsked }
        }
        return CatchUpReport(attempted, found, skipped)
    }

    /**
     * [catchUp] for every identity whose tracked peer record or prekey bundle has expired or expires within
     * [expiringWithinSeconds]. Meant to be called periodically by the owner of this node; it is not.
     */
    fun refreshStale(
        nowEpochSecond: Long = Instant.now().epochSecond,
        expiringWithinSeconds: Long = DEFAULT_EXPIRING_WITHIN_SECONDS,
    ): CatchUpReport {
        require(expiringWithinSeconds >= 0) { "expiringWithinSeconds must not be negative" }
        val stale =
            (peerDirectory.knownIdentities() + prekeys.knownIdentities()).filter {
                peerDirectory.expiresWithin(it, nowEpochSecond, expiringWithinSeconds) ||
                    prekeys.expiresWithin(it, nowEpochSecond, expiringWithinSeconds)
            }
        return catchUp(stale, limits.defaultTimeout)
    }

    private fun isThrottled(identity: Secp256k1PublicKey): Boolean =
        synchronized(resolveAttempts) {
            val peerId = peerDirectory.knownPeerId(identity) ?: return@synchronized false
            val previous = resolveAttempts[AttemptKey(identity, peerId)] ?: return@synchronized false
            val window = if (previous.negative) limits.negativeCacheTtl else limits.minResolveInterval
            clock() - previous.atNanos < window.toNanos()
        }

    /** Reserves a lookup of [identity] unless one happened too recently; atomic, so concurrent callers do not both pass. */
    private fun tryBeginResolve(key: AttemptKey): Boolean =
        synchronized(resolveAttempts) {
            val now = clock()
            val previous = resolveAttempts[key]
            if (previous != null) {
                val window = if (previous.negative) limits.negativeCacheTtl else limits.minResolveInterval
                if (now - previous.atNanos < window.toNanos()) return@synchronized false
            }
            resolveAttempts[key] = Attempt(now, negative = false)
            true
        }

    private fun markNegative(key: AttemptKey) {
        synchronized(resolveAttempts) { resolveAttempts[key]?.negative = true }
    }

    private fun forgetAttempt(key: AttemptKey) {
        synchronized(resolveAttempts) { resolveAttempts.remove(key) }
    }

    companion object {
        /** IPNS caching hint of a published record. */
        private val IPNS_TTL: Duration = Duration.ofMinutes(5)

        const val DEFAULT_EXPIRING_WITHIN_SECONDS: Long = 600L

        /**
         * Wires the DHT fallback onto the already attached [storage], [peerDirectory] and [prekeys].
         * [localIdentity] enables the dispatch of outbox entries addressed to it and [discoverInbox]; [outbox]
         * is where this node's own outgoing entries are published from. Both default to "off".
         */
        fun attach(
            storage: NabuStorage,
            peerDirectory: PeerDirectoryGossip,
            prekeys: PrekeyBundleGossip,
            limits: DirectoryDhtLimits = DirectoryDhtLimits(),
            localIdentity: Secp256k1PublicKey? = null,
            outbox: DhtOutbox? = null,
        ): DirectoryDht =
            DirectoryDht(
                NabuIpnsValueStore(storage),
                peerDirectory,
                prekeys,
                limits,
                rendezvous = NabuRendezvousStore(storage),
                localIdentity = localIdentity,
                outbox = outbox,
            )
    }
}
