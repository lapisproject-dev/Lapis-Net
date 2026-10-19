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

private val logger = KotlinLogging.logger {}

/** What [DirectoryDht.resolve] found. */
sealed interface DirectoryDhtResolution {
    /** A valid value was found; the flags say whether each part was newer than what was already tracked. */
    data class Found(
        val peerRecordAccepted: Boolean,
        val prekeyBundleAccepted: Boolean,
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
        val identity: Secp256k1PublicKey,
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
     * @throws IllegalArgumentException if nothing is given, a part is foreign or invalid, the value is too
     * large or a part has already expired.
     * @throws NabuStorageException if the DHT layer fails (busy, stopped, interrupted).
     */
    fun publishOwn(
        identity: DualKeyIdentity,
        peerRecord: PeerRecord?,
        prekeyBundle: PrekeyBundle?,
        timeout: Duration = limits.defaultTimeout,
    ): DirectoryDhtPublishResult {
        require(peerRecord != null || prekeyBundle != null) { "nothing to publish" }
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
        val encoded =
            DirectoryDhtValueCodec.encode(
                DirectoryDhtValue(
                    identityKey,
                    identity.binding,
                    peerRecord?.let { PeerRecordCodec.encode(it) },
                    prekeyBundle?.let { PrekeyBundleCodec.encode(it) },
                ),
            )
        val now = wallClock()
        val innerExpiry =
            listOfNotNull(peerRecord?.notValidAfterEpochSecond, prekeyBundle?.notValidAfterEpochSecond).min()
        require(innerExpiry > now.epochSecond) { "a part to publish has already expired" }
        val notValidAfter =
            minOf(
                Instant.ofEpochSecond(innerExpiry),
                now.plus(minOf(limits.maxRecordValidity, values.maxRecordValidity ?: limits.maxRecordValidity)),
            )

        synchronized(publishLock) {
            val last = lastPublishAtNanos
            if (last != null && clock() - last < limits.minRepublishInterval.toNanos()) {
                return DirectoryDhtPublishResult(0, 0, skippedByRateLimit = true)
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
            return DirectoryDhtPublishResult(result.acknowledged, result.attempted, skippedByRateLimit = false)
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
        val attemptKey = AttemptKey(identity, peerId)
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
        val entry = DirectoryDhtValidator.validate(resolved, identity, wallClock().epochSecond)
        if (entry == null) {
            markNegative(attemptKey)
            return DirectoryDhtResolution.Rejected
        }
        val recordAccepted =
            entry.peerRecord?.let { peerDirectory.ingestFromDht(it, entry.peerRecordBytes!!) } ?: false
        val bundleAccepted =
            entry.prekeyBundle?.let { prekeys.ingestFromDht(it, entry.prekeyBundleBytes!!) } ?: false
        logger.debug { "directory DHT lookup for ${identity.fingerprint()} found a valid value" }
        return DirectoryDhtResolution.Found(recordAccepted, bundleAccepted)
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

        /** Wires the DHT fallback onto the already attached [storage], [peerDirectory] and [prekeys]. */
        fun attach(
            storage: NabuStorage,
            peerDirectory: PeerDirectoryGossip,
            prekeys: PrekeyBundleGossip,
            limits: DirectoryDhtLimits = DirectoryDhtLimits(),
        ): DirectoryDht = DirectoryDht(NabuIpnsValueStore(storage), peerDirectory, prekeys, limits)
    }
}
