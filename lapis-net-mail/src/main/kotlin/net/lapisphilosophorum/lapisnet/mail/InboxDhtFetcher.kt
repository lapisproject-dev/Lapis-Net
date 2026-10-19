package net.lapisphilosophorum.lapisnet.mail

import io.github.oshai.kotlinlogging.KotlinLogging
import io.libp2p.core.PeerId
import net.lapisphilosophorum.lapisnet.directory.DirectoryDht
import net.lapisphilosophorum.lapisnet.directory.OutboxEntry
import net.lapisphilosophorum.lapisnet.directory.OutboxEntryConsumer
import net.lapisphilosophorum.lapisnet.directory.OutboxEntryKind
import net.lapisphilosophorum.lapisnet.directory.OutboxIngestOutcome
import net.lapisphilosophorum.lapisnet.directory.PeerAddressDialing
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
 * Receiving side of the DHT fallback for mail (V0.9.14): consumer of `MAIL_POINTER` outbox entries and the
 * poller that turns them into inbox messages, in the shape of lapis-net-dm's `MailboxPoller`.
 *
 * [consumer] only **queues** a pointer (the envelope CID, the sender's identity and Ed25519 peer ID, the expiry)
 * - no network, no clock, as it runs inside `DirectoryDht.resolve`. [pollOnce] then, per pending pointer:
 * 1. looks the sender up in the peer directory (the peer record was ingested from the same DHT value just
 *    before) and refuses a record whose peer ID differs from the one that signed the DHT value;
 * 2. registers the sender's addresses through [PeerAddressDialing] (same hygiene as the mailbox poller);
 * 3. fetches the **envelope** from that very peer - always with an explicit peer, never by a provider search for
 *    the CID, which would announce the CID to the DHT;
 * 4. re-computes the envelope's CID from the received bytes, then runs the **same envelope checks as the gossip
 *    validator** including the [MailAcceptanceCheck] policy ([InboxGossip.dhtCheckEnvelope]), and requires the
 *    envelope's sender to be the identity of the DHT value;
 * 5. only now - policy passed, not already received by gossip - fetches the **body** (again from that peer),
 *    bounded by [MessageBodyCodec.MAX_BODY_BLOB_SIZE], verifies its CID against the envelope and ingests it
 *    ([InboxGossip.dhtIngest]: decode, dedup, persistence cap, index).
 * The acceptance policy therefore cannot be bypassed and rejected senders cost no body download.
 *
 * Bounded like the mailbox poller: [POLL_PASS_WALL_CLOCK_BUDGET] per pass, [MAX_FETCH_ATTEMPTS_PER_SENDER_PER_PASS]
 * per sender, a rotating start offset so unreachable pointers cannot starve the others, one try/catch per entry.
 * The sender must be reachable for the fetch: only the pointer lives in the DHT, never the message.
 */
class InboxDhtFetcher internal constructor(
    private val inbox: InboxGossip,
    private val storage: NabuStorage,
    private val peerDirectory: PeerDirectoryGossip,
    private val localIdentity: Secp256k1PublicKey,
    private val pollIntervalSeconds: Long,
    private val fetchTimeout: Duration = FETCH_TIMEOUT,
    private val passBudget: Duration = POLL_PASS_WALL_CLOCK_BUDGET,
) {
    private val pending = InboxDhtPendingIndex()

    /** Network fetches attempted so far (diagnostics and tests). */
    @Volatile
    internal var fetchAttempts: Long = 0
        private set

    private var passStartOffset: Int = 0

    private val executor: ScheduledExecutorService by lazy {
        ScheduledThreadPoolExecutor(1) { r -> Thread(r, "lapis-net-mail-dht-fetch").apply { isDaemon = true } }
            .also { it.removeOnCancelPolicy = true }
    }
    private var scheduledTask: ScheduledFuture<*>? = null

    /** Queues `MAIL_POINTER` entries addressed to this identity. Never touches the network or the clock. */
    fun consumer(): OutboxEntryConsumer = MailPointerQueueConsumer(localIdentity, pending)

    /** Number of pointers queued and not yet resolved (diagnostics, tests). */
    internal fun pendingCount(): Int = pending.pending().size

    @Synchronized
    fun pollOnce(nowEpochSecond: Long = Instant.now().epochSecond) {
        pending.evictExpired(nowEpochSecond)
        val passStart = System.nanoTime()
        val attemptsBySender = HashMap<Secp256k1PublicKey, Int>()
        val list = pending.pending()
        if (list.isEmpty()) {
            passStartOffset = 0
            return
        }
        val size = list.size
        val startIndex = passStartOffset % size
        var processed = 0
        while (processed < size) {
            if (System.nanoTime() - passStart >= passBudget.toNanos()) {
                logger.debug { "mail DHT poll pass budget exhausted - the next pass resumes where this one stopped" }
                break
            }
            val entry = list[(startIndex + processed) % size]
            try {
                val used = attemptsBySender.getOrDefault(entry.sender, 0)
                if (entry.notValidAfterEpochSecond < nowEpochSecond ||
                    entry.attempts >= InboxDhtPendingIndex.MAX_ATTEMPTS_PER_ENTRY
                ) {
                    pending.markResolved(entry)
                } else if (entry.nextAttemptEpochSecond > nowEpochSecond) {
                    // backing off
                } else if (used < MAX_FETCH_ATTEMPTS_PER_SENDER_PER_PASS) {
                    if (attemptOne(entry, nowEpochSecond)) attemptsBySender[entry.sender] = used + 1
                }
            } catch (e: RuntimeException) {
                logger.warn(e) { "unexpected exception fetching a DHT mail pointer - leaving it pending" }
            }
            processed++
        }
        passStartOffset = (startIndex + processed) % size
    }

    /** @return whether a network fetch was attempted (and is to be charged against the per-sender budget). */
    private fun attemptOne(
        entry: InboxDhtPendingIndex.Entry,
        nowEpochSecond: Long,
    ): Boolean {
        val record = peerDirectory.lookup(entry.sender) ?: return false
        if (record.peerId != entry.senderPeerId) {
            logger.debug { "sender record and DHT publisher disagree on the peer ID - dropping the pointer" }
            pending.markResolved(entry)
            return false
        }
        val envelopeBytes =
            try {
                if (!PeerAddressDialing.registerSafeAddresses(storage, record)) return false
                fetchAttempts++
                pending.recordAttempt(entry, nowEpochSecond)
                storage.get(entry.envelopeCid, peers = setOf(record.peerId), timeout = fetchTimeout)
            } catch (e: NabuStorageException) {
                null
            } ?: return true // attempted; unreachable or timed out, stays pending

        if (envelopeBytes.size > MailFrameCodec.MAX_ENVELOPE_SECTION_BYTES ||
            MessageBodyCodec.cidFor(envelopeBytes) != entry.envelopeCid
        ) {
            logger.debug { "DHT mail envelope is oversized or does not match its CID - discarding" }
            pending.markResolved(entry)
            return true
        }
        val envelope =
            when (val check = inbox.dhtCheckEnvelope(envelopeBytes)) {
                is EnvelopeCheck.Passed -> check.envelope
                is EnvelopeCheck.Failed -> {
                    logger.debug { "DHT mail envelope rejected: ${check.reason}" }
                    pending.markResolved(entry)
                    return true
                }
            }
        if (envelope.sender != entry.sender) {
            logger.debug { "DHT mail envelope is from another sender than the value that carried it - discarding" }
            pending.markResolved(entry)
            return true
        }
        if (inbox.alreadyHas(envelope)) {
            pending.markResolved(entry)
            return true
        }
        // The acceptance policy has passed: only now is the body worth downloading.
        val bodyBytes =
            try {
                fetchAttempts++
                storage.get(envelope.contentCid, peers = setOf(record.peerId), timeout = fetchTimeout)
            } catch (e: NabuStorageException) {
                null
            } ?: return true
        if (bodyBytes.size > MessageBodyCodec.MAX_BODY_BLOB_SIZE) {
            logger.debug { "DHT mail body is oversized - discarding" }
            pending.markResolved(entry)
            return true
        }
        when (inbox.dhtIngest(envelope, envelopeBytes, bodyBytes)) {
            InboxIngestOutcome.ACCEPTED, InboxIngestOutcome.DUPLICATE, InboxIngestOutcome.INVALID ->
                pending.markResolved(entry)
            InboxIngestOutcome.PERSIST_FAILED -> Unit // may succeed later
        }
        return true
    }

    private fun start() {
        scheduledTask =
            executor.scheduleWithFixedDelay(
                { runCatching { pollOnce() } },
                pollIntervalSeconds,
                pollIntervalSeconds,
                TimeUnit.SECONDS,
            )
    }

    /** Cancels the periodic task. Idempotent. */
    fun stop() {
        scheduledTask?.cancel(false)
        executor.shutdownNow()
    }

    companion object {
        const val DEFAULT_POLL_INTERVAL_SECONDS: Long = 60L
        val POLL_PASS_WALL_CLOCK_BUDGET: Duration = Duration.ofSeconds(20)
        const val MAX_FETCH_ATTEMPTS_PER_SENDER_PER_PASS: Int = 4
        val FETCH_TIMEOUT: Duration = Duration.ofSeconds(10)

        /**
         * Registers the consumer for `MAIL_POINTER` entries with [directoryDht] and starts the periodic fetch.
         * Nothing here publishes; the caller decides when [DirectoryDht.catchUp] / `discoverInbox` run.
         */
        fun attach(
            inbox: InboxGossip,
            storage: NabuStorage,
            peerDirectory: PeerDirectoryGossip,
            directoryDht: DirectoryDht,
            localIdentity: Secp256k1PublicKey,
            pollIntervalSeconds: Long = DEFAULT_POLL_INTERVAL_SECONDS,
        ): InboxDhtFetcher =
            InboxDhtFetcher(inbox, storage, peerDirectory, localIdentity, pollIntervalSeconds).also {
                directoryDht.registerOutboxConsumer(OutboxEntryKind.MAIL_POINTER, it.consumer())
                it.start()
            }
    }
}

/**
 * The queueing consumer of `MAIL_POINTER` outbox entries (V0.9.14). A class of its own so that what it must not
 * do - touch the network or the clock, it runs inside `DirectoryDht.resolve` - is checkable on its bytecode.
 */
internal class MailPointerQueueConsumer(
    private val localIdentity: Secp256k1PublicKey,
    private val pending: InboxDhtPendingIndex,
) : OutboxEntryConsumer {
    override fun onDhtOutboxEntry(
        sender: Secp256k1PublicKey,
        senderPeerId: PeerId,
        entry: OutboxEntry,
    ): OutboxIngestOutcome {
        if (entry.kind != OutboxEntryKind.MAIL_POINTER || entry.recipient != localIdentity) {
            return OutboxIngestOutcome.REJECTED
        }
        val pointer =
            try {
                MailDhtPointerCodec.decode(entry.payload)
            } catch (e: MalformedMailDhtPointerException) {
                return OutboxIngestOutcome.REJECTED
            }
        val queued =
            pending.add(
                InboxDhtPendingIndex.Entry(sender, senderPeerId, pointer.envelopeCid, entry.notValidAfterEpochSecond),
            )
        return if (queued) OutboxIngestOutcome.ACCEPTED else OutboxIngestOutcome.DUPLICATE
    }
}
