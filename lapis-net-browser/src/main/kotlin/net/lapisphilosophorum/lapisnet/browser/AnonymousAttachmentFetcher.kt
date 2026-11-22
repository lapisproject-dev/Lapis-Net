package net.lapisphilosophorum.lapisnet.browser

import io.github.oshai.kotlinlogging.KotlinLogging
import io.ipfs.cid.Cid
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.future.await
import kotlinx.coroutines.withContext
import net.lapisphilosophorum.lapisnet.dmonion.attachment.AnonymousAttachmentLimits
import net.lapisphilosophorum.lapisnet.dmonion.attachment.AttachmentFetchClient
import net.lapisphilosophorum.lapisnet.dmonion.attachment.AttachmentFetchFailure
import net.lapisphilosophorum.lapisnet.dmonion.attachment.AttachmentFetchResult
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.storage.LookupLimits
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.util.concurrent.Semaphore
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlin.time.toJavaDuration

private val logger = KotlinLogging.logger {}

/** What [AnonymousAttachmentFetcher] needs of the blockstore (a seam for tests). */
interface AttachmentBlobStore {
    /** The local stores (served and unserved); no network. */
    fun getLocal(cid: Cid): ByteArray?

    /** Stores a verified blob in the store that is never served or announced. */
    fun putUnserved(bytes: ByteArray)

    /** The local stores, then one MAILBOX lookup through a circuit (anonymity mode only); blocks up to [timeout]. */
    fun getThroughRemote(
        cid: Cid,
        timeout: Duration,
    ): ByteArray?
}

/** [AttachmentBlobStore] over [NabuStorage]. */
class NabuAttachmentBlobStore(
    private val storage: NabuStorage,
) : AttachmentBlobStore {
    override fun getLocal(cid: Cid): ByteArray? = storage.getLocal(cid)

    override fun putUnserved(bytes: ByteArray) {
        storage.putUnserved(bytes)
    }

    override fun getThroughRemote(
        cid: Cid,
        timeout: Duration,
    ): ByteArray? = storage.getThroughRemote(cid, timeout.toJavaDuration())
}

/**
 * The anonymity-mode download of an attachment blob that is not local (wave Q21, unreleased, design not confirmed by
 * the user). Order: the local stores; then the sender's onion service ([AttachmentFetchClient], only with an attachment
 * key, because the key makes the fetch token); then, only when the sender's service was not reachable and the blob fits
 * one lookup ([LookupLimits.MAX_CONTENT]), one MAILBOX lookup through a circuit (decision Q21-B: best effort, it finds
 * only what a node in normal mode happens to announce; the exit relay sees the CID of the encrypted blob and the time).
 *
 * At most [maxConcurrent] fetches run at once (more: [Outcome.Busy], answered `rate-limited`). A verified blob is stored
 * unserved, so a second download is local and the blob is never provided, not even after a switch to normal mode.
 * Blocking work runs on [io]; cancelling the calling coroutine cancels the fetch, which closes its stream. Nothing logged
 * names a CID, a sender or a key. There is never a direct connection: no path here dials a peer.
 */
class AnonymousAttachmentFetcher(
    private val store: AttachmentBlobStore,
    private val client: () -> AttachmentFetchClient?,
    maxConcurrent: Int = 2,
    private val lookupFallbackTimeout: Duration = 60.seconds,
    private val io: CoroutineDispatcher = Dispatchers.IO,
) {
    init {
        require(maxConcurrent > 0) { "maxConcurrent must be positive" }
        require(lookupFallbackTimeout.isPositive()) { "lookupFallbackTimeout must be positive" }
    }

    private val slots = Semaphore(maxConcurrent)

    sealed interface Outcome {
        class Bytes(
            bytes: ByteArray,
        ) : Outcome {
            private val stored = bytes.copyOf()
            val bytes: ByteArray get() = stored.copyOf()

            override fun toString(): String = "Bytes(REDACTED)"
        }

        data object NotReady : Outcome

        data object Unavailable : Outcome

        data object Timeout : Outcome

        data object TooLarge : Outcome

        data object Busy : Outcome
    }

    /**
     * The blob for [cid], fetched from [sender] if it is not local. [attachmentKey] `null` (an unencrypted mail
     * attachment) means no network at all. [maxBytes] is the largest blob the caller accepts; above
     * [AnonymousAttachmentLimits.MAX_BLOB_BYTES] nothing is fetched ([Outcome.TooLarge]).
     */
    suspend fun fetch(
        sender: Secp256k1PublicKey,
        cid: Cid,
        attachmentKey: ByteArray?,
        maxBytes: Int,
    ): Outcome =
        withContext(io) {
            runCatching { store.getLocal(cid) }.getOrNull()?.let { return@withContext Outcome.Bytes(it) }
            if (attachmentKey == null) return@withContext Outcome.Unavailable
            if (maxBytes < 1) return@withContext Outcome.Unavailable
            if (maxBytes > AnonymousAttachmentLimits.MAX_BLOB_BYTES) return@withContext Outcome.TooLarge
            if (!slots.tryAcquire()) return@withContext Outcome.Busy
            try {
                val active = client() ?: return@withContext Outcome.NotReady
                val result = active.fetch(sender, cid, attachmentKey, maxBytes).await()
                when (result) {
                    is AttachmentFetchResult.Found -> {
                        val bytes = result.bytes
                        runCatching { store.putUnserved(bytes) }
                            .onFailure {
                                logger.debug { "could not store a fetched attachment (${it.javaClass.simpleName})" }
                            }
                        Outcome.Bytes(bytes)
                    }
                    AttachmentFetchResult.NotFound -> Outcome.Unavailable
                    is AttachmentFetchResult.Unavailable ->
                        when (result.reason) {
                            AttachmentFetchFailure.NOT_READY -> Outcome.NotReady
                            AttachmentFetchFailure.TIMEOUT -> Outcome.Timeout
                            AttachmentFetchFailure.TOO_LARGE -> Outcome.TooLarge
                            AttachmentFetchFailure.RATE_LIMITED -> Outcome.Busy
                            AttachmentFetchFailure.MANIPULATED -> Outcome.Unavailable
                            AttachmentFetchFailure.NOT_REACHABLE,
                            AttachmentFetchFailure.CLOSED,
                            -> lookupFallback(cid, maxBytes)
                        }
                }
            } finally {
                slots.release()
            }
        }

    /** Decision Q21-B: the last resort, only for a blob that fits one lookup answer. */
    private fun lookupFallback(
        cid: Cid,
        maxBytes: Int,
    ): Outcome {
        if (maxBytes > LookupLimits.MAX_CONTENT) return Outcome.Unavailable
        val bytes = runCatching { store.getThroughRemote(cid, lookupFallbackTimeout) }.getOrNull()
        return if (bytes != null && bytes.size <= maxBytes) Outcome.Bytes(bytes) else Outcome.Unavailable
    }
}
