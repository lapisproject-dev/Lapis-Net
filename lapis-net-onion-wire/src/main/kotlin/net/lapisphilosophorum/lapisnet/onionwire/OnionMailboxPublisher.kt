package net.lapisphilosophorum.lapisnet.onionwire

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptor
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.onion.CellFormatException
import net.lapisphilosophorum.lapisnet.onion.CircuitPurpose
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onion.MailboxPublishBody
import net.lapisphilosophorum.lapisnet.onion.MailboxPublishStatus
import net.lapisphilosophorum.lapisnet.onion.RelayCommand
import net.lapisphilosophorum.lapisnet.onion.RelayMessage
import net.lapisphilosophorum.lapisnet.onion.StatusBody
import java.security.SecureRandom
import java.time.Clock
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

private val logger = KotlinLogging.logger {}

/**
 * Client side of sealed mailbox item publication through circuits (wave V0.10.0-F1). It builds ONE circuit (purpose
 * [CircuitPurpose.MAILBOX_PUBLISH]) that ends at a relay chosen by the caller-supplied candidate list, sends up to
 * [MAX_ITEMS_PER_CIRCUIT] items as eight fragments each, waits for one MAILBOX_PUBLISHED acknowledgement per item
 * (default 15 s overall) and closes the circuit. The relay announces the items on the shared mailbox topic, so the
 * mesh sees the relay, not this node, as the author.
 *
 * There is deliberately NO fallback to announcing from the own node: [publishItems] reports `false` and the caller
 * retries on its own schedule. A failing or refusing relay is put on an exponential backoff and another one is tried
 * (at most [maxAttempts]); announcing the same sealed item through two relays is harmless, the topic suppresses
 * duplicates. The relay learns that one circuit carried several items; it does not learn sender, recipient or content.
 * Experimental infrastructure.
 */
@ExperimentalOnionApi
class OnionMailboxPublisher internal constructor(
    private val factory: OnionCircuitFactory,
    private val paths: OnionPathProvider,
    private val publishRelays: () -> List<OnionRelayDescriptor>,
    private val buildTimeout: Duration = 20.seconds,
    private val ackTimeout: Duration = 15.seconds,
    private val maxAttempts: Int = 3,
    private val clock: Clock = Clock.systemUTC(),
    private val random: SecureRandom = SecureRandom(),
    /** A pre-built circuit for the purpose, if any (the warm pool of wave V0.10.0-H); used once, then the usual path. */
    private val prebuilt: (
        (CircuitPurpose) -> net.lapisphilosophorum.lapisnet.onionwire.anonymity.WarmCircuitPool.Prebuilt?
    )? =
        null,
) : AutoCloseable {
    private enum class Outcome { OK, RETRY }

    private class Backoff(
        val failures: Int,
        val untilMillis: Long,
    )

    private val backoff = ConcurrentHashMap<Secp256k1PublicKey, Backoff>()
    private val open = ConcurrentHashMap.newKeySet<OnionClientCircuit>()
    private val publications = AtomicInteger(0)

    @Volatile private var closed = false

    @Volatile internal var onClosed: (() -> Unit)? = null

    /** Number of circuits currently open for publishing (leak checks). */
    fun openCircuits(): Int = open.size

    /** Number of successful circuit publications so far (tests). */
    fun publicationCount(): Int = publications.get()

    /** `true` once every item was acknowledged by a relay. Never throws; never publishes from the own node. */
    fun publishItems(items: List<ByteArray>): CompletableFuture<Boolean> {
        if (closed) return CompletableFuture.completedFuture(false)
        if (items.isEmpty() ||
            items.size > MAX_ITEMS_PER_CIRCUIT ||
            items.any { it.size != MailboxPublishBody.ITEM_SIZE }
        ) {
            return CompletableFuture.completedFuture(false)
        }
        val warm = runCatching { prebuilt?.invoke(CircuitPurpose.MAILBOX_PUBLISH) }.getOrNull()
        if (warm == null || warm.circuit.isClosed) {
            warm?.let { runCatching { it.circuit.close() } }
            return publishRegular(items)
        }
        return exchange(warm.circuit, items)
            .exceptionally { Outcome.RETRY }
            .thenCompose { outcome ->
                when (outcome) {
                    Outcome.OK -> {
                        publications.incrementAndGet()
                        CompletableFuture.completedFuture(true)
                    }
                    Outcome.RETRY -> {
                        penalise(warm.lastHop.identity)
                        publishRegular(items)
                    }
                }
            }.exceptionally { false }
    }

    private fun publishRegular(items: List<ByteArray>): CompletableFuture<Boolean> {
        val now = clock.millis()
        val usable =
            try {
                publishRelays()
                    .filter { (backoff[it.identity]?.untilMillis ?: 0L) <= now }
                    .shuffled(random)
                    .take(maxAttempts)
            } catch (e: RuntimeException) {
                return CompletableFuture.completedFuture(false)
            }
        return attemptFrom(usable, 0, items).exceptionally { false }
    }

    private fun attemptFrom(
        candidates: List<OnionRelayDescriptor>,
        index: Int,
        items: List<ByteArray>,
    ): CompletableFuture<Boolean> {
        if (closed || index >= candidates.size) return CompletableFuture.completedFuture(false)
        val relay = candidates[index]
        return attempt(relay, items)
            .exceptionally { Outcome.RETRY }
            .thenCompose { outcome ->
                when (outcome) {
                    Outcome.OK -> {
                        backoff.remove(relay.identity)
                        publications.incrementAndGet()
                        CompletableFuture.completedFuture(true)
                    }
                    Outcome.RETRY -> {
                        penalise(relay.identity)
                        attemptFrom(candidates, index + 1, items)
                    }
                }
            }
    }

    private fun penalise(relay: Secp256k1PublicKey) {
        val now = clock.millis()
        backoff.compute(relay) { _, old ->
            val failures = (old?.failures ?: 0) + 1
            Backoff(failures, now + (BASE_BACKOFF_MILLIS shl minOf(failures - 1, MAX_BACKOFF_SHIFT)))
        }
    }

    private fun attempt(
        relay: OnionRelayDescriptor,
        items: List<ByteArray>,
    ): CompletableFuture<Outcome> {
        val path =
            try {
                paths.pathEndingAt(relay, CircuitPurpose.MAILBOX_PUBLISH)
            } catch (e: RuntimeException) {
                return CompletableFuture.completedFuture(Outcome.RETRY)
            }
        return factory.build(path, buildTimeout, CircuitPurpose.MAILBOX_PUBLISH).thenCompose { circuit ->
            exchange(circuit, items)
        }
    }

    private fun exchange(
        circuit: OnionClientCircuit,
        items: List<ByteArray>,
    ): CompletableFuture<Outcome> {
        open += circuit
        if (closed) {
            open -= circuit
            circuit.close()
            return CompletableFuture.completedFuture(Outcome.RETRY)
        }
        val done = CompletableFuture<Boolean>()
        val acks = AtomicInteger(0)
        circuit.onInbound = { msg ->
            if (msg.command == RelayCommand.MAILBOX_PUBLISHED) {
                try {
                    if (StatusBody.decode(msg.data) == MailboxPublishStatus.ACCEPTED) {
                        if (acks.incrementAndGet() == items.size) done.complete(true)
                    } else {
                        done.complete(false)
                    }
                } catch (e: CellFormatException) {
                    done.completeExceptionally(e)
                }
            }
        }
        circuit.onClosed = { done.completeExceptionally(IllegalStateException("circuit closed")) }
        for ((itemIndex, item) in items.withIndex()) {
            for (body in MailboxPublishBody.encodeItem(itemIndex, item)) {
                if (!circuit.send(RelayMessage(RelayCommand.MAILBOX_PUBLISH, 0, body))) {
                    open -= circuit
                    circuit.close()
                    return CompletableFuture.completedFuture(Outcome.RETRY)
                }
            }
        }
        return done
            .orTimeout(ackTimeout.inWholeMilliseconds, TimeUnit.MILLISECONDS)
            .handle { ok, error ->
                open -= circuit
                circuit.close()
                if (error != null || ok != true) Outcome.RETRY else Outcome.OK
            }
    }

    override fun close() {
        if (closed) return
        closed = true
        open.toList().forEach { runCatching { it.close() } }
        open.clear()
        runCatching { onClosed?.invoke() }
        logger.debug { "mailbox publisher closed" }
    }

    companion object {
        const val MAX_ITEMS_PER_CIRCUIT = 4
        private const val BASE_BACKOFF_MILLIS = 30_000L
        private const val MAX_BACKOFF_SHIFT = 4
    }
}
