package net.lapisphilosophorum.lapisnet.onionwire

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.directory.AnonymousPeerRecord
import net.lapisphilosophorum.lapisnet.directory.AnonymousPeerRecordCodec
import net.lapisphilosophorum.lapisnet.directory.DirectoryPublicationChannel
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptor
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.onion.CellFormatException
import net.lapisphilosophorum.lapisnet.onion.CircuitPurpose
import net.lapisphilosophorum.lapisnet.onion.DirectoryObjectType
import net.lapisphilosophorum.lapisnet.onion.DirectoryPublishBody
import net.lapisphilosophorum.lapisnet.onion.DirectoryPublishStatus
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptor
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptorCodec
import net.lapisphilosophorum.lapisnet.onion.RelayCommand
import net.lapisphilosophorum.lapisnet.onion.RelayMessage
import net.lapisphilosophorum.lapisnet.onion.StatusBody
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundle
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundleCodec
import java.security.SecureRandom
import java.time.Clock
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

private val logger = KotlinLogging.logger {}

/**
 * Client side of directory publication through circuits (wave V0.10.0-D): builds a circuit over a path supplied by the
 * [OnionPathProvider] (purpose [CircuitPurpose.DIRECTORY_PUBLISH]) that ends at a publish relay, sends ONE
 * DIRECTORY_PUBLISH message, waits for the acknowledgement (default 15 s) and closes the circuit. The relay announces
 * the object on the directory gossip, so the mesh sees the relay, not this node, as the publisher.
 *
 * Failure handling: another relay is tried (at most [maxAttempts]), a failing relay is put on an exponential backoff.
 * There is deliberately NO fallback to publishing from the own node: [exposesOrigin] is `false` and stays so; a
 * failed publication is reported as `false` and the caller retries later. A relay that answers `INVALID` or
 * `MALFORMED` is not asked again for the same object (the object, not the relay, is the problem); `RATE_LIMITED` and
 * `UNKNOWN_TYPE` (a relay without a directory sink) move on to the next relay.
 *
 * What it does NOT do: no path selection (the provider decides), no anonymity of the relay (it sees the clear object,
 * which is public by nature), no DHT publication (see docs/anonymity.adoc). Experimental infrastructure.
 */
@ExperimentalOnionApi
class OnionDirectoryPublisher internal constructor(
    private val factory: OnionCircuitFactory,
    private val paths: OnionPathProvider,
    private val publishRelays: () -> List<OnionRelayDescriptor>,
    private val buildTimeout: Duration = 20.seconds,
    private val ackTimeout: Duration = 15.seconds,
    private val maxAttempts: Int = 3,
    private val clock: Clock = Clock.systemUTC(),
    private val random: SecureRandom = SecureRandom(),
) : DirectoryPublicationChannel,
    AutoCloseable {
    private enum class Outcome { OK, REJECTED, RETRY }

    private class Backoff(
        val failures: Int,
        val untilMillis: Long,
    )

    private val backoff = ConcurrentHashMap<Secp256k1PublicKey, Backoff>()
    private val open = ConcurrentHashMap.newKeySet<OnionClientCircuit>()

    @Volatile private var closed = false

    @Volatile internal var onClosed: (() -> Unit)? = null

    override val exposesOrigin: Boolean get() = false

    /** Number of circuits currently open for publishing (leak checks). */
    fun openCircuits(): Int = open.size

    override fun publishAnonymousPeerRecord(record: AnonymousPeerRecord): CompletableFuture<Boolean> =
        publish(DirectoryObjectType.ANONYMOUS_PEER_RECORD, AnonymousPeerRecordCodec.encode(record))

    override fun publishPrekeyBundle(bundle: PrekeyBundle): CompletableFuture<Boolean> =
        publish(DirectoryObjectType.PREKEY_BUNDLE, PrekeyBundleCodec.encode(bundle))

    override fun publishServiceDescriptor(descriptor: OnionServiceDescriptor): CompletableFuture<Boolean> =
        publish(DirectoryObjectType.ONION_SERVICE_DESCRIPTOR, OnionServiceDescriptorCodec.encode(descriptor))

    private fun publish(
        type: DirectoryObjectType,
        bytes: ByteArray,
    ): CompletableFuture<Boolean> {
        if (closed) return CompletableFuture.completedFuture(false)
        if (bytes.size > DirectoryPublishBody.MAX_OBJECT_SIZE) {
            logger.debug { "directory object of type $type does not fit one publish message" }
            return CompletableFuture.completedFuture(false)
        }
        val now = clock.millis()
        val usable =
            publishRelays()
                .filter { (backoff[it.identity]?.untilMillis ?: 0L) <= now }
                .shuffled(random)
                .take(maxAttempts)
        return attemptFrom(usable, 0, type, bytes).exceptionally { false }
    }

    private fun attemptFrom(
        candidates: List<OnionRelayDescriptor>,
        index: Int,
        type: DirectoryObjectType,
        bytes: ByteArray,
    ): CompletableFuture<Boolean> {
        if (closed || index >= candidates.size) return CompletableFuture.completedFuture(false)
        val relay = candidates[index]
        return attempt(relay, type, bytes)
            .exceptionally { Outcome.RETRY }
            .thenCompose { outcome ->
                when (outcome) {
                    Outcome.OK -> {
                        backoff.remove(relay.identity)
                        CompletableFuture.completedFuture(true)
                    }
                    Outcome.REJECTED -> CompletableFuture.completedFuture(false)
                    Outcome.RETRY -> {
                        penalise(relay.identity)
                        attemptFrom(candidates, index + 1, type, bytes)
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
        type: DirectoryObjectType,
        bytes: ByteArray,
    ): CompletableFuture<Outcome> {
        val path =
            try {
                paths.pathEndingAt(relay, CircuitPurpose.DIRECTORY_PUBLISH)
            } catch (e: RuntimeException) {
                return CompletableFuture.completedFuture(Outcome.RETRY)
            }
        return factory.build(path, buildTimeout, CircuitPurpose.DIRECTORY_PUBLISH).thenCompose { circuit ->
            exchange(circuit, type, bytes)
        }
    }

    private fun exchange(
        circuit: OnionClientCircuit,
        type: DirectoryObjectType,
        bytes: ByteArray,
    ): CompletableFuture<Outcome> {
        open += circuit
        if (closed) {
            open -= circuit
            circuit.close()
            return CompletableFuture.completedFuture(Outcome.RETRY)
        }
        val ack = CompletableFuture<Byte>()
        circuit.onInbound = { msg ->
            if (msg.command == RelayCommand.DIRECTORY_PUBLISHED) {
                try {
                    ack.complete(StatusBody.decode(msg.data))
                } catch (e: CellFormatException) {
                    ack.completeExceptionally(e)
                }
            }
        }
        circuit.onClosed = { ack.completeExceptionally(IllegalStateException("circuit closed")) }
        val body = DirectoryPublishBody.encode(type, bytes, random)
        if (!circuit.send(RelayMessage(RelayCommand.DIRECTORY_PUBLISH, 0, body))) {
            open -= circuit
            circuit.close()
            return CompletableFuture.completedFuture(Outcome.RETRY)
        }
        return ack
            .orTimeout(ackTimeout.inWholeMilliseconds, TimeUnit.MILLISECONDS)
            .handle { status, error ->
                open -= circuit
                circuit.close()
                when {
                    error != null || status == null -> Outcome.RETRY
                    status == DirectoryPublishStatus.ACCEPTED -> Outcome.OK
                    // a relay without a directory sink answers UNKNOWN_TYPE: the relay, not the object, is the problem
                    status == DirectoryPublishStatus.RATE_LIMITED ||
                        status == DirectoryPublishStatus.UNKNOWN_TYPE -> Outcome.RETRY
                    else -> Outcome.REJECTED
                }
            }
    }

    override fun close() {
        if (closed) return
        closed = true
        open.toList().forEach { runCatching { it.close() } }
        open.clear()
        runCatching { onClosed?.invoke() }
    }

    private companion object {
        const val BASE_BACKOFF_MILLIS = 30_000L
        const val MAX_BACKOFF_SHIFT = 4
    }
}
