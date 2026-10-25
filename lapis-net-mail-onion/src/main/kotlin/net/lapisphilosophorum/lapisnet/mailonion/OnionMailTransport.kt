package net.lapisphilosophorum.lapisnet.mailonion

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.directory.AnonymousCapability
import net.lapisphilosophorum.lapisnet.directory.DirectoryReachability
import net.lapisphilosophorum.lapisnet.directory.SealedMailboxKind
import net.lapisphilosophorum.lapisnet.dmonion.AnonymousMailboxRedelivery
import net.lapisphilosophorum.lapisnet.dmonion.DmFramingException
import net.lapisphilosophorum.lapisnet.dmonion.FrameChannel
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.identity.X25519PublicKey
import net.lapisphilosophorum.lapisnet.mail.AnonymousMailSizeClass
import net.lapisphilosophorum.lapisnet.mail.AnonymousMailSizing
import net.lapisphilosophorum.lapisnet.mail.AnonymousMailTransport
import net.lapisphilosophorum.lapisnet.mail.MailAnonymousDeliveryException
import net.lapisphilosophorum.lapisnet.mail.MailAnonymousFailure
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptor
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundle
import java.time.Clock
import java.time.Duration
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

private val logger = KotlinLogging.logger {}

/**
 * [AnonymousMailTransport] over onion circuits (wave V0.10.0-F2).
 *
 * [preflight] looks every recipient up in the local anonymous directory only (never the DHT) and answers with ONE refusal
 * for every way a recipient can be unreachable anonymously (unknown, direct mode, revoked, no MAIL capability, no prekey
 * bundle), with no silent fallback to the direct path; the size rules are checked in the same call, before any network step.
 * [deliver] works per recipient on a small bounded executor: a recipient with a published onion service gets the bundle on a
 * NEW circuit (one circuit per delivery, no stream cache, mail is rare and this keeps deliveries unlinkable), acknowledged by
 * a constant byte. When that fails, or the recipient has no descriptor yet, a small mail (INLINE) becomes a sealed mailbox
 * item announced again and again by the shared [AnonymousMailboxRedelivery], and a bundle with attachments (CIRCUIT) goes
 * into the [OnionMailRetryQueue]. Nothing here logs an address, key, id or subject.
 *
 * [ownIdentity] is skipped as a recipient (no network self-delivery, as on the direct path).
 */
class OnionMailTransport(
    private val port: OnionMailRuntimePort,
    private val ownIdentity: Secp256k1PublicKey,
    private val bundleLookup: (Secp256k1PublicKey) -> PrekeyBundle?,
    private val redelivery: AnonymousMailboxRedelivery,
    private val retryQueue: OnionMailRetryQueue,
    private val clock: Clock = Clock.systemUTC(),
    private val connectTimeout: Duration = Duration.ofSeconds(25),
    private val deliveryTimeout: Duration = Duration.ofSeconds(120),
    private val lifetimeSeconds: Long = LIFETIME_SECONDS,
    executorThreads: Int = EXECUTOR_THREADS,
    executorQueue: Int = EXECUTOR_QUEUE,
) : AnonymousMailTransport {
    private class Target(
        val recipient: Secp256k1PublicKey,
        val sealingKey: X25519PublicKey,
        val descriptor: OnionServiceDescriptor?,
    )

    private val closed = AtomicBoolean(false)
    private val queuedDirectly = AtomicLong(0)
    private val executor =
        ThreadPoolExecutor(
            executorThreads,
            executorThreads,
            0,
            TimeUnit.SECONDS,
            ArrayBlockingQueue(executorQueue),
            { r -> Thread(r, "lapis-net-mail-onion-send").apply { isDaemon = true } },
        )

    init {
        retryQueue.start { recipient, bundle -> retryAttempt(recipient, bundle) }
    }

    /** Deliveries that skipped the online attempt because the executor was busy (tests, diagnostics). */
    fun queuedDirectlyCount(): Long = queuedDirectly.get()

    private fun fail(failure: MailAnonymousFailure): Nothing = throw MailAnonymousDeliveryException(failure)

    private fun unreachable(): Nothing {
        runCatching { port.recordRecipientUnreachable() }
        fail(MailAnonymousFailure.RECIPIENT_NOT_REACHABLE_ANONYMOUSLY)
    }

    /** `null` for every way a recipient is not reachable anonymously (the callers turn it into the one refusal). */
    private fun resolve(recipient: Secp256k1PublicKey): Target? {
        val reachability =
            try {
                port.resolveIdentity(recipient)
            } catch (e: RuntimeException) {
                return null
            }
        val bundle = bundleLookup(recipient) ?: return null
        return when (reachability) {
            is DirectoryReachability.Hidden ->
                if (AnonymousCapability.MAIL !in reachability.record.capabilities) {
                    null
                } else {
                    Target(recipient, bundle.x25519IdentityKey, reachability.descriptor)
                }
            is DirectoryReachability.HiddenDescriptorMissing ->
                if (AnonymousCapability.MAIL !in reachability.record.capabilities) {
                    null
                } else {
                    Target(recipient, bundle.x25519IdentityKey, null)
                }
            // direct-mode, revoked and unknown recipients are all the same answer, and there is no fallback
            is DirectoryReachability.Direct,
            DirectoryReachability.Revoked,
            DirectoryReachability.Unknown,
            -> null
        }
    }

    override fun preflight(
        recipients: List<Secp256k1PublicKey>,
        frameBytes: Int,
        attachmentBlobSizes: List<Int>,
    ): AnonymousMailSizeClass {
        if (closed.get() || !port.ready()) fail(MailAnonymousFailure.ANONYMITY_NOT_READY)
        val sizeClass = AnonymousMailSizing.classify(frameBytes, attachmentBlobSizes)
        for (recipient in recipients.filter { it != ownIdentity }.distinct()) {
            if (resolve(recipient) == null) unreachable()
        }
        return sizeClass
    }

    override fun deliver(
        recipients: List<Secp256k1PublicKey>,
        frameBytes: ByteArray,
        attachmentBlobs: List<ByteArray>,
        sizeClass: AnonymousMailSizeClass,
    ) {
        if (closed.get()) fail(MailAnonymousFailure.ANONYMITY_NOT_READY)
        require(
            sizeClass == AnonymousMailSizeClass.CIRCUIT || attachmentBlobs.isEmpty(),
        ) { "INLINE mail has no attachments" }
        val bundle = MailCircuitBundleCodec.encode(frameBytes, attachmentBlobs)
        val notValidAfter = clock.millis() / 1000 + lifetimeSeconds
        for (recipient in recipients.filter { it != ownIdentity }.distinct()) {
            val job = { deliverTo(recipient, frameBytes, bundle, sizeClass, notValidAfter) }
            try {
                executor.execute {
                    runCatching(
                        job,
                    ).onFailure { logger.debug { "mail delivery failed (${it.javaClass.simpleName})" } }
                }
            } catch (e: RejectedExecutionException) {
                // busy: skip the online attempt and let the offline path / retry queue carry it
                queuedDirectly.incrementAndGet()
                enqueue(
                    recipient,
                    resolve(recipient),
                    frameBytes,
                    bundle,
                    sizeClass,
                    notValidAfter,
                    firstDelayMillis = RETRY_SOON_MILLIS,
                )
            }
        }
    }

    private fun deliverTo(
        recipient: Secp256k1PublicKey,
        frame: ByteArray,
        bundle: ByteArray,
        sizeClass: AnonymousMailSizeClass,
        notValidAfter: Long,
    ) {
        if (closed.get()) return
        val target = resolve(recipient)
        val descriptor = target?.descriptor
        if (descriptor != null && sendBundle(descriptor, bundle)) return
        enqueue(
            recipient,
            target,
            frame,
            bundle,
            sizeClass,
            notValidAfter,
            firstDelayMillis =
                if (descriptor !=
                    null
                ) {
                    null
                } else {
                    RETRY_SOON_MILLIS
                },
        )
    }

    private fun enqueue(
        recipient: Secp256k1PublicKey,
        target: Target?,
        frame: ByteArray,
        bundle: ByteArray,
        sizeClass: AnonymousMailSizeClass,
        notValidAfter: Long,
        firstDelayMillis: Long?,
    ) {
        when (sizeClass) {
            AnonymousMailSizeClass.INLINE -> {
                val sealingKey = target?.sealingKey ?: bundleLookup(recipient)?.x25519IdentityKey
                if (sealingKey == null) {
                    logger.debug { "mail dropped: recipient bundle vanished" }
                    return
                }
                redelivery.add(recipient, sealingKey, frame, notValidAfter, SealedMailboxKind.MAIL)
            }
            AnonymousMailSizeClass.CIRCUIT ->
                if (firstDelayMillis == null) {
                    retryQueue.add(recipient, bundle, notValidAfter)
                } else {
                    retryQueue.add(recipient, bundle, notValidAfter, firstDelayMillis)
                }
        }
    }

    /** One retry of the queue: look the recipient up again (the descriptor may be new) and try the stream. */
    private fun retryAttempt(
        recipient: Secp256k1PublicKey,
        bundle: ByteArray,
    ): Boolean {
        if (closed.get() || !port.ready()) return false
        val descriptor = resolve(recipient)?.descriptor ?: return false
        return sendBundle(descriptor, bundle)
    }

    /** One bundle, one new circuit, one constant acknowledgement; the circuit is always closed afterwards. */
    private fun sendBundle(
        descriptor: OnionServiceDescriptor,
        bundle: ByteArray,
    ): Boolean {
        var channel: FrameChannel? = null
        var pending: CompletableFuture<FrameChannel>? = null
        try {
            val future = port.connect(descriptor, connectTimeout)
            pending = future
            channel = future.get(connectTimeout.toMillis() + 1000, TimeUnit.MILLISECONDS)
        } catch (e: ExecutionException) {
            logger.debug {
                "mail stream could not be opened (${generateSequence<Throwable>(
                    e,
                ) { it.cause }.last().javaClass.simpleName})"
            }
        } catch (e: TimeoutException) {
            logger.debug { "mail stream could not be opened (timeout)" }
        } catch (e: RuntimeException) {
            logger.debug { "mail stream could not be opened (${e.javaClass.simpleName})" }
        } finally {
            if (channel == null) {
                // an abandoned connect that still completes later must not leak its stream and circuit
                pending?.whenComplete { ch, _ -> if (ch != null) runCatching { ch.close() } }
            }
        }
        val opened = channel ?: return false
        try {
            val ack = CompletableFuture<Boolean>()
            val reader = MailCircuitFraming.ackReader(clock::millis)
            opened.onReceive { chunk ->
                try {
                    reader.feed(chunk) { _, _ -> ack.complete(true) }
                } catch (e: DmFramingException) {
                    ack.complete(false)
                }
            }
            opened.onClose { ack.complete(false) }
            val frame =
                if (port.paddingEnabled) {
                    if (bundle.size > MailCircuitFraming.MAX_FRAME_BYTES) return false
                    MailCircuitFraming.paddedBundleFrame(bundle, opened.maxPayload)
                } else {
                    MailCircuitFraming.bundleFrame(bundle)
                }
            for (chunk in MailCircuitFraming.chunks(frame, opened.maxPayload)) {
                if (!opened.send(chunk)) return false
            }
            return ack.get(deliveryTimeout.toMillis(), TimeUnit.MILLISECONDS)
        } catch (e: TimeoutException) {
            return false
        } catch (e: ExecutionException) {
            return false
        } catch (e: RuntimeException) {
            return false
        } finally {
            runCatching { opened.close() }
        }
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        executor.shutdownNow()
        retryQueue.close()
        // the shared redelivery queue is owned (and closed) by its creator, not by one of its two users
    }

    override fun toString(): String = "OnionMailTransport(REDACTED)"

    companion object {
        const val LIFETIME_SECONDS = 48L * 3600
        const val EXECUTOR_THREADS = 2
        const val EXECUTOR_QUEUE = 16
        const val RETRY_SOON_MILLIS = 60_000L
    }
}
