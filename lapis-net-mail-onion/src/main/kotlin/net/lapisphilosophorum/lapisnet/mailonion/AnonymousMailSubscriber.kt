package net.lapisphilosophorum.lapisnet.mailonion

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.directory.AnonymousMailboxGossip
import net.lapisphilosophorum.lapisnet.directory.SealedMailboxBox
import net.lapisphilosophorum.lapisnet.directory.SealedMailboxKind
import net.lapisphilosophorum.lapisnet.identity.X25519PrivateKey
import net.lapisphilosophorum.lapisnet.mail.AnonymousMailInboundSink
import java.time.Clock
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

private val logger = KotlinLogging.logger {}

/**
 * The offline half of mail over circuits (wave V0.10.0-F2): every sealed item that passed the shared topic's validator is
 * tried against the node's own sealing key; only an unexpired item of kind MAIL addressed to us opens, everything else
 * (other recipients, direct-message items, garbage) is dropped silently. The attempts run on a bounded single-thread
 * executor, so a flood on the topic can at worst fill that queue (excess is dropped and counted). The sealing key is
 * requested per attempt and destroyed right after. The opened frame goes through the same [AnonymousMailInboundSink] as
 * a stream delivery, so the acceptance policy is applied identically.
 */
class AnonymousMailSubscriber private constructor(
    private val sink: AnonymousMailInboundSink,
    private val ownSealingKey: () -> X25519PrivateKey,
    private val clock: Clock,
    queueCapacity: Int,
) : AutoCloseable {
    @Volatile private var handle: AutoCloseable? = null
    private val dropped = AtomicLong(0)
    private val tried = AtomicLong(0)
    private val executor =
        ThreadPoolExecutor(
            1,
            1,
            0,
            TimeUnit.SECONDS,
            ArrayBlockingQueue(queueCapacity),
            { r -> Thread(r, "lapis-net-mail-onion-mailbox").apply { isDaemon = true } },
        )

    /** Items dropped because the work queue was full. */
    fun droppedCount(): Long = dropped.get()

    /** Items tried against the own key so far. */
    fun triedCount(): Long = tried.get()

    internal fun offer(item: ByteArray) {
        try {
            executor.execute {
                tried.incrementAndGet()
                var key: X25519PrivateKey? = null
                var payload: ByteArray? = null
                try {
                    key = ownSealingKey()
                    payload = SealedMailboxBox.open(item, key, clock.millis() / 1000, SealedMailboxKind.MAIL)
                    if (payload != null) sink.acceptAnonymousMail(payload, emptyList())
                } catch (e: RuntimeException) {
                    logger.debug { "mailbox item handling failed (${e.javaClass.simpleName})" }
                } finally {
                    payload?.fill(0)
                    key?.destroy()
                }
            }
        } catch (e: RejectedExecutionException) {
            dropped.incrementAndGet()
        }
    }

    override fun close() {
        handle?.close()
        executor.shutdownNow()
    }

    override fun toString(): String = "AnonymousMailSubscriber(REDACTED)"

    companion object {
        const val QUEUE_CAPACITY = 64

        fun attach(
            gossip: AnonymousMailboxGossip,
            ownSealingKey: () -> X25519PrivateKey,
            sink: AnonymousMailInboundSink,
            clock: Clock = Clock.systemUTC(),
            queueCapacity: Int = QUEUE_CAPACITY,
        ): AnonymousMailSubscriber {
            val subscriber = AnonymousMailSubscriber(sink, ownSealingKey, clock, queueCapacity)
            subscriber.handle = gossip.addConsumer(subscriber::offer)
            return subscriber
        }
    }
}
