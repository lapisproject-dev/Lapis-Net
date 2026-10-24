package net.lapisphilosophorum.lapisnet.dmonion

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.directory.AnonymousMailboxGossip
import net.lapisphilosophorum.lapisnet.dm.DmInboundSink
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

private val logger = KotlinLogging.logger {}

/**
 * The receiving side of the anonymity-mode offline mailbox (wave V0.10.0-F1): every sealed item that passed the shared
 * topic's validator (size, relay author, duplicates, budget) is tried against the node's own sealing key by the
 * [DmInboundSink]; an item for someone else simply does not open and is dropped without a trace. The attempts run on a
 * small bounded executor, so a flood on the topic can at worst fill that queue (excess is dropped and counted), never
 * stall gossip. The topic's global budget (120 items per minute) bounds the decryption work further.
 *
 * Subscribing to the shared topic only reveals "anonymity mode is on", which the node's public record shows anyway.
 */
class AnonymousMailboxSubscriber private constructor(
    private val gossip: AnonymousMailboxGossip,
    private val sink: DmInboundSink,
    queueCapacity: Int,
) : AutoCloseable {
    @Volatile
    private var handle: AutoCloseable? = null
    private val dropped = AtomicLong(0)
    private val tried = AtomicLong(0)
    private val executor =
        ThreadPoolExecutor(
            1,
            1,
            0,
            TimeUnit.SECONDS,
            ArrayBlockingQueue(queueCapacity),
            { r -> Thread(r, "lapis-net-dm-onion-mailbox").apply { isDaemon = true } },
        )

    /** Items dropped because the work queue was full. */
    fun droppedCount(): Long = dropped.get()

    /** Items tried against the own key so far. */
    fun triedCount(): Long = tried.get()

    private fun offer(item: ByteArray) {
        try {
            executor.execute {
                tried.incrementAndGet()
                try {
                    sink.acceptSealedMailboxItem(item)
                } catch (e: RuntimeException) {
                    logger.debug { "mailbox item handling failed (${e.javaClass.simpleName})" }
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

    companion object {
        const val QUEUE_CAPACITY = 64

        fun attach(
            gossip: AnonymousMailboxGossip,
            sink: DmInboundSink,
            queueCapacity: Int = QUEUE_CAPACITY,
        ): AnonymousMailboxSubscriber {
            val subscriber = AnonymousMailboxSubscriber(gossip, sink, queueCapacity)
            subscriber.handle = gossip.addConsumer(subscriber::offer)
            return subscriber
        }
    }
}
