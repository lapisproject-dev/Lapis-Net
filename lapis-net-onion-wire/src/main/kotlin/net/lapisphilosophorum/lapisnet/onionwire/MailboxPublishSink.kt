package net.lapisphilosophorum.lapisnet.onionwire

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.directory.AnonymousMailboxGossip
import net.lapisphilosophorum.lapisnet.onion.MailboxPublishStatus

private val logger = KotlinLogging.logger {}

/**
 * What a relay does with a sealed mailbox item that a client handed to it through a circuit (wave V0.10.0-F1).
 * Returns the MAILBOX_PUBLISHED status byte ([MailboxPublishStatus]). Runs on a pool thread, never on a link event loop.
 */
fun interface MailboxPublishSink {
    fun publish(itemBytes: ByteArray): Byte
}

/**
 * The production sink: announces the item on the shared mailbox topic so that the relay (not the client) is the
 * author the mesh sees. The relay cannot read the item and checks only its size (the reassembly already guarantees
 * it). The answer is the same for every item that reached the topic code: no oracle about duplicates or budgets,
 * which the gossip validators decide silently.
 */
internal class GossipMailboxPublishSink(
    private val gossip: AnonymousMailboxGossip,
) : MailboxPublishSink {
    override fun publish(itemBytes: ByteArray): Byte =
        try {
            gossip.publish(itemBytes)
            MailboxPublishStatus.ACCEPTED
        } catch (e: RuntimeException) {
            logger.debug { "mailbox publish failed (${e.javaClass.simpleName})" }
            MailboxPublishStatus.RATE_LIMITED
        }
}
