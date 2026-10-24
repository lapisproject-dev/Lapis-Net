package net.lapisphilosophorum.lapisnet.directory

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import java.util.concurrent.atomic.AtomicInteger

/** The shared topic serves the direct-message and the mail subscriber at once. */
class AnonymousMailboxGossipConsumersTest :
    FunSpec({
        fun withGossip(block: (AnonymousMailboxGossip, GossipPubSub) -> Unit) {
            val node = LapisNode.create(DualKeyIdentity.generate())
            node.start(bootstrapPeers = emptyList())
            try {
                val pubsub = GossipPubSub.attach(node)
                val gossip = AnonymousMailboxGossip.attach(pubsub, OnionRelayDescriptorIndex())
                try {
                    block(gossip, pubsub)
                } finally {
                    runCatching { gossip.stop() } // some tests stop it themselves
                    pubsub.stop()
                }
            } finally {
                node.stop()
            }
        }

        test("two consumers both receive an item; a failing consumer does not disturb the other") {
            withGossip { gossip, _ ->
                val a = AtomicInteger()
                val b = AtomicInteger()
                gossip.addConsumer { a.incrementAndGet() }
                gossip.addConsumer { throw IllegalStateException("boom") }
                gossip.addConsumer { b.incrementAndGet() }
                gossip.dispatch(ByteArray(AnonymousMailboxGossip.ITEM_SIZE))
                a.get() shouldBe 1
                b.get() shouldBe 1
            }
        }

        test("closing the handle removes only that consumer") {
            withGossip { gossip, _ ->
                val a = AtomicInteger()
                val b = AtomicInteger()
                val handle = gossip.addConsumer { a.incrementAndGet() }
                gossip.addConsumer { b.incrementAndGet() }
                handle.close()
                gossip.dispatch(ByteArray(1))
                a.get() shouldBe 0
                b.get() shouldBe 1
            }
        }

        test("at most four consumers") {
            withGossip { gossip, _ ->
                repeat(AnonymousMailboxGossip.MAX_CONSUMERS) { gossip.addConsumer { } }
                shouldThrow<IllegalArgumentException> { gossip.addConsumer { } }
            }
        }

        test("stop clears the consumers") {
            withGossip { gossip, _ ->
                val a = AtomicInteger()
                gossip.addConsumer { a.incrementAndGet() }
                gossip.stop()
                gossip.dispatch(ByteArray(1))
                a.get() shouldBe 0
            }
        }

        test("the shared topic shows up in subscribedTopics and disappears on stop") {
            withGossip { gossip, pubsub ->
                (ANONYMOUS_MAILBOX_GOSSIP_TOPIC in pubsub.subscribedTopics()) shouldBe true
                gossip.stop()
                (ANONYMOUS_MAILBOX_GOSSIP_TOPIC in pubsub.subscribedTopics()) shouldBe false
            }
        }
    })
