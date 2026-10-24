package net.lapisphilosophorum.lapisnet.mailonion

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.directory.AnonymousMailboxGossip
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptorIndex
import net.lapisphilosophorum.lapisnet.directory.SealedMailboxBox
import net.lapisphilosophorum.lapisnet.directory.SealedMailboxKind
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.identity.X25519PrivateKey
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import java.security.SecureRandom
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch

class AnonymousMailSubscriberTest :
    FunSpec({
        val node = LapisNode.create(DualKeyIdentity.generate())
        node.start(bootstrapPeers = emptyList())
        val pubsub = GossipPubSub.attach(node)
        val gossip = AnonymousMailboxGossip.attach(pubsub, OnionRelayDescriptorIndex())
        afterSpec {
            runCatching { gossip.stop() }
            pubsub.stop()
            runCatching { node.stop() }
        }

        val raw = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val own = X25519KeyPair.fromPrivateKeyBytes(raw.copyOf())
        val handedOut = CopyOnWriteArrayList<X25519PrivateKey>()
        val keySource = {
            X25519KeyPair.fromPrivateKeyBytes(raw.copyOf()).privateKey.also { handedOut += it }
        }
        val now = System.currentTimeMillis() / 1000
        val payload = ByteArray(700) { (it % 50).toByte() }

        test("an own MAIL item reaches the sink; a DM item, a foreign item and garbage are dropped silently") {
            val sink = CollectingMailSink()
            val subscriber = AnonymousMailSubscriber.attach(gossip, keySource, sink)
            try {
                subscriber.offer(SealedMailboxBox.seal(SealedMailboxKind.MAIL, payload, own.publicKey, now + 100))
                subscriber.offer(SealedMailboxBox.seal(SealedMailboxKind.DM, payload, own.publicKey, now + 100))
                subscriber.offer(
                    SealedMailboxBox.seal(
                        SealedMailboxKind.MAIL,
                        payload,
                        X25519KeyPair.generate().publicKey,
                        now + 100,
                    ),
                )
                subscriber.offer(ByteArray(SealedMailboxBox.ITEM_BYTES) { 1 })
                // expired
                subscriber.offer(SealedMailboxBox.seal(SealedMailboxKind.MAIL, payload, own.publicKey, now - 10))
                waitFor { subscriber.triedCount() == 5L } shouldBe true
                sink.received.size shouldBe 1
                sink.received
                    .single()
                    .frame
                    .contentEquals(payload) shouldBe true
                sink.received
                    .single()
                    .blobs.size shouldBe 0
            } finally {
                subscriber.close()
            }
        }

        test("the sealing key is destroyed after every attempt") {
            handedOut.clear()
            val subscriber = AnonymousMailSubscriber.attach(gossip, keySource, CollectingMailSink())
            try {
                subscriber.offer(SealedMailboxBox.seal(SealedMailboxKind.MAIL, payload, own.publicKey, now + 100))
                subscriber.offer(ByteArray(10))
                waitFor { subscriber.triedCount() == 2L } shouldBe true
                waitFor { handedOut.size == 2 } shouldBe true
                handedOut.all { k -> k.bytes.all { it == 0.toByte() } } shouldBe true
            } finally {
                subscriber.close()
            }
        }

        test("a flood beyond the queue is dropped and counted, never blocks the caller") {
            val sink = CollectingMailSink()
            val gate = CountDownLatch(1)
            sink.gate = gate
            val subscriber = AnonymousMailSubscriber.attach(gossip, keySource, sink, queueCapacity = 2)
            try {
                val item = SealedMailboxBox.seal(SealedMailboxKind.MAIL, payload, own.publicKey, now + 100)
                repeat(10) { subscriber.offer(item) }
                (subscriber.droppedCount() >= 6) shouldBe true
            } finally {
                gate.countDown()
                subscriber.close()
            }
        }

        test("the subscriber registers as one consumer of the shared topic and releases it on close") {
            // four consumers is the cap: after close the slot is free again
            val subs =
                List(
                    AnonymousMailboxGossip.MAX_CONSUMERS,
                ) { AnonymousMailSubscriber.attach(gossip, keySource, CollectingMailSink()) }
            runCatching { AnonymousMailSubscriber.attach(gossip, keySource, CollectingMailSink()) }.isFailure shouldBe
                true
            subs.first().close()
            AnonymousMailSubscriber.attach(gossip, keySource, CollectingMailSink()).close()
            subs.forEach { it.close() }
        }
    })
