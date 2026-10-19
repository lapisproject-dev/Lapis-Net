package net.lapisphilosophorum.lapisnet.storage

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.comparables.shouldBeLessThan
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import org.peergos.protocol.dht.pb.Dht
import java.time.Duration
import java.time.Instant
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import kotlin.time.Duration.Companion.seconds

/**
 * `publishIpnsValue` and `resolveIpnsValue` against peers that answer the walk but then say nothing:
 * both must come back by their absolute deadline, `stop()` must end a wait at once, permits must
 * be honoured, and an interrupt must not be swallowed.
 */
class DhtIpnsDeadlineTest :
    FunSpec({
        /** A peer that answers FIND_NODE (so it is walked to and written to) but is mute for PUT_VALUE / GET_VALUE. */
        fun mutePeer(): ScriptedDhtPeer =
            ScriptedDhtPeer.start().also { it.answer(Dht.Message.MessageType.FIND_NODE) { msg -> msg } }

        fun expiry(): Instant = Instant.now().plus(Duration.ofHours(1))

        test("publish and resolve return by their deadline when every peer is mute").config(timeout = 60.seconds) {
            val a = newTestNode()
            val peers = List(3) { mutePeer() }
            try {
                val storage = storageOn(a.node)
                peers.forEach { storage.connectToDhtPeer(it.address) shouldBe true }

                val publishStart = System.nanoTime()
                val result =
                    storage.publishIpnsValue(
                        a.signingKey,
                        "x".toByteArray(),
                        1,
                        expiry(),
                        timeout = Duration.ofSeconds(3),
                    )
                val publishMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - publishStart)
                result.acknowledged shouldBe 0
                // the FIND_NODE walk has only half the timeout, so a mute peer may drop out before it is counted
                (result.attempted in 1..3) shouldBe true
                publishMs shouldBeLessThan 3_000L + 1_500L

                val resolveStart = System.nanoTime()
                storage.resolveIpnsValue(IpnsIdentity.generate().peerId, Duration.ofSeconds(2)) shouldBe null
                TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - resolveStart) shouldBeLessThan 2_000L + 1_500L
            } finally {
                peers.forEach { it.stop() }
                runCatching { a.node.stop() }
            }
        }

        test("stop() ends a running resolve at once, long before its timeout").config(timeout = 60.seconds) {
            val a = newTestNode()
            val peers = List(2) { mutePeer() }
            try {
                val storage = storageOn(a.node, DhtLimits(perRpcTimeout = Duration.ofSeconds(30)))
                peers.forEach { storage.connectToDhtPeer(it.address) shouldBe true }

                val outcome = CompletableFuture<Result<Any?>>()
                Thread {
                    outcome.complete(
                        runCatching {
                            storage.resolveIpnsValue(
                                IpnsIdentity.generate().peerId,
                                Duration.ofSeconds(30),
                            )
                        },
                    )
                }.apply {
                    isDaemon = true
                    start()
                }
                Thread.sleep(800)
                outcome.isDone shouldBe false
                val stopped = System.nanoTime()
                storage.stop()
                val result = outcome.get(5, TimeUnit.SECONDS)
                TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - stopped) shouldBeLessThan 3_000L
                result.getOrNull() shouldBe null
            } finally {
                peers.forEach { it.stop() }
                runCatching { a.node.stop() }
            }
        }

        test("with every DHT permit taken a further call fails with 'DHT busy' within its own timeout").config(
            timeout = 60.seconds,
        ) {
            val a = newTestNode()
            val peer = mutePeer()
            try {
                val storage =
                    storageOn(a.node, DhtLimits(maxConcurrentDhtOperations = 1, perRpcTimeout = Duration.ofSeconds(10)))
                storage.connectToDhtPeer(peer.address) shouldBe true
                val holder = CompletableFuture<Any?>()
                Thread {
                    holder.complete(
                        runCatching { storage.resolveIpnsValue(IpnsIdentity.generate().peerId, Duration.ofSeconds(8)) },
                    )
                }.apply {
                    isDaemon = true
                    start()
                }
                Thread.sleep(500)

                val start = System.nanoTime()
                val e =
                    shouldThrow<NabuStorageException> {
                        storage.resolveIpnsValue(
                            IpnsIdentity.generate().peerId,
                            Duration.ofMillis(300),
                        )
                    }
                e.message shouldContain "DHT busy"
                TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) shouldBeLessThan 2_000L
                shouldThrow<NabuStorageException> {
                    storage.publishIpnsValue(
                        a.signingKey,
                        "x".toByteArray(),
                        1,
                        expiry(),
                        timeout = Duration.ofMillis(300),
                    )
                }.message shouldContain "DHT busy"
                storage.stop()
                holder.get(10, TimeUnit.SECONDS)
            } finally {
                peer.stop()
                runCatching { a.node.stop() }
            }
        }

        test(
            "an interrupted thread gets a NabuStorageException and keeps its interrupt flag",
        ).config(timeout = 30.seconds) {
            val a = newTestNode()
            try {
                val storage = storageOn(a.node)
                Thread.currentThread().interrupt()
                try {
                    shouldThrow<NabuStorageException> {
                        storage.resolveIpnsValue(
                            IpnsIdentity.generate().peerId,
                            Duration.ofSeconds(2),
                        )
                    }
                    Thread.currentThread().isInterrupted shouldBe true
                } finally {
                    Thread.interrupted()
                }
            } finally {
                runCatching { a.node.stop() }
            }
        }

        test("after stop() publish and resolve refuse to start") {
            val a = newTestNode()
            try {
                val storage = storageOn(a.node)
                storage.stop()
                shouldThrow<NabuStorageException> { storage.resolveIpnsValue(a.peerId) }
                shouldThrow<NabuStorageException> {
                    storage.publishIpnsValue(
                        a.signingKey,
                        "x".toByteArray(),
                        1,
                        expiry(),
                    )
                }
            } finally {
                runCatching { a.node.stop() }
            }
        }
    })
