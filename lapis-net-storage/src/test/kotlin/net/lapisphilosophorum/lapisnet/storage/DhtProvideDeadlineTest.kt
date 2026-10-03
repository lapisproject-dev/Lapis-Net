package net.lapisphilosophorum.lapisnet.storage

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.longs.shouldBeLessThan
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.libp2p.core.PeerId
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import java.time.Duration
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.time.Duration.Companion.seconds

/**
 * V0.9.11 / finding A: `provide()` used to be unbounded. Nabu's `findClosestPeers` blocks on
 * `future.get()` / `join()` with no deadline and runs on a fixed 16-thread NON-daemon pool, so a
 * handful of silent peers wedged it for good. These tests put a real silent peer (accepts the
 * connection and the Kademlia stream, never answers) into the victim's routing table next to an
 * honest one and prove every call comes back within its own timeout, that the DHT stays usable
 * afterwards, and that interruption and `stop()` end a call early.
 */
class DhtProvideDeadlineTest :
    FunSpec({
        val timeout = Duration.ofSeconds(2)
        val fast = DhtLimits(perRpcTimeout = Duration.ofMillis(500))

        /** V (victim) knows a silent peer S and an honest peer B; C knows only B. */
        class Rig(
            val limits: DhtLimits,
        ) {
            val silent = ScriptedDhtPeer.start()
            val nodeV: LapisNode = newNode()
            val nodeB: LapisNode = newNode()
            val nodeC: LapisNode = newNode()
            val storageV = storageOn(nodeV, limits)
            val storageB = storageOn(nodeB)
            val storageC = storageOn(nodeC)

            init {
                storageV.connectToDhtPeer(silent.address) shouldBe true
                storageV.connectToDhtPeer(addressOf(nodeB)) shouldBe true
                storageC.connectToDhtPeer(addressOf(nodeB)) shouldBe true
            }

            fun close() {
                silent.stop()
                listOf(nodeV, nodeB, nodeC).forEach { runCatching { it.stop() } }
            }
        }

        test("30 sequential provide() calls each return within their timeout, and the DHT keeps working").config(
            timeout = 120.seconds,
        ) {
            val rig = Rig(fast)
            // each call runs on a daemon thread and is awaited with a bound, so an implementation that
            // hangs FAILS this test instead of hanging the whole suite
            val pool = Executors.newSingleThreadExecutor { task -> Thread(task).apply { isDaemon = true } }
            try {
                val payload = "provided through a routing table that contains a silent peer".toByteArray()
                val cid = rig.storageV.put(payload)
                repeat(30) {
                    val start = System.nanoTime()
                    val sent =
                        pool
                            .submit<Int> {
                                rig.storageV.provide(cid, timeout)
                            }.get(timeout.toMillis() + 1_500, TimeUnit.MILLISECONDS)
                    val elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start)
                    elapsedMs shouldBeLessThan timeout.toMillis() + 500
                    sent shouldBe 1 // only B answered; the silent peer is not announced to
                }
                rig.storageC.findProviders(cid, timeout = Duration.ofSeconds(5)) shouldBe setOf(rig.nodeV.peerId)
                rig.storageC.get(cid, timeout = Duration.ofSeconds(10)) shouldBe payload
            } finally {
                pool.shutdownNow()
                rig.close()
            }
        }

        test("30 parallel provide() calls all come back within their timeout - normally or as DHT busy").config(
            timeout = 120.seconds,
        ) {
            val rig = Rig(fast)
            val pool = Executors.newFixedThreadPool(30)
            try {
                val cid = rig.storageV.put("parallel provide".toByteArray())
                val futures =
                    List(30) {
                        pool.submit<Result<Int>> {
                            runCatching { rig.storageV.provide(cid, timeout) }
                        }
                    }
                val start = System.nanoTime()
                val results = futures.map { it.get(timeout.toMillis() + 3_000, TimeUnit.MILLISECONDS) }
                TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) shouldBeLessThan timeout.toMillis() + 3_000
                results.forEach { result ->
                    result.onFailure { it.shouldBeInstanceOf<NabuStorageException>() }
                }
                results.count { it.isSuccess } shouldNotBe 0
            } finally {
                pool.shutdownNow()
                rig.close()
            }
        }

        test("interrupting a running provide() ends it within a second and restores the interrupt flag").config(
            timeout = 60.seconds,
        ) {
            val rig = Rig(DhtLimits(perRpcTimeout = Duration.ofSeconds(20)))
            try {
                val cid = rig.storageV.put("interrupt".toByteArray())
                val outcome = AtomicReference<Throwable?>()
                val flag = AtomicBoolean()
                val thread =
                    Thread {
                        try {
                            rig.storageV.provide(cid, Duration.ofSeconds(30))
                        } catch (e: Throwable) {
                            outcome.set(e)
                        }
                        flag.set(Thread.currentThread().isInterrupted)
                    }.apply { isDaemon = true }
                thread.start()
                Thread.sleep(400)
                val interruptedAt = System.nanoTime()
                thread.interrupt()
                thread.join(5_000)
                thread.isAlive shouldBe false
                TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - interruptedAt) shouldBeLessThan 1_500
                outcome.get().shouldBeInstanceOf<NabuStorageException>()
                flag.get() shouldBe true
            } finally {
                rig.close()
            }
        }

        test("stop() during a running provide() ends it within a second, and provide() after stop() throws").config(
            timeout = 60.seconds,
        ) {
            val rig = Rig(DhtLimits(perRpcTimeout = Duration.ofSeconds(20)))
            try {
                val cid = rig.storageV.put("stop".toByteArray())
                val outcome = AtomicReference<Throwable?>()
                val thread =
                    Thread {
                        try {
                            rig.storageV.provide(cid, Duration.ofSeconds(30))
                        } catch (e: Throwable) {
                            outcome.set(e)
                        }
                    }.apply { isDaemon = true }
                thread.start()
                Thread.sleep(400)
                val stoppedAt = System.nanoTime()
                rig.storageV.stop()
                thread.join(5_000)
                thread.isAlive shouldBe false
                TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - stoppedAt) shouldBeLessThan 1_500
                outcome.get().shouldBeInstanceOf<NabuStorageException>()

                shouldThrow<NabuStorageException> { rig.storageV.provide(cid, timeout) }
                shouldThrow<NabuStorageException> { rig.storageV.findProviders(cid, timeout = timeout) }
                val notHeld = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { 7 })
                rig.storageV.get(notHeld, setOf(PeerId.random()), timeout) shouldBe null
                rig.storageV.stop() // idempotent
            } finally {
                rig.close()
            }
        }

        test("provide() with an empty routing table announces to nobody and returns 0") {
            val node = newNode()
            try {
                val storage = storageOn(node)
                storage.provide(storage.put("alone".toByteArray()), timeout) shouldBe 0
            } finally {
                node.stop()
            }
        }

        test("a non-positive timeout is rejected") {
            val node = newNode()
            try {
                val storage = storageOn(node)
                val cid = storage.put("t".toByteArray())
                shouldThrow<IllegalArgumentException> { storage.provide(cid, Duration.ZERO) }
                shouldThrow<IllegalArgumentException> { storage.findProviders(cid, timeout = Duration.ofSeconds(-1)) }
            } finally {
                node.stop()
            }
        }
    })
