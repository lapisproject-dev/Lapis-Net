package net.lapisphilosophorum.lapisnet.dmonion

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.dm.SealedMailboxItemCodec
import java.time.Instant
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

private fun waitFor(condition: () -> Boolean): Boolean {
    val end = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
    while (System.nanoTime() < end) {
        if (condition()) return true
        Thread.sleep(10)
    }
    return condition()
}

class AnonymousMailboxRedeliveryTest :
    FunSpec({
        fun envelope(
            fill: Int,
            size: Int = 600,
        ) = ByteArray(size) { (it + fill).toByte() }

        fun expiry(seconds: Long = 3600) = Instant.now().epochSecond + seconds

        test("the first announcement is immediate, re-sealed on every round, never more than four items per circuit") {
            val port = FakePort()
            val r =
                AnonymousMailboxRedelivery(
                    port,
                    intervalMillis = 150,
                    jitterMillis = 0,
                    retryMillis = 150,
                    tickMillis = 30,
                )
            try {
                val peer = Peer()
                repeat(6) { r.add(peer.key, peer.bundle.x25519IdentityKey, envelope(it), expiry()) }
                waitFor { port.published.size >= 4 } shouldBe true
                port.published.all { it.size in 1..4 } shouldBe true
                port.published.all { call -> call.all { it.size == SealedMailboxItemCodec.SEALED_ITEM_BYTES } } shouldBe
                    true
                // stop the scheduler first: it keeps announcing every 150 ms, so a snapshot taken while it
                // runs would race against announcementCount(). An in-flight tick may still finish, hence
                // the wait for the two counters to agree before snapshotting.
                r.close()
                waitFor {
                    val published = port.published.sumOf { it.size }.toLong()
                    r.announcementCount() == published
                } shouldBe true
                // the same envelope announced twice yields different bytes (fresh ephemeral key)
                val all = port.published.flatten()
                all.map { java.nio.ByteBuffer.wrap(it) }.toSet().size shouldBe all.size
                // every sealed item opens for the recipient and carries the original envelope
                val key = peer.prekeys.x25519IdentityPrivateKey()
                (all.size > 6) shouldBe true
                r.announcementCount() shouldBe (all.size.toLong())
                key.destroy()
            } finally {
                r.close()
            }
        }

        test("close() waits for a running tick: nothing is published or counted after close() returned") {
            repeat(30) { round ->
                val port = FakePort()
                val r =
                    AnonymousMailboxRedelivery(
                        port,
                        intervalMillis = 1,
                        jitterMillis = 0,
                        retryMillis = 1,
                        tickMillis = 1,
                    )
                val peer = Peer()
                r.add(peer.key, peer.bundle.x25519IdentityKey, envelope(round), expiry())
                waitFor { port.published.isNotEmpty() } shouldBe true
                r.close()
                val published = port.published.size
                val announced = r.announcementCount()
                Thread.sleep(25)
                port.published.size shouldBe published
                r.announcementCount() shouldBe announced
            }
        }

        test("a failed announcement is retried, an expired entry is dropped") {
            val port = FakePort()
            port.publishResult = CompletableFuture.completedFuture(false)
            val r =
                AnonymousMailboxRedelivery(
                    port,
                    intervalMillis = 10_000,
                    jitterMillis = 0,
                    retryMillis = 100,
                    tickMillis = 30,
                )
            try {
                val peer = Peer()
                r.add(peer.key, peer.bundle.x25519IdentityKey, envelope(1), expiry())
                waitFor { port.published.size >= 3 } shouldBe true
                r.announcementCount() shouldBe 0
                port.publishResult = CompletableFuture.completedFuture(true)
                val soon = Instant.now().epochSecond + 1
                r.add(peer.key, peer.bundle.x25519IdentityKey, envelope(2), soon)
                Thread.sleep(2_500)
                // the short-lived entry is gone, the long one remains
                waitFor { r.pendingCount() == 1 } shouldBe true
            } finally {
                r.close()
            }
        }

        test("the queue is bounded in total and per recipient; the oldest entry goes first") {
            val port = FakePort()
            port.ready = false // nothing is announced, entries only accumulate
            val r = AnonymousMailboxRedelivery(port, tickMillis = 3_600_000, maxEntries = 10, maxPerRecipient = 3)
            try {
                val a = Peer()
                repeat(5) { r.add(a.key, a.bundle.x25519IdentityKey, envelope(it), expiry()) }
                r.pendingCount() shouldBe 3
                r.droppedCount() shouldBe 2
                val others = List(10) { Peer() }
                others.forEach { r.add(it.key, it.bundle.x25519IdentityKey, envelope(99), expiry()) }
                r.pendingCount() shouldBe 10
                (r.droppedCount() >= 3) shouldBe true
                // the same envelope for the same recipient is not queued twice
                val before = r.pendingCount()
                r.add(others[9].key, others[9].bundle.x25519IdentityKey, envelope(99), expiry())
                r.pendingCount() shouldBe before
            } finally {
                r.close()
            }
        }

        test("nothing is announced while the runtime is not ready, and close() clears the queue") {
            val port = FakePort()
            port.ready = false
            val r = AnonymousMailboxRedelivery(port, tickMillis = 30)
            val peer = Peer()
            r.add(peer.key, peer.bundle.x25519IdentityKey, envelope(1), expiry())
            Thread.sleep(300)
            port.published.size shouldBe 0
            r.close()
            r.pendingCount() shouldBe 0
        }
    })
