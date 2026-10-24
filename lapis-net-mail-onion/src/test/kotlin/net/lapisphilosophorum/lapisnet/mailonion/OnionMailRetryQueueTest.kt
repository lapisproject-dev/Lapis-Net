package net.lapisphilosophorum.lapisnet.mailonion

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import java.security.SecureRandom
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger

class OnionMailRetryQueueTest :
    FunSpec({
        val a = Secp256k1KeyPair.generate().publicKey
        val b = Secp256k1KeyPair.generate().publicKey

        fun queue(
            clock: SteppingClock = SteppingClock(),
            maxEntries: Int = 32,
            perRecipient: Int = 4,
            maxBytes: Long = 16L * 1024 * 1024,
            interval: Long = 600_000,
            jitter: Long = 0,
        ) = OnionMailRetryQueue(
            clock = clock,
            intervalMillis = interval,
            jitterMillis = jitter,
            tickMillis = 20,
            maxEntries = maxEntries,
            maxPerRecipient = perRecipient,
            maxTotalBytes = maxBytes,
        )

        test("the per-recipient cap drops the oldest entry and counts it") {
            val q = queue(perRecipient = 2)
            try {
                repeat(3) { q.add(a, ByteArray(10) { i -> i.toByte() }, Long.MAX_VALUE) }
                q.pendingCount() shouldBe 2
                q.droppedCount() shouldBe 1
                q.add(b, ByteArray(10), Long.MAX_VALUE)
                q.pendingCount() shouldBe 3
            } finally {
                q.close()
            }
        }

        test("the total entry cap and the byte cap both evict the oldest first") {
            val q = queue(maxEntries = 3, perRecipient = 10, maxBytes = 100)
            try {
                repeat(5) { q.add(a, ByteArray(10), Long.MAX_VALUE) }
                q.pendingCount() shouldBe 3
                q.droppedCount() shouldBe 2
                q.add(b, ByteArray(60), Long.MAX_VALUE)
                (q.pendingBytes() <= 100) shouldBe true
                q.add(b, ByteArray(101), Long.MAX_VALUE) // larger than the whole budget: not queued at all
                (q.pendingBytes() <= 100) shouldBe true
            } finally {
                q.close()
            }
        }

        test("an acknowledged bundle is removed; a failed one is retried later") {
            val clock = SteppingClock()
            val q = queue(clock = clock, interval = 1000)
            val attempts = CopyOnWriteArrayList<Boolean>()
            val succeedFrom = AtomicInteger(2)
            q.start { _, _ ->
                val ok = attempts.size + 1 >= succeedFrom.get()
                attempts += ok
                ok
            }
            try {
                q.add(a, ByteArray(10), Long.MAX_VALUE, firstDelayMillis = 0)
                waitFor { attempts.size == 1 } shouldBe true
                q.pendingCount() shouldBe 1
                clock.millis += 2000
                waitFor { attempts.size == 2 } shouldBe true
                waitFor { q.pendingCount() == 0 } shouldBe true
                q.deliveredCount() shouldBe 1
            } finally {
                q.close()
            }
        }

        test("an entry is not attempted before its first delay and expires after its lifetime") {
            val clock = SteppingClock()
            val q = queue(clock = clock)
            val attempts = AtomicInteger()
            q.start { _, _ ->
                attempts.incrementAndGet()
                false
            }
            try {
                q.add(a, ByteArray(10), clock.millis / 1000 + 10, firstDelayMillis = 60_000)
                Thread.sleep(200)
                attempts.get() shouldBe 0
                clock.millis += 11_000 // past its lifetime
                waitFor { q.pendingCount() == 0 } shouldBe true
                attempts.get() shouldBe 0
            } finally {
                q.close()
            }
        }

        test("the retry interval stays within the jitter bounds") {
            val clock = SteppingClock()
            val q =
                OnionMailRetryQueue(
                    clock = clock,
                    random = SecureRandom(),
                    intervalMillis = 10_000,
                    jitterMillis = 2_000,
                    tickMillis = 20,
                )
            val attempts = AtomicInteger()
            q.start { _, _ ->
                attempts.incrementAndGet()
                false
            }
            try {
                q.add(a, ByteArray(5), Long.MAX_VALUE, firstDelayMillis = 0)
                waitFor { attempts.get() == 1 } shouldBe true
                clock.millis += 7_999 // below interval - jitter: never due yet
                Thread.sleep(250)
                attempts.get() shouldBe 1
                clock.millis += 4_002 // beyond interval + jitter: always due
                waitFor { attempts.get() == 2 } shouldBe true
            } finally {
                q.close()
            }
        }

        test("close wipes and drops everything and is idempotent; a closed queue accepts nothing") {
            val q = queue()
            q.add(a, ByteArray(10), Long.MAX_VALUE)
            q.close()
            q.close()
            q.pendingCount() shouldBe 0
            q.add(a, ByteArray(10), Long.MAX_VALUE)
            q.pendingCount() shouldBe 0
        }
    })
