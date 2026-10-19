package net.lapisphilosophorum.lapisnet.directory

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import java.time.Instant
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class DhtOutboxTest :
    FunSpec({
        val now = Instant.now().epochSecond

        test("identical entries are deduplicated, the first offer is new") {
            val outbox = DhtOutbox()
            val e = outboxEntry()
            outbox.offer(e) shouldBe true
            outbox.offer(e) shouldBe false
            outbox.size() shouldBe 1
            outbox.remove(e)
            outbox.size() shouldBe 0
        }

        test("the tracked size is bounded, the least recently offered entry goes first") {
            val outbox = DhtOutbox(maxTracked = 3)
            val entries = List(5) { outboxEntry() }
            entries.forEach { outbox.offer(it) }
            outbox.size() shouldBe 3
            val selected = outbox.selectForPublication(now, 10, 10_000).entries
            selected.toSet() shouldBe entries.drop(2).toSet()
        }

        test("a non-positive capacity is refused") {
            shouldThrow<IllegalArgumentException> { DhtOutbox(0) }
        }

        test("expired entries are not selected and not counted as omitted") {
            val outbox = DhtOutbox()
            outbox.offer(outboxEntry(expiresInSeconds = -10))
            val live = outboxEntry()
            outbox.offer(live)
            val selection = outbox.selectForPublication(now, 10, 10_000)
            selection.entries shouldBe listOf(live)
            selection.omitted shouldBe 0
        }

        test("the entry count limit is applied and the rest is reported as omitted") {
            val outbox = DhtOutbox()
            repeat(6) { outbox.offer(outboxEntry()) }
            val selection = outbox.selectForPublication(now, 4, 10_000)
            selection.entries.size shouldBe 4
            selection.omitted shouldBe 2
        }

        test("round robin: a burst to one recipient does not push every other recipient out") {
            val outbox = DhtOutbox()
            val a = newKey()
            val b = newKey()
            repeat(10) { outbox.offer(outboxEntry(recipient = a)) }
            val forB = outboxEntry(recipient = b)
            outbox.offer(forB)
            val selection = outbox.selectForPublication(now, 3, 10_000)
            selection.entries.size shouldBe 3
            (forB in selection.entries) shouldBe true
        }

        test("newest first within a recipient") {
            val outbox = DhtOutbox()
            val a = newKey()
            val older = outboxEntry(recipient = a)
            val newer = outboxEntry(recipient = a)
            outbox.offer(older)
            outbox.offer(newer)
            outbox.selectForPublication(now, 1, 10_000).entries shouldBe listOf(newer)
        }

        test("the byte budget is respected, an entry that does not fit is skipped and a smaller one still taken") {
            val outbox = DhtOutbox()
            val big = outboxEntry(payloadSize = 274)
            val small = outboxEntry(payloadSize = 10)
            outbox.offer(big)
            outbox.offer(small)
            val budget = small.encodedSize() + 5
            val selection = outbox.selectForPublication(now, 10, budget)
            selection.entries shouldBe listOf(small)
            selection.omitted shouldBe 1
            val all = outbox.selectForPublication(now, 10, big.encodedSize() + small.encodedSize())
            all.entries.size shouldBe 2
        }

        test("concurrent offers and selections neither fail nor exceed the bound") {
            val outbox = DhtOutbox(maxTracked = 50)
            val pool = Executors.newFixedThreadPool(4)
            val start = CountDownLatch(1)
            val errors =
                java.util.concurrent.atomic
                    .AtomicInteger()
            repeat(4) { t ->
                pool.submit {
                    start.await()
                    runCatching {
                        repeat(200) {
                            if (t % 2 == 0) {
                                outbox.offer(outboxEntry())
                            } else {
                                outbox.selectForPublication(now, 24, 2000)
                            }
                        }
                    }.onFailure { errors.incrementAndGet() }
                }
            }
            start.countDown()
            pool.shutdown()
            pool.awaitTermination(60, TimeUnit.SECONDS) shouldBe true
            errors.get() shouldBe 0
            (outbox.size() <= 50) shouldBe true
        }

        test("the content id binds kind, recipient, expiry and payload") {
            val r = newKey()
            val a = OutboxEntry(OutboxEntryKind.MAIL_POINTER, r, 100, byteArrayOf(1, 2, 3))
            val same = OutboxEntry(OutboxEntryKind.MAIL_POINTER, r, 100, byteArrayOf(1, 2, 3))
            a.contentId().contentEquals(same.contentId()) shouldBe true
            a shouldBe same
            val others =
                listOf(
                    OutboxEntry(OutboxEntryKind.DM_MAILBOX_POINTER, r, 100, byteArrayOf(1, 2, 3)),
                    OutboxEntry(OutboxEntryKind.MAIL_POINTER, newKey(), 100, byteArrayOf(1, 2, 3)),
                    OutboxEntry(OutboxEntryKind.MAIL_POINTER, r, 101, byteArrayOf(1, 2, 3)),
                    OutboxEntry(OutboxEntryKind.MAIL_POINTER, r, 100, byteArrayOf(1, 2, 4)),
                )
            others.forEach { it.contentId().contentEquals(a.contentId()) shouldBe false }
        }

        test("the payload is copied on the way in and on the way out, toString shows no payload") {
            val bytes = byteArrayOf(9, 9, 9)
            val e = OutboxEntry(OutboxEntryKind.MAIL_POINTER, newKey(), 5, bytes)
            bytes[0] = 0
            e.payload[0] shouldBe 9.toByte()
            e.payload[0] = 0
            e.payload[0] shouldBe 9.toByte()
            // Only the length is shown. (A bare "09" check is flaky: the random recipient fingerprint can contain it.)
            e.toString().contains("payloadBytes=3") shouldBe true
            e.toString().contains("090909") shouldBe false
            e.toString().contains("[9, 9, 9]") shouldBe false
        }
    })
