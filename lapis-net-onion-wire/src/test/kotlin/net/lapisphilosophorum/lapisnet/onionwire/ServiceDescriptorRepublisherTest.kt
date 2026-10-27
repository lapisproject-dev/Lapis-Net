package net.lapisphilosophorum.lapisnet.onionwire

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.directory.AnonymousPeerRecord
import net.lapisphilosophorum.lapisnet.directory.DirectoryPublicationChannel
import net.lapisphilosophorum.lapisnet.directory.DirectoryRepublishSchedule
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.onion.IntroPointEntry
import net.lapisphilosophorum.lapisnet.onion.OnionKeyBinding
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptor
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptorCodec
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundle
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Future
import kotlin.time.Duration.Companion.seconds

/** A scheduler with a due list and a manual clock; cancelled entries never run. */
private class ManualScheduler(
    var now: Long = System.currentTimeMillis(),
) {
    class Entry(
        val due: Long,
        val task: () -> Unit,
    ) : CompletableFuture<Unit>()

    private val entries = ArrayList<Entry>()

    fun schedule(
        delay: Long,
        task: () -> Unit,
    ): Future<*> = Entry(now + delay, task).also { entries += it }

    fun pending(): Int = entries.count { !it.isCancelled }

    fun advanceBy(millis: Long) {
        val target = now + millis
        while (true) {
            val next = entries.filter { !it.isCancelled && it.due <= target }.minByOrNull { it.due } ?: break
            entries.remove(next)
            now = maxOf(now, next.due)
            next.task()
        }
        now = target
    }
}

private class DescriptorChannel(
    var answer: (call: Int) -> CompletableFuture<Boolean> = { CompletableFuture.completedFuture(true) },
) : DirectoryPublicationChannel {
    override val exposesOrigin = false
    val sent = ArrayList<OnionServiceDescriptor>()
    var inFlight = 0
    var maxInFlight = 0

    override fun publishServiceDescriptor(descriptor: OnionServiceDescriptor): CompletableFuture<Boolean> {
        sent += descriptor
        val f = answer(sent.size - 1)
        inFlight++
        maxInFlight = maxOf(maxInFlight, inFlight)
        return f.whenComplete { _, _ -> inFlight-- }
    }

    override fun publishAnonymousPeerRecord(record: AnonymousPeerRecord) = CompletableFuture.completedFuture(true)

    override fun publishPrekeyBundle(bundle: PrekeyBundle) = CompletableFuture.completedFuture(true)
}

private val serviceKey = Ed25519KeyPair.generate()

private fun descriptor(
    sequence: Long,
    clockMillis: Long,
    ttlSeconds: Long = 3600,
    createdSecondsAgo: Long = 0,
): OnionServiceDescriptor {
    val nowSec = clockMillis / 1000 - createdSecondsAgo
    return OnionServiceDescriptor.create(
        serviceKey,
        X25519KeyPair.generate().publicKey,
        List(2) {
            IntroPointEntry(
                OnionKeyBinding.create(
                    Secp256k1KeyPair.generate(),
                    X25519KeyPair.generate().publicKey,
                    nowSec + 86_400,
                ),
                Ed25519KeyPair.generate().publicKey,
            )
        },
        sequence,
        nowSec + ttlSeconds,
        nowSec,
    )
}

class ServiceDescriptorRepublisherTest :
    FunSpec({
        val noJitter = DirectoryRepublishSchedule(jitterFraction = 0.0)

        fun republisher(
            scheduler: ManualScheduler,
            channel: DirectoryPublicationChannel,
            maxPerHour: Int = 12,
            reserve: Int = 0,
        ) = ServiceDescriptorRepublisher(
            channel,
            scheduler::schedule,
            { scheduler.now },
            noJitter,
            maxEarlySendsPerHour = maxPerHour,
            retryReserve = reserve,
        )

        test("a failed first send is retried along the backoff and then given up on") {
            val s = ManualScheduler()
            val channel = DescriptorChannel { CompletableFuture.completedFuture(false) }
            republisher(s, channel).use { r ->
                r.submit(descriptor(1, s.now))
                s.advanceBy(20 * 60_000L)
                channel.sent.size shouldBe 6 // the first send and five retries
                r.sends shouldBe 6
                s.pending() shouldBe 0
            }
        }

        test("after the first success the identical descriptor is sent again at the schedule slots") {
            val s = ManualScheduler()
            val channel = DescriptorChannel()
            republisher(s, channel).use { r ->
                val d = descriptor(1, s.now)
                r.submit(d)
                s.advanceBy(10 * 60_000L)
                channel.sent.size shouldBe 6
                channel.sent.all { it == d } shouldBe true
                channel.sent
                    .map { OnionServiceDescriptorCodec.encode(it).toList() }
                    .distinct()
                    .size shouldBe 1
                s.pending() shouldBe 0
            }
        }

        test("a newer descriptor cancels everything open for the older one, an older one is never sent") {
            val s = ManualScheduler()
            val channel = DescriptorChannel()
            republisher(s, channel).use { r ->
                r.submit(descriptor(5, s.now))
                s.advanceBy(10_000)
                val sentBefore = channel.sent.size
                r.submit(descriptor(4, s.now)) // older: ignored
                r.submit(descriptor(5, s.now)) // equal: ignored
                channel.sent.size shouldBe sentBefore
                r.submit(descriptor(6, s.now))
                s.advanceBy(10 * 60_000L)
                // the schedule is planned once per lifetime: the newest descriptor takes over the open slots
                channel.sent.size shouldBe sentBefore + 5
                channel.sent.drop(sentBefore).all { it.sequenceNumber == 6L } shouldBe true
            }
        }

        test("an expired descriptor is never sent") {
            val s = ManualScheduler()
            val channel = DescriptorChannel()
            republisher(s, channel).use { r ->
                r.submit(descriptor(1, s.now, ttlSeconds = 3600, createdSecondsAgo = 7200))
                channel.sent.size shouldBe 0
                r.submit(descriptor(2, s.now, ttlSeconds = 60))
                s.advanceBy(10 * 60_000L)
                // the first send plus the slots at 5, 15 and 45 s; the slots at 2 and 5 min are past the expiry
                channel.sent.size shouldBe 4
            }
        }

        test("the hourly cap limits retries and repeats, not the first send of each descriptor") {
            val s = ManualScheduler()
            val channel = DescriptorChannel()
            republisher(s, channel, maxPerHour = 2).use { r ->
                r.submit(descriptor(1, s.now))
                s.advanceBy(10 * 60_000L)
                channel.sent.size shouldBe 3 // first send + 2 repeats
                r.submit(descriptor(2, s.now))
                channel.sent.size shouldBe 4 // a new descriptor is still sent at once
                s.advanceBy(10 * 60_000L)
                channel.sent.size shouldBe 4 // and it gets no repeats of its own
                s.advanceBy(60 * 60_000L)
                r.submit(descriptor(3, s.now))
                s.advanceBy(10 * 60_000L)
                channel.sent.size shouldBe 5 // an hour later: first send only, the schedule does not restart
            }
        }

        test("an hourly descriptor does not restart the repeat schedule") {
            val s = ManualScheduler()
            val channel = DescriptorChannel()
            republisher(s, channel).use { r ->
                r.submit(descriptor(1, s.now))
                s.advanceBy(10 * 60_000L)
                channel.sent.size shouldBe 6
                r.submit(descriptor(2, s.now))
                s.advanceBy(10 * 60_000L)
                channel.sent.size shouldBe 7
                s.pending() shouldBe 0
            }
        }

        test("repeats stop before the cap so that the retry of a failed first send keeps its budget") {
            val s = ManualScheduler()
            val channel =
                DescriptorChannel { CompletableFuture.completedFuture(it < 3) }
            republisher(s, channel, maxPerHour = 4, reserve = 2).use { r ->
                r.submit(descriptor(1, s.now))
                s.advanceBy(10 * 60_000L)
                channel.sent.size shouldBe 3 // first send + 2 repeats, the third repeat is held back by the reserve
                r.submit(descriptor(2, s.now))
                s.advanceBy(10 * 60_000L)
                channel.sent.size shouldBe 6 // first send of 2 plus two retries from the reserve, then capped
            }
        }

        test("close cancels everything and later submits are no-ops") {
            val s = ManualScheduler()
            val channel = DescriptorChannel()
            val r = republisher(s, channel)
            r.submit(descriptor(1, s.now))
            s.pending() shouldBe 1
            r.close()
            r.close()
            s.pending() shouldBe 0
            s.advanceBy(10 * 60_000L)
            r.submit(descriptor(2, s.now))
            channel.sent.size shouldBe 1
            s.pending() shouldBe 0
        }

        test("submit never blocks and there is never more than one send in flight") {
            val s = ManualScheduler()
            val pending = ArrayList<CompletableFuture<Boolean>>()
            val channel = DescriptorChannel { CompletableFuture<Boolean>().also { pending += it } }
            republisher(s, channel).use { r ->
                r.submit(descriptor(1, s.now)) // returns although the future never completes
                r.submit(descriptor(2, s.now))
                r.submit(descriptor(3, s.now))
                channel.sent.size shouldBe 1
                pending[0].complete(true)
                channel.sent.size shouldBe 2 // the newest descriptor follows the finished send
                channel.sent[1].sequenceNumber shouldBe 3L
                pending[1].complete(true)
                s.advanceBy(10 * 60_000L)
                channel.maxInFlight shouldBe 1
            }
        }

        test("a failing channel call is treated like a failed send") {
            val s = ManualScheduler()
            val calls = ArrayList<Int>()
            val channel =
                DescriptorChannel {
                    calls += it
                    if (it == 0) throw IllegalStateException("boom") else CompletableFuture.completedFuture(true)
                }
            republisher(s, channel).use { r ->
                runCatching { r.submit(descriptor(1, s.now)) }
                s.advanceBy(5.seconds.inWholeMilliseconds + 1_000)
                calls.size shouldBe 2
            }
        }
    })
