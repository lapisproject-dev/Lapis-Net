package net.lapisphilosophorum.lapisnet.onionwire

import io.kotest.assertions.fail
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.directory.AnonymousPeerRecord
import net.lapisphilosophorum.lapisnet.directory.DirectoryPublicationChannel
import net.lapisphilosophorum.lapisnet.directory.DirectoryRepublishSchedule
import net.lapisphilosophorum.lapisnet.directory.PublicationRateGuard
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.onion.IntroPointEntry
import net.lapisphilosophorum.lapisnet.onion.OnionKeyBinding
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptor
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptorCodec
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundle
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicInteger
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

        /** Simulates the host: every refresh re-signs the content as a version with the next sequence number. */
        class RefreshingHost(
            private val s: ManualScheduler,
            startSeq: Long = 1,
        ) {
            var seq = startSeq
            var calls = 0
            var produce = true
            lateinit var republisher: ServiceDescriptorRepublisher

            fun refresh(): Boolean {
                calls++
                if (!produce) return false
                seq++
                republisher.submit(descriptor(seq, s.now))
                return true
            }
        }

        fun refreshing(
            scheduler: ManualScheduler,
            channel: DirectoryPublicationChannel,
            host: RefreshingHost,
            guard: PublicationRateGuard? = PublicationRateGuard(4, 60_000L) { scheduler.now },
            maxPerHour: Int = 12,
        ) = ServiceDescriptorRepublisher(
            channel,
            scheduler::schedule,
            { scheduler.now },
            noJitter,
            maxEarlySendsPerHour = maxPerHour,
            retryReserve = 0,
            refresh = host::refresh,
            versionGuard = guard,
        ).also { host.republisher = it }

        test("at the slots a fresh version is sent: strictly rising sequence numbers, no byte-identical repeat") {
            val s = ManualScheduler()
            val channel = DescriptorChannel()
            val host = RefreshingHost(s)
            refreshing(s, channel, host).use { r ->
                r.submit(descriptor(1, s.now))
                s.advanceBy(10 * 60_000L)
                channel.sent.size shouldBe 6 // the first send and one fresh version per slot
                host.calls shouldBe 5
                channel.sent.map { it.sequenceNumber } shouldBe (1L..6L).toList()
                channel.sent
                    .map { OnionServiceDescriptorCodec.encode(it).toList() }
                    .distinct()
                    .size shouldBe 6
                channel.maxInFlight shouldBe 1
                s.pending() shouldBe 0 // the schedule runs to its end
            }
        }

        test("an empty version guard falls back to the identical repeat and asks the host for nothing") {
            val s = ManualScheduler()
            val channel = DescriptorChannel()
            val host = RefreshingHost(s)
            val exhausted = PublicationRateGuard(1, 3_600_000L) { s.now }
            exhausted.tryAcquire() shouldBe true
            refreshing(s, channel, host, guard = exhausted).use { r ->
                val d = descriptor(1, s.now)
                r.submit(d)
                s.advanceBy(10 * 60_000L)
                host.calls shouldBe 0
                channel.sent.size shouldBe 6
                channel.sent.all { it == d } shouldBe true
            }
        }

        test("a host that has nothing to refresh leads to the identical repeat") {
            val s = ManualScheduler()
            val channel = DescriptorChannel()
            val host = RefreshingHost(s).also { it.produce = false }
            refreshing(s, channel, host).use { r ->
                val d = descriptor(1, s.now)
                r.submit(d)
                s.advanceBy(10 * 60_000L)
                host.calls shouldBe 5
                channel.sent.size shouldBe 6
                channel.sent.all { it == d } shouldBe true
            }
        }

        test("a host that produced nothing does not consume version guard tokens") {
            val s = ManualScheduler()
            val channel = DescriptorChannel()
            val host = RefreshingHost(s).also { it.produce = false }
            val guard = PublicationRateGuard(4, 3_600_000L) { s.now }
            refreshing(s, channel, host, guard = guard).use { r ->
                r.submit(descriptor(1, s.now))
                s.advanceBy(10 * 60_000L)
                host.calls shouldBe 5
            }
            // only the genuine first send took a token; the 5 unproductive refresh attempts took none: 3 remain
            List(3) { guard.tryAcquire() }.all { it } shouldBe true
            guard.tryAcquire() shouldBe false
        }

        test("a refresh version whose send fails does not stop the remaining slots") {
            val s = ManualScheduler()
            val channel =
                DescriptorChannel { CompletableFuture.completedFuture(it != 1) } // the first fresh version fails
            val host = RefreshingHost(s)
            refreshing(s, channel, host).use { r ->
                r.submit(descriptor(1, s.now))
                s.advanceBy(10 * 60_000L)
                channel.sent.size shouldBe 6
                host.calls shouldBe 5
                s.pending() shouldBe 0
            }
        }

        test("the hourly cap of early sends still applies to fresh versions") {
            val s = ManualScheduler()
            val channel = DescriptorChannel()
            val host = RefreshingHost(s)
            refreshing(s, channel, host, maxPerHour = 3).use { r ->
                r.submit(descriptor(1, s.now))
                s.advanceBy(10 * 60_000L)
                channel.sent.size shouldBe 4 // the first send and three capped early sends
            }
        }

        test("the version guard keeps the sends of one descriptor lifetime at four per minute") {
            val s = ManualScheduler()
            val host = RefreshingHost(s)
            val times = ArrayList<Long>()
            val channel =
                DescriptorChannel {
                    times += s.now
                    CompletableFuture.completedFuture(true)
                }
            refreshing(s, channel, host).use { r ->
                r.submit(descriptor(1, s.now))
                s.advanceBy(10 * 60_000L)
            }
            (times.size >= 6) shouldBe true
            for (t in times) (times.count { it in t until t + 60_000L } <= 4) shouldBe true
        }

        test("close during a running refresh leaves nothing behind") {
            val s = ManualScheduler()
            val channel = DescriptorChannel()
            lateinit var r: ServiceDescriptorRepublisher
            var seq = 1L
            r =
                ServiceDescriptorRepublisher(
                    channel,
                    s::schedule,
                    { s.now },
                    noJitter,
                    retryReserve = 0,
                    refresh = {
                        r.close()
                        seq++
                        r.submit(descriptor(seq, s.now))
                        true
                    },
                    versionGuard = PublicationRateGuard(4, 60_000L) { s.now },
                )
            r.submit(descriptor(1, s.now))
            s.advanceBy(10 * 60_000L)
            channel.sent.size shouldBe 1
            s.pending() shouldBe 0
        }

        test("refresh never runs under the republisher monitor: no deadlock against submit under a host lock") {
            val pool = List(64) { descriptor(it + 1L, System.currentTimeMillis()) }
            val hostLock = Any()
            val executor = Executors.newFixedThreadPool(2)
            try {
                repeat(1000) { iteration ->
                    val next = AtomicInteger(0)
                    lateinit var r: ServiceDescriptorRepublisher
                    r =
                        ServiceDescriptorRepublisher(
                            DescriptorChannel(),
                            { _, task -> executor.submit(Runnable { task() }) }, // slots fire at once, on a pool thread
                            System::currentTimeMillis,
                            DirectoryRepublishSchedule(jitterFraction = 0.0),
                            retryReserve = 0,
                            // like the real host: takes its session lock, then calls submit
                            refresh = {
                                synchronized(hostLock) { r.submit(pool[next.incrementAndGet()]) }
                                true
                            },
                            versionGuard = PublicationRateGuard(1_000, 60_000L, System::currentTimeMillis),
                        )
                    val genuine =
                        executor.submit {
                            repeat(10) {
                                // the host publishes under its session lock and calls submit inside
                                synchronized(hostLock) { r.submit(pool[next.incrementAndGet()]) }
                            }
                        }
                    try {
                        genuine.get(20, TimeUnit.SECONDS)
                    } catch (e: TimeoutException) {
                        fail("deadlock between the host lock and the republisher monitor (iteration $iteration)")
                    } finally {
                        r.close()
                    }
                }
            } finally {
                executor.shutdownNow()
            }
        }
    })
