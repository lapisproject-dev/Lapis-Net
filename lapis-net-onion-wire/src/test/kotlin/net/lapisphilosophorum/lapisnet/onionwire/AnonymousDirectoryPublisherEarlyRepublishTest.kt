package net.lapisphilosophorum.lapisnet.onionwire

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.directory.AnonymousPeerRecord
import net.lapisphilosophorum.lapisnet.directory.DirectoryPublicationChannel
import net.lapisphilosophorum.lapisnet.directory.DirectoryRepublishSchedule
import net.lapisphilosophorum.lapisnet.directory.InMemoryDirectoryModeStore
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptor
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundle
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyStore
import java.nio.file.Files
import java.util.Random
import java.util.concurrent.CompletableFuture
import kotlin.time.Duration.Companion.seconds

/**
 * A mesh stand-in: like the relay it acknowledges every publication ([ack] decides), but it only delivers to the
 * subscribers that exist at the moment of the publication (GossipSub gives late subscribers no history).
 */
private class FakeMeshChannel(
    private val clock: () -> Long,
    var ack: (call: Int) -> Boolean = { true },
) : DirectoryPublicationChannel {
    class Subscriber {
        val records = ArrayList<AnonymousPeerRecord>()
        val bundles = ArrayList<PrekeyBundle>()
    }

    override val exposesOrigin = false
    val subscribers = ArrayList<Subscriber>()
    val recordTimes = ArrayList<Long>()
    val recordSequences = ArrayList<Long>()
    val bundleSequences = ArrayList<Long>()
    private var calls = 0

    override fun publishAnonymousPeerRecord(record: AnonymousPeerRecord): CompletableFuture<Boolean> {
        val ok = ack(calls++)
        recordTimes += clock()
        recordSequences += record.sequenceNumber
        if (ok) subscribers.forEach { it.records += record }
        return CompletableFuture.completedFuture(ok)
    }

    override fun publishPrekeyBundle(bundle: PrekeyBundle): CompletableFuture<Boolean> {
        bundleSequences += bundle.sequenceNumber
        subscribers.forEach { it.bundles += bundle }
        return CompletableFuture.completedFuture(true)
    }

    override fun publishServiceDescriptor(descriptor: OnionServiceDescriptor) = CompletableFuture.completedFuture(true)
}

private class FixedJitter(
    private val value: Double,
) : Random() {
    override fun nextDouble(): Double = value
}

class AnonymousDirectoryPublisherEarlyRepublishTest :
    FunSpec({
        val identity = DualKeyIdentity.generate()
        val prekeys = PrekeyStore.create(Files.createTempDirectory("early-republish-prekeys"), identity)
        val zeroJitter = DirectoryRepublishSchedule(jitterFraction = 0.0)

        class Rig(
            schedule: DirectoryRepublishSchedule = zeroJitter,
            ack: (Int) -> Boolean = { true },
            maxVersionsPerMinute: Int = 4,
        ) {
            var now = System.currentTimeMillis()
            val start = now
            val channel = FakeMeshChannel({ now - start }, ack)
            val publisher =
                AnonymousDirectoryPublisher(
                    identity,
                    Ed25519KeyPair.generate(),
                    prekeys,
                    channel,
                    InMemoryDirectoryModeStore(),
                    clockMillis = { now },
                    earlySchedule = schedule,
                    maxVersionsPerMinute = maxVersionsPerMinute,
                )

            /** Ticks once per simulated second until [seconds] have passed. */
            fun run(seconds: Int) {
                repeat(seconds) {
                    publisher.tick()
                    now += 1000
                }
            }
        }

        test(
            "regression: a subscriber that joins after the first publication gets record and bundle without a restart",
        ) {
            val rig = Rig()
            rig.run(1) // first publication reaches nobody
            val late = FakeMeshChannel.Subscriber()
            rig.channel.subscribers += late
            late.records.size shouldBe 0
            rig.run(6 * 60)
            (late.records.isNotEmpty()) shouldBe true
            (late.bundles.isNotEmpty()) shouldBe true
            // it arrived with the first slot after it joined (15 s), long before the hourly republication
            (rig.channel.recordTimes[1] <= 16_000L) shouldBe true
            (rig.now - rig.start < 6 * 60_000L + 2_000L) shouldBe true
        }

        test("slots that fell due during a suspend are merged into exactly one publication") {
            val rig = Rig()
            rig.run(1)
            rig.publisher.publications shouldBe 1
            rig.now += 10 * 60_000L // suspend: all five slots are overdue
            rig.publisher.tick()
            rig.publisher.publications shouldBe 2
            rig.publisher.earlyRepublications shouldBe 1
            repeat(30) {
                rig.now += 1000
                rig.publisher.tick()
            }
            rig.publisher.publications shouldBe 2 // nothing left: no catch-up salvo
        }

        test(
            "exactly as many early publications as slots, then quiet until the hourly one, which does not restart the schedule",
        ) {
            val rig = Rig()
            rig.run(59 * 60)
            rig.publisher.earlyRepublications shouldBe 5
            rig.publisher.publications shouldBe 6
            rig.run(90 * 60) // crosses the hourly republication
            rig.publisher.earlyRepublications shouldBe 5
            (rig.publisher.publications in 7..8) shouldBe true
        }

        test("dense slots plus failures never exceed maxVersionsPerMinute versions in a rolling 60 s window") {
            val dense =
                DirectoryRepublishSchedule(
                    offsets = listOf(4, 8, 12, 16, 20, 24, 28, 32).map { it.seconds },
                    jitterFraction = 0.0,
                )
            val rig = Rig(dense, ack = { it != 3 && it != 4 })
            rig.run(5 * 60)
            val times = rig.channel.recordTimes
            (times.size >= 5) shouldBe true
            for (t in times) {
                (times.count { it >= t && it < t + 60_000L } <= 4) shouldBe true
            }
            // deferred and failed slots are merged, never dropped silently: all of them are served by the end
            (rig.publisher.earlyRepublications in 1..8) shouldBe true
            rig.publisher.nextDelayMillis() shouldBe 60_000L
        }

        test("failed publications back off 5 s, 15 s, 45 s and then every 60 s, without a storm") {
            val rig = Rig(ack = { false })
            rig.run(130)
            rig.channel.recordTimes.map { it / 1000 } shouldBe listOf(0L, 5L, 20L, 65L, 125L)
            rig.publisher.publications shouldBe 0
            rig.publisher.attempts shouldBe 5
        }

        test("every publication is a new version: record and bundle sequences rise strictly") {
            val rig = Rig()
            rig.run(6 * 60)
            val records = rig.channel.recordSequences
            val bundles = rig.channel.bundleSequences
            records.size shouldBe 6
            bundles.size shouldBe 6
            records.zipWithNext().all { (a, b) -> b > a } shouldBe true
            bundles.zipWithNext().all { (a, b) -> b > a } shouldBe true
        }

        test("nextDelayMillis follows the schedule, the backoff and the retry cap") {
            val rig = Rig()
            rig.publisher.nextDelayMillis() shouldBe 1_000L // nothing published yet: due now, floored at 1 s
            rig.publisher.tick() shouldBe true
            rig.publisher.nextDelayMillis() shouldBe 5_000L // first slot
            rig.now += 5_000
            rig.publisher.tick()
            rig.publisher.nextDelayMillis() shouldBe 10_000L // 15 s slot
            rig.now += 6 * 60_000L
            repeat(6) {
                rig.publisher.tick()
                rig.now += 3_000
            }
            rig.publisher.nextDelayMillis() shouldBe 60_000L // capped at retryInterval, nothing due for an hour

            val failing = Rig(ack = { false })
            failing.publisher.tick() shouldBe false
            failing.publisher.nextDelayMillis() shouldBe 5_000L
        }

        test("the version rate must stay below the receivers' per-author rate") {
            val rig = Rig()
            rig.run(1)
            val tooHigh =
                runCatching {
                    AnonymousDirectoryPublisher(
                        identity,
                        Ed25519KeyPair.generate(),
                        prekeys,
                        rig.channel,
                        InMemoryDirectoryModeStore(),
                        maxVersionsPerMinute = 6,
                    )
                }
            tooHigh.isFailure shouldBe true
        }
    })
