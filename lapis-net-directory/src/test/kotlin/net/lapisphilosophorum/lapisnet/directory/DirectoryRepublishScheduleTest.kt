package net.lapisphilosophorum.lapisnet.directory

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import java.util.Random
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

/** A random source that always returns the same fraction (0.0 = lowest jitter, 1.0-eps = highest). */
private class FixedRandom(
    private val value: Double,
) : Random() {
    override fun nextDouble(): Double = value
}

class DirectoryRepublishScheduleTest :
    FunSpec({
        test("slots stay inside the jitter band and are strictly increasing for a fixed seed") {
            val schedule = DirectoryRepublishSchedule(random = Random(42))
            val plan = schedule.plan(1_000_000L)
            plan.size shouldBe DirectoryRepublishSchedule.DEFAULT_OFFSETS.size
            for ((i, offset) in schedule.offsets.withIndex()) {
                val base = offset.inWholeMilliseconds
                ((plan[i] - 1_000_000L) in (base * 8 / 10)..(base * 12 / 10)) shouldBe true
            }
            plan.toList().zipWithNext().all { (a, b) -> b > a } shouldBe true
        }

        test("consecutive slots are at least MIN_GAP apart even with extreme jitter") {
            val schedule =
                DirectoryRepublishSchedule(
                    offsets = listOf(5.seconds, 6.seconds, 7.seconds),
                    jitterFraction = 0.3,
                    random = FixedRandom(0.0),
                )
            schedule.plan(0L).toList().zipWithNext().all { (a, b) ->
                b - a >= DirectoryRepublishSchedule.MIN_GAP.inWholeMilliseconds
            } shouldBe true
            for (seed in 1L..50L) {
                DirectoryRepublishSchedule(random = Random(seed)).plan(0L).toList().zipWithNext().all { (a, b) ->
                    b - a >= DirectoryRepublishSchedule.MIN_GAP.inWholeMilliseconds
                } shouldBe true
            }
        }

        test("invalid offsets and jitter are rejected") {
            shouldThrow<IllegalArgumentException> {
                DirectoryRepublishSchedule(
                    offsets = listOf(10.seconds, 5.seconds),
                )
            }
            shouldThrow<IllegalArgumentException> { DirectoryRepublishSchedule(offsets = listOf(5.seconds, 5.seconds)) }
            shouldThrow<IllegalArgumentException> { DirectoryRepublishSchedule(offsets = listOf((-1).seconds)) }
            shouldThrow<IllegalArgumentException> { DirectoryRepublishSchedule(offsets = listOf(0.seconds)) }
            shouldThrow<IllegalArgumentException> {
                DirectoryRepublishSchedule(
                    offsets = List(DirectoryRepublishSchedule.MAX_STEPS + 1) { (it + 1).minutes },
                )
            }
            shouldThrow<IllegalArgumentException> { DirectoryRepublishSchedule(jitterFraction = 0.5) }
            shouldThrow<IllegalArgumentException> { DirectoryRepublishSchedule(jitterFraction = -0.1) }
        }

        test("an empty schedule plans nothing") {
            DirectoryRepublishSchedule(offsets = emptyList()).plan(5L).size shouldBe 0
        }
    })
