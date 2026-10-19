package net.lapisphilosophorum.lapisnet.madli

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

class MadliRelayMetricsTest :
    FunSpec({
        test("accepts the boundary values 0 and 1_000_000") {
            MadliRelayMetrics(0, 0).relayReliabilityMicros shouldBe 0
            MadliRelayMetrics(1_000_000, 5).relayReliabilityMicros shouldBe 1_000_000
        }

        test("rejects reliability out of range") {
            shouldThrow<IllegalArgumentException> { MadliRelayMetrics(-1, 1) }
            shouldThrow<IllegalArgumentException> { MadliRelayMetrics(1_000_001, 1) }
            shouldThrow<IllegalArgumentException> { MadliRelayMetrics(Int.MAX_VALUE, 1) }
        }

        test("rejects a negative attempt count") {
            shouldThrow<IllegalArgumentException> { MadliRelayMetrics(1, -1) }
        }
    })
