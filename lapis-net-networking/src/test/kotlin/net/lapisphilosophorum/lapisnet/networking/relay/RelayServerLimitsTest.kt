package net.lapisphilosophorum.lapisnet.networking.relay

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import java.time.Duration

class RelayServerLimitsTest :
    FunSpec({
        test("circuitStallTimeout defaults to 30 seconds") {
            RelayServerLimits().circuitStallTimeout shouldBe Duration.ofSeconds(30)
        }

        test("circuitStallTimeout must be positive") {
            shouldThrow<IllegalArgumentException> { RelayServerLimits(circuitStallTimeout = Duration.ZERO) }
                .message shouldContain "circuitStallTimeout"
            shouldThrow<IllegalArgumentException> {
                RelayServerLimits(circuitStallTimeout = Duration.ofSeconds(-1))
            }.message shouldContain "circuitStallTimeout"
        }

        test("a stall timeout at or above circuitMaxDuration is accepted (it just disables the bound in practice)") {
            val limits =
                RelayServerLimits(
                    circuitMaxDuration = Duration.ofMinutes(1),
                    circuitStallTimeout = Duration.ofMinutes(5),
                )
            limits.circuitStallTimeout shouldBe Duration.ofMinutes(5)
        }

        test("connection stall budget defaults to 60 s per 10 min window") {
            RelayServerLimits().connectionStallBudget shouldBe Duration.ofSeconds(60)
            RelayServerLimits().connectionStallBudgetWindow shouldBe Duration.ofMinutes(10)
        }

        test("connection stall budget must be positive and shorter than its window") {
            shouldThrow<IllegalArgumentException> { RelayServerLimits(connectionStallBudget = Duration.ZERO) }
                .message shouldContain "connectionStallBudget"
            shouldThrow<IllegalArgumentException> {
                RelayServerLimits(
                    connectionStallBudget = Duration.ofMinutes(10),
                    connectionStallBudgetWindow = Duration.ofMinutes(10),
                )
            }.message shouldContain "connectionStallBudgetWindow"
        }

        test("connection stall grace defaults to 1 s, may be zero, must not be negative") {
            RelayServerLimits().connectionStallGrace shouldBe Duration.ofSeconds(1)
            RelayServerLimits(connectionStallGrace = Duration.ZERO).connectionStallGrace shouldBe Duration.ZERO
            shouldThrow<IllegalArgumentException> {
                RelayServerLimits(connectionStallGrace = Duration.ofMillis(-1))
            }.message shouldContain "connectionStallGrace"
        }
    })
