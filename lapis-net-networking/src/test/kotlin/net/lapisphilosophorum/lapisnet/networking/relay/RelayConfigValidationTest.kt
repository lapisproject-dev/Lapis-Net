package net.lapisphilosophorum.lapisnet.networking.relay

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import java.time.Duration

class RelayConfigValidationTest :
    FunSpec({
        test("defaults are valid and unspecified") {
            RelayConfig().reachability shouldBe NodeReachability.UNSPECIFIED
            RelayConfig().autoRelay.targetRelayCount shouldBe 2
        }

        test("a PRIVATE node needs targetRelayCount within clientLimits.maxReservations") {
            shouldThrow<IllegalArgumentException> {
                RelayConfig(
                    reachability = NodeReachability.PRIVATE,
                    clientLimits = RelayClientLimits(maxReservations = 1),
                    autoRelay = AutoRelayConfig(targetRelayCount = 2),
                )
            }
            RelayConfig(
                reachability = NodeReachability.PRIVATE,
                clientLimits = RelayClientLimits(maxReservations = 2),
                autoRelay = AutoRelayConfig(targetRelayCount = 2),
            )
        }

        test("AutoRelayConfig rejects non-positive values") {
            shouldThrow<IllegalArgumentException> { AutoRelayConfig(targetRelayCount = 0) }
            shouldThrow<IllegalArgumentException> { AutoRelayConfig(reselectInterval = Duration.ZERO) }
            shouldThrow<IllegalArgumentException> { AutoRelayConfig(candidateLimit = 0) }
            shouldThrow<IllegalArgumentException> { AutoRelayConfig(maxAttemptsPerPass = 0) }
            shouldThrow<IllegalArgumentException> { AutoRelayConfig(failureBackoff = Duration.ofSeconds(-1)) }
            shouldThrow<IllegalArgumentException> { AutoRelayConfig(maxBackoffEntries = 0) }
        }
    })
