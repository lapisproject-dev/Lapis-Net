package net.lapisphilosophorum.lapisnet.onionwire

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.seconds

class OnionWireConfigTest :
    FunSpec({
        test("defaults are valid") {
            OnionWireConfig()
        }

        test("inconsistent or non-positive values are refused") {
            shouldThrow<IllegalArgumentException> { OnionWireConfig(maxLinks = 0) }
            shouldThrow<IllegalArgumentException> { OnionWireConfig(cellsPerSecondPerLink = 0) }
            shouldThrow<IllegalArgumentException> { OnionWireConfig(extendTimeout = 0.seconds) }
            shouldThrow<IllegalArgumentException> {
                OnionWireConfig(
                    onionKeyLifetime = 3.days,
                    onionKeyRotateAfter = 4.days,
                )
            }
            shouldThrow<IllegalArgumentException> { OnionWireConfig(descriptorTtl = 48.hours) }
            shouldThrow<IllegalArgumentException> {
                OnionWireConfig(descriptorTtl = 1.hours, descriptorRepublishInterval = 2.hours)
            }
            shouldThrow<IllegalArgumentException> { OnionWireConfig(dialThreads = 0) }
        }
    })
