package net.lapisphilosophorum.lapisnet.storage

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import java.time.Duration

class DhtLimitsTest :
    FunSpec({
        test("defaults are the documented values and valid") {
            val limits = DhtLimits()
            limits.provideFanout shouldBe 20
            limits.walkParallelism shouldBe 3
            limits.maxWalkRounds shouldBe 8
            limits.perRpcTimeout shouldBe Duration.ofSeconds(2)
            limits.maxCloserPeersPerResponse shouldBe 20
            limits.maxAddressesPerPeer shouldBe 8
            limits.maxAddressesPerIp shouldBe 2
            limits.maxAddressBytes shouldBe 256
            limits.maxProvidersPerKey shouldBe 8
            limits.providerStoreKeyCapacity shouldBe 1024
            limits.maxConcurrentDhtOperations shouldBe 8
            limits.maxConcurrentFetches shouldBe 4
            limits.fetchConnectTimeout shouldBe Duration.ofSeconds(5)
            limits.streamCloseGrace shouldBe Duration.ofSeconds(1)
        }

        val invalid: Map<String, () -> DhtLimits> =
            mapOf(
                "provideFanout zero" to { DhtLimits(provideFanout = 0) },
                "provideFanout above the maximum" to { DhtLimits(provideFanout = 65) },
                "walkParallelism zero" to { DhtLimits(walkParallelism = 0) },
                "walkParallelism above provideFanout" to { DhtLimits(provideFanout = 2, walkParallelism = 3) },
                "maxWalkRounds zero" to { DhtLimits(maxWalkRounds = 0) },
                "maxWalkRounds above the maximum" to { DhtLimits(maxWalkRounds = 33) },
                "perRpcTimeout zero" to { DhtLimits(perRpcTimeout = Duration.ZERO) },
                "perRpcTimeout negative" to { DhtLimits(perRpcTimeout = Duration.ofSeconds(-1)) },
                "maxCloserPeersPerResponse zero" to { DhtLimits(maxCloserPeersPerResponse = 0) },
                "maxAddressesPerPeer zero" to { DhtLimits(maxAddressesPerPeer = 0) },
                "maxAddressesPerPeer above the maximum" to { DhtLimits(maxAddressesPerPeer = 65) },
                "maxAddressesPerIp zero" to { DhtLimits(maxAddressesPerIp = 0) },
                "maxAddressesPerIp above maxAddressesPerPeer" to {
                    DhtLimits(maxAddressesPerPeer = 4, maxAddressesPerIp = 5)
                },
                "maxAddressBytes below the minimum" to { DhtLimits(maxAddressBytes = 31) },
                "maxProvidersPerKey zero" to { DhtLimits(maxProvidersPerKey = 0) },
                "providerStoreKeyCapacity zero" to { DhtLimits(providerStoreKeyCapacity = 0) },
                "maxConcurrentDhtOperations zero" to { DhtLimits(maxConcurrentDhtOperations = 0) },
                "maxConcurrentFetches zero" to { DhtLimits(maxConcurrentFetches = 0) },
                "fetchConnectTimeout zero" to { DhtLimits(fetchConnectTimeout = Duration.ZERO) },
                "streamCloseGrace zero" to { DhtLimits(streamCloseGrace = Duration.ZERO) },
            )
        for ((name, build) in invalid) {
            test("rejects $name") {
                shouldThrow<IllegalArgumentException> { build() }
            }
        }
    })
