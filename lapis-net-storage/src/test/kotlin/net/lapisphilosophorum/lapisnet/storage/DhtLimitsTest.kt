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
            limits.maxIpnsRecordBytes shouldBe 10_240
            limits.recordStoreCapacity shouldBe 1024
            limits.maxRecordValidity shouldBe Duration.ofDays(7)
            limits.maxClockSkew shouldBe Duration.ofMinutes(5)
            limits.valuePutFanout shouldBe 8
            limits.resolveQuorum shouldBe 3
            limits.maxValuePutsPerSourcePerMinute shouldBe 6
            limits.valueRateTrackerCapacity shouldBe 1024
            limits.routingBucketSize shouldBe 20
            limits.routingReplacementCacheSize shouldBe 8
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
                "maxIpnsRecordBytes below the minimum" to { DhtLimits(maxIpnsRecordBytes = 511) },
                "maxIpnsRecordBytes above Nabu's hard limit" to { DhtLimits(maxIpnsRecordBytes = 10_241) },
                "recordStoreCapacity zero" to { DhtLimits(recordStoreCapacity = 0) },
                "maxRecordValidity zero" to { DhtLimits(maxRecordValidity = Duration.ZERO) },
                "maxClockSkew negative" to { DhtLimits(maxClockSkew = Duration.ofSeconds(-1)) },
                "valuePutFanout zero" to { DhtLimits(valuePutFanout = 0) },
                "valuePutFanout above the maximum" to { DhtLimits(valuePutFanout = 65) },
                "resolveQuorum zero" to { DhtLimits(resolveQuorum = 0) },
                "resolveQuorum above valuePutFanout" to { DhtLimits(valuePutFanout = 2, resolveQuorum = 3) },
                "maxValuePutsPerSourcePerMinute zero" to { DhtLimits(maxValuePutsPerSourcePerMinute = 0) },
                "valueRateTrackerCapacity zero" to { DhtLimits(valueRateTrackerCapacity = 0) },
                "routingBucketSize zero" to { DhtLimits(routingBucketSize = 0) },
                "routingBucketSize above the maximum" to { DhtLimits(routingBucketSize = 65) },
                "routingReplacementCacheSize zero" to { DhtLimits(routingReplacementCacheSize = 0) },
                "routingReplacementCacheSize above the maximum" to { DhtLimits(routingReplacementCacheSize = 65) },
            )
        for ((name, build) in invalid) {
            test("rejects $name") {
                shouldThrow<IllegalArgumentException> { build() }
            }
        }
    })
