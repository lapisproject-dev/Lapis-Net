package net.lapisphilosophorum.lapisnet.networking

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

/**
 * Unit-level test of [GossipPubSub.buildGossipParams] - the [io.libp2p.pubsub.gossip.GossipParams]
 * [GossipPubSub.attach] actually builds and installs. Exercised directly against the internal test
 * seam rather than through a full running node, since these are plain config values.
 *
 * Round-2 M1 regression test: `GossipParamsBuilder`'s real default for `maxPublishedMessages` (and
 * several sibling RPC-shape fields) is `null` - confirmed by decompiling `GossipParams`/
 * `GossipParamsBuilder` against the real jvm-libp2p jar - which `PubsubRpcLimits` treats as "no
 * limit" on how many entries a single incoming RPC frame may carry. This asserts the explicit,
 * documented bounds [GossipPubSub] now sets are actually the ones that land in the built params,
 * not just present in source.
 */
class GossipPubSubParamsTest :
    FunSpec({
        test("buildGossipParams sets an explicit, non-null maxPublishedMessages bound") {
            val params = GossipPubSub.buildGossipParams()

            params.maxPublishedMessages shouldBe 48
        }

        test("buildGossipParams sets an explicit, non-null maxSubscriptionsPerRpc bound") {
            val params = GossipPubSub.buildGossipParams()

            params.maxSubscriptionsPerRpc shouldBe 64
        }

        test("buildGossipParams keeps the existing maxGossipMessageSize bound") {
            val params = GossipPubSub.buildGossipParams()

            params.maxGossipMessageSize shouldBe 262_144
        }
    })
