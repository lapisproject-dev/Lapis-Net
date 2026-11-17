package net.lapisphilosophorum.lapisnet.networking

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldNotContain
import io.libp2p.core.PeerId
import io.libp2p.core.PeerInfo
import io.libp2p.core.pubsub.ValidationResult
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.config.TransportKeyPolicy
import java.util.Collections
import kotlin.time.Duration.Companion.seconds

private const val ALLOWED = "LapisNet:peer-record-gossip:v1"
private const val NOT_ALLOWED = "LapisNet:inbox:v1:deadbeef"

/** Wave V0.10.0-J1a: GossipSub under the anonymity policy receives and forwards, but publishes nothing of its own. */
class GossipPubSubPolicyTest :
    FunSpec({
        test("a topic outside the allowlist is refused without naming it; an allowed one works") {
            val node = LapisNode.create(DualKeyIdentity.generate(), mdnsEnabled = false)
            try {
                node.start()
                val pubsub = GossipPubSub.attach(node, GossipAnonymityPolicy())
                val refused =
                    shouldThrow<GossipAnonymityRefusedException> {
                        pubsub.subscribe(
                            NOT_ALLOWED,
                        ) { _, _ -> ValidationResult.Valid }
                    }
                refused.message!! shouldNotContain NOT_ALLOWED
                pubsub.refusedSubscriptions shouldBe 1
                (NOT_ALLOWED in pubsub.subscribedTopics()) shouldBe false
                pubsub.subscribe(ALLOWED) { _, _ -> ValidationResult.Valid }
                (ALLOWED in pubsub.subscribedTopics()) shouldBe true
            } finally {
                node.stop()
            }
        }

        test("every own publication is refused before the test tap sees it") {
            val node = LapisNode.create(DualKeyIdentity.generate(), mdnsEnabled = false)
            try {
                node.start()
                val pubsub = GossipPubSub.attach(node, GossipAnonymityPolicy())
                val tapped = Collections.synchronizedList(ArrayList<String>())
                pubsub.outboundTap = { topic, _ -> tapped += topic }
                shouldThrow<GossipAnonymityRefusedException> { pubsub.publish(ALLOWED, byteArrayOf(1)) }
                shouldThrow<GossipAnonymityRefusedException> { pubsub.publishReporting(ALLOWED, byteArrayOf(1)) }
                // a GossipPubSubException, so existing "not delivered" handling applies
                shouldThrow<GossipPubSubException> { pubsub.publish(NOT_ALLOWED, byteArrayOf(1)) }
                tapped shouldBe emptyList()
                pubsub.refusedPublications shouldBe 3
            } finally {
                node.stop()
            }
        }

        test("without a policy nothing changes: any topic, any publication") {
            val node = LapisNode.create(DualKeyIdentity.generate(), mdnsEnabled = false)
            try {
                node.start()
                val pubsub = GossipPubSub.attach(node)
                pubsub.anonymityRestricted shouldBe false
                pubsub.subscribe(NOT_ALLOWED) { _, _ -> ValidationResult.Valid }
                val tapped = Collections.synchronizedList(ArrayList<String>())
                pubsub.outboundTap = { topic, _ -> tapped += topic }
                // no mesh peer: reported as not delivered, but attempted
                pubsub.publishReporting(NOT_ALLOWED, byteArrayOf(1)) shouldBe false
                tapped shouldBe listOf(NOT_ALLOWED)
            } finally {
                node.stop()
            }
        }

        test(
            "a node under the policy still forwards: A to M (anonymity, ephemeral key) to C",
        ).config(timeout = 60.seconds) {
            val a = LapisNode.create(DualKeyIdentity.generate(), mdnsEnabled = false)
            val m =
                LapisNode.create(
                    DualKeyIdentity.generate(),
                    transportKey = TransportKeyPolicy.EphemeralPerRun,
                    mdnsEnabled = false,
                )
            val c = LapisNode.create(DualKeyIdentity.generate(), mdnsEnabled = false)
            try {
                listOf(a, m, c).forEach { it.start() }
                val ga = GossipPubSub.attach(a)
                val gm = GossipPubSub.attach(m, GossipAnonymityPolicy())
                val gc = GossipPubSub.attach(c)
                val atM = Collections.synchronizedList(ArrayList<ByteArray>())
                val atC = Collections.synchronizedList(ArrayList<Pair<ByteArray, PeerId>>())
                ga.subscribe(ALLOWED) { _, _ -> ValidationResult.Valid }
                gm.subscribe(ALLOWED) { bytes, _ ->
                    atM += bytes
                    ValidationResult.Valid
                }
                gc.subscribe(ALLOWED) { bytes, from ->
                    atC += bytes to from
                    ValidationResult.Valid
                }
                // a line A - M - C: C can only get A's message through M
                a.connect(PeerInfo(m.peerId, m.listenAddresses()))
                c.connect(PeerInfo(m.peerId, m.listenAddresses()))
                val payload = "forwarded by an anonymity-mode node".toByteArray()
                val deadline = System.nanoTime() + 30_000_000_000L
                while (atC.isEmpty() && System.nanoTime() < deadline) {
                    runCatching { ga.publish(ALLOWED, payload) }
                    Thread.sleep(500)
                }
                atC.toList().shouldNotBeEmpty()
                atC.first().first shouldBe payload
                // the original publisher stays A (M only forwarded)
                atC.first().second shouldBe a.peerId
                atM.toList().shouldNotBeEmpty()
                gm.refusedPublications shouldBe 0
            } finally {
                listOf(a, m, c).forEach { runCatching { it.stop() } }
            }
        }
    })
