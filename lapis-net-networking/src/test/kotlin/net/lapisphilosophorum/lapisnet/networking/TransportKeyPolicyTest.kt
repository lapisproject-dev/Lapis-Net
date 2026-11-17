package net.lapisphilosophorum.lapisnet.networking

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldContainAll
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.libp2p.core.PeerId
import io.libp2p.core.PeerInfo
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.config.TransportKeyPolicy

/**
 * Wave V0.10.0-J1a: the transport key of anonymity mode is fresh per run and carries no link to the identity; normal
 * mode keeps the identity-derived key, mDNS and the exact protocol set it had before.
 */
class TransportKeyPolicyTest :
    FunSpec({
        test("the ephemeral key differs from the derived one and from every other run") {
            val identity = DualKeyIdentity.generate()
            val derived = TransportKeyPolicy.IdentityDerived.resolve(identity)
            derived.publicKey() shouldBe identity.deriveLibp2pPrivKey().publicKey()
            val first = TransportKeyPolicy.EphemeralPerRun.resolve(identity)
            val second = TransportKeyPolicy.EphemeralPerRun.resolve(identity)
            first.publicKey() shouldNotBe derived.publicKey()
            second.publicKey() shouldNotBe first.publicKey()
            // still a usable Ed25519 key: it signs and verifies
            val message = "lapis".toByteArray()
            first.publicKey().verify(message, first.sign(message)) shouldBe true
        }

        test("a node with the ephemeral key shows a PeerId unrelated to the identity and a new one per run") {
            val identity = DualKeyIdentity.generate()
            val ids = ArrayList<PeerId>()
            repeat(2) {
                val node =
                    LapisNode.create(
                        identity,
                        transportKey = TransportKeyPolicy.EphemeralPerRun,
                        mdnsEnabled = false,
                    )
                try {
                    node.start()
                    ids += node.peerId
                    node.peerId shouldNotBe identity.deriveLibp2pPeerId()
                    node.mdnsRunning shouldBe false
                } finally {
                    node.stop()
                }
            }
            ids[0] shouldNotBe ids[1]
        }

        test("a peer that connects sees the ephemeral PeerId, never the identity-derived one") {
            val identity = DualKeyIdentity.generate()
            val anonymous =
                LapisNode.create(identity, transportKey = TransportKeyPolicy.EphemeralPerRun, mdnsEnabled = false)
            val other = LapisNode.create(DualKeyIdentity.generate())
            try {
                anonymous.start()
                other.start()
                other.connect(PeerInfo(anonymous.peerId, anonymous.listenAddresses()))
                val seen =
                    other.host.network.connections
                        .map { it.secureSession().remoteId }
                seen shouldContainAll listOf(anonymous.peerId)
                (identity.deriveLibp2pPeerId() in seen) shouldBe false
            } finally {
                runCatching { anonymous.stop() }
                runCatching { other.stop() }
            }
        }

        test("mode off is unchanged: derived PeerId, mDNS running and the same protocol set as before wave J") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            try {
                node.start()
                node.peerId shouldBe identity.deriveLibp2pPeerId()
                node.mdnsRunning shouldBe true
                // snapshot of the protocols registered by LapisNode.create with default options (before wave J)
                node.registeredProtocolIds() shouldBe
                    setOf("/libp2p/circuit/relay/0.2.0/hop", "/libp2p/circuit/relay/0.2.0/stop")
            } finally {
                node.stop()
            }
            node.mdnsRunning shouldBe false
        }

        test("an anonymity-mode node registers the same base protocols, without mDNS") {
            val node =
                LapisNode.create(
                    DualKeyIdentity.generate(),
                    transportKey = TransportKeyPolicy.EphemeralPerRun,
                    mdnsEnabled = false,
                )
            try {
                node.start()
                node.mdnsRunning shouldBe false
                node.registeredProtocolIds() shouldBe
                    setOf("/libp2p/circuit/relay/0.2.0/hop", "/libp2p/circuit/relay/0.2.0/stop")
            } finally {
                node.stop()
            }
        }
    })
