package net.lapisphilosophorum.lapisnet.dm

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.pubsub.ValidationResult
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.networking.deriveLibp2pPeerId
import net.lapisphilosophorum.lapisnet.policy.AcceptanceGate
import net.lapisphilosophorum.lapisnet.policy.KarmaScoreLookup
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import net.lapisphilosophorum.lapisnet.trust.TrustGraph
import java.nio.file.Files

private fun testCid(seed: Byte): Cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { seed })

/**
 * [MailboxGossip.onGossipMessage]'s V0.8.6 offline pre-check ([DmAcceptanceCheck] wiring) -
 * mirrors [MailboxGossipOnGossipMessageTest]'s established seam.
 */
class MailboxGossipAcceptanceTest :
    FunSpec({
        test("a pointer from a non-gated sender is rejected BEFORE persistence - not tracked, not indexed") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("mailbox-acceptance-a"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = MailboxPointerIndex()
                val localIdentity = identity.secp256k1KeyPair.publicKey
                val sender = DualKeyIdentity.generate().secp256k1KeyPair

                // No trust path from localIdentity to sender - VeritasPath gate fails, and no
                // pointerDepositLookup is configured (default { null }), so an out-of-band deposit
                // can never unlock this either.
                val acceptance =
                    DmAcceptanceCheck(
                        gates = listOf(AcceptanceGate.VeritasPath),
                        trustGraph = TrustGraph.fromEdges(emptyList()),
                        karmaScoreOf = KarmaScoreLookup { 0.0 },
                    )

                val pointer =
                    MailboxPointer.create(
                        sender = sender,
                        recipientIdentity = localIdentity,
                        blobCid = testCid(1),
                        notValidAfterEpochSecond = 1_000_000L,
                        nowEpochSecond = 0,
                    )
                val bytes = MailboxPointerCodec.encode(pointer)

                val result = MailboxGossip.onGossipMessage(bytes, from, storage, index, localIdentity, acceptance)

                result shouldBe ValidationResult.Invalid
                index.size() shouldBe 0
                index.pending().size shouldBe 0

                // Prove nothing was persisted - the mint-CID technique this file's sibling test
                // already established.
                val mintingNode = LapisNode.create(DualKeyIdentity.generate())
                mintingNode.start(bootstrapPeers = emptyList())
                try {
                    val mintingStorage =
                        NabuStorage.attach(
                            mintingNode,
                            Files.createTempDirectory("mailbox-acceptance-a-mint"),
                        )
                    storage.get(mintingStorage.put(bytes)) shouldBe null
                } finally {
                    mintingNode.stop()
                }
            } finally {
                node.stop()
            }
        }

        test("a pointer from a Veritas-trusted sender is accepted and tracked") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("mailbox-acceptance-b"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = MailboxPointerIndex()
                val localIdentity = identity.secp256k1KeyPair.publicKey
                val sender = DualKeyIdentity.generate().secp256k1KeyPair

                val graph = TrustGraph.fromEdges(listOf(Triple(localIdentity, sender.publicKey, 1_000_000)))
                val acceptance =
                    DmAcceptanceCheck(
                        gates = listOf(AcceptanceGate.VeritasPath),
                        trustGraph = graph,
                        karmaScoreOf = KarmaScoreLookup { 0.0 },
                    )

                val pointer =
                    MailboxPointer.create(
                        sender = sender,
                        recipientIdentity = localIdentity,
                        blobCid = testCid(1),
                        notValidAfterEpochSecond = 1_000_000L,
                        nowEpochSecond = 0,
                    )
                val bytes = MailboxPointerCodec.encode(pointer)

                val result = MailboxGossip.onGossipMessage(bytes, from, storage, index, localIdentity, acceptance)

                result shouldBe ValidationResult.Valid
                index.pending().size shouldBe 1
            } finally {
                node.stop()
            }
        }

        test(
            "with gates = ACCEPT_ALL, behavior is bit-identical to V0.8.5 (no acceptance check) and " +
                "pointerDepositLookup is NEVER invoked",
        ) {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("mailbox-acceptance-c"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = MailboxPointerIndex()
                val localIdentity = identity.secp256k1KeyPair.publicKey
                val sender = DualKeyIdentity.generate().secp256k1KeyPair

                var lookupCalls = 0
                val acceptance =
                    DmAcceptanceCheck(
                        gates = DmAcceptancePolicy.ACCEPT_ALL,
                        trustGraph = TrustGraph.fromEdges(emptyList()),
                        karmaScoreOf = KarmaScoreLookup { 0.0 },
                        pointerDepositLookup = {
                            lookupCalls++
                            null
                        },
                    )

                val pointer =
                    MailboxPointer.create(
                        sender = sender,
                        recipientIdentity = localIdentity,
                        blobCid = testCid(1),
                        notValidAfterEpochSecond = 1_000_000L,
                        nowEpochSecond = 0,
                    )
                val bytes = MailboxPointerCodec.encode(pointer)

                val result = MailboxGossip.onGossipMessage(bytes, from, storage, index, localIdentity, acceptance)

                result shouldBe ValidationResult.Valid
                index.pending().size shouldBe 1
                lookupCalls shouldBe 0
            } finally {
                node.stop()
            }
        }
    })
