package net.lapisphilosophorum.lapisnet.dm

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.pubsub.ValidationResult
import net.lapisphilosophorum.lapisnet.directory.OutboxEntry
import net.lapisphilosophorum.lapisnet.directory.OutboxEntryKind
import net.lapisphilosophorum.lapisnet.directory.OutboxIngestOutcome
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.networking.deriveLibp2pPeerId
import net.lapisphilosophorum.lapisnet.policy.AcceptanceGate
import net.lapisphilosophorum.lapisnet.policy.KarmaScoreLookup
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import net.lapisphilosophorum.lapisnet.trust.TrustGraph
import java.nio.file.Files

private fun cid(seed: Byte): Cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { seed })

/**
 * [MailboxGossip.onDhtEntry] (V0.9.14): the DHT path into the same index, with the same checks as
 * [MailboxGossip.onGossipMessage] - plus the binding of the pointer to the outbox entry it came in.
 */
class MailboxGossipDhtEntryTest :
    FunSpec({
        val identity = DualKeyIdentity.generate()
        val node = LapisNode.create(identity)
        node.start(bootstrapPeers = emptyList())
        val storage = NabuStorage.attach(node, Files.createTempDirectory("mailbox-dht-entry"))
        val local = identity.secp256k1KeyPair.publicKey
        val from = DualKeyIdentity.generate().deriveLibp2pPeerId()

        afterSpec { runCatching { node.stop() } }

        fun pointerFrom(
            sender: Secp256k1KeyPair,
            recipient: Secp256k1PublicKey = local,
            seed: Byte = 1,
            notValidAfter: Long = 1_000_000L,
        ) = MailboxPointer.create(sender, recipient, cid(seed), notValidAfter, nowEpochSecond = 0)

        fun entryFor(
            pointer: MailboxPointer,
            recipient: Secp256k1PublicKey = pointer.recipientIdentity,
            notValidAfter: Long = pointer.notValidAfterEpochSecond,
            kind: OutboxEntryKind = OutboxEntryKind.DM_MAILBOX_POINTER,
            payload: ByteArray = MailboxPointerCodec.encode(pointer),
        ) = OutboxEntry(kind, recipient, notValidAfter, payload)

        test("a valid pointer from the right sender is accepted and becomes pending") {
            val sender = DualKeyIdentity.generate().secp256k1KeyPair
            val index = MailboxPointerIndex()
            val pointer = pointerFrom(sender)
            MailboxGossip.onDhtEntry(sender.publicKey, entryFor(pointer), storage, index, local) shouldBe
                OutboxIngestOutcome.ACCEPTED
            index.pending().map { it.contentId().toList() } shouldBe listOf(pointer.contentId().toList())
        }

        test("a forged signature is rejected") {
            val sender = DualKeyIdentity.generate().secp256k1KeyPair
            val index = MailboxPointerIndex()
            val pointer = pointerFrom(sender)
            val bytes = MailboxPointerCodec.encode(pointer)
            bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 1).toByte()
            MailboxGossip.onDhtEntry(
                sender.publicKey,
                entryFor(pointer, payload = bytes),
                storage,
                index,
                local,
            ) shouldBe
                OutboxIngestOutcome.REJECTED
            index.size() shouldBe 0
        }

        test("a pointer re-published under another identity's value is rejected") {
            val sender = DualKeyIdentity.generate().secp256k1KeyPair
            val thief = DualKeyIdentity.generate().secp256k1KeyPair
            val index = MailboxPointerIndex()
            val pointer = pointerFrom(sender)
            MailboxGossip.onDhtEntry(thief.publicKey, entryFor(pointer), storage, index, local) shouldBe
                OutboxIngestOutcome.REJECTED
            index.size() shouldBe 0
        }

        test("a wrong recipient - in the entry header or in the pointer - is rejected") {
            val sender = DualKeyIdentity.generate().secp256k1KeyPair
            val other = DualKeyIdentity.generate().secp256k1KeyPair.publicKey
            val index = MailboxPointerIndex()
            val toLocal = pointerFrom(sender)
            MailboxGossip.onDhtEntry(
                sender.publicKey,
                entryFor(toLocal, recipient = other),
                storage,
                index,
                local,
            ) shouldBe
                OutboxIngestOutcome.REJECTED
            val toOther = pointerFrom(sender, recipient = other)
            MailboxGossip.onDhtEntry(sender.publicKey, entryFor(toOther), storage, index, local) shouldBe
                OutboxIngestOutcome.REJECTED
            MailboxGossip.onDhtEntry(
                sender.publicKey,
                entryFor(toOther, recipient = local),
                storage,
                index,
                local,
            ) shouldBe
                OutboxIngestOutcome.REJECTED
            index.size() shouldBe 0
        }

        test("an expiry in the header that differs from the signed one is rejected") {
            val sender = DualKeyIdentity.generate().secp256k1KeyPair
            val index = MailboxPointerIndex()
            val pointer = pointerFrom(sender)
            MailboxGossip.onDhtEntry(
                sender.publicKey,
                entryFor(pointer, notValidAfter = pointer.notValidAfterEpochSecond + 1),
                storage,
                index,
                local,
            ) shouldBe OutboxIngestOutcome.REJECTED
        }

        test("the wrong kind and a broken payload are rejected") {
            val sender = DualKeyIdentity.generate().secp256k1KeyPair
            val index = MailboxPointerIndex()
            val pointer = pointerFrom(sender)
            MailboxGossip.onDhtEntry(
                sender.publicKey,
                entryFor(pointer, kind = OutboxEntryKind.MAIL_POINTER, payload = ByteArray(100) { 3 }),
                storage,
                index,
                local,
            ) shouldBe OutboxIngestOutcome.REJECTED
            MailboxGossip.onDhtEntry(
                sender.publicKey,
                entryFor(pointer, payload = ByteArray(200) { 5 }),
                storage,
                index,
                local,
            ) shouldBe OutboxIngestOutcome.REJECTED
            index.size() shouldBe 0
        }

        test("the same pointer by gossip and by the DHT is tracked once, in either order") {
            val sender = DualKeyIdentity.generate().secp256k1KeyPair
            val pointer = pointerFrom(sender)
            val bytes = MailboxPointerCodec.encode(pointer)

            val gossipFirst = MailboxPointerIndex()
            MailboxGossip.onGossipMessage(bytes, from, storage, gossipFirst, local) shouldBe ValidationResult.Valid
            MailboxGossip.onDhtEntry(sender.publicKey, entryFor(pointer), storage, gossipFirst, local) shouldBe
                OutboxIngestOutcome.DUPLICATE
            gossipFirst.size() shouldBe 1

            val dhtFirst = MailboxPointerIndex()
            MailboxGossip.onDhtEntry(sender.publicKey, entryFor(pointer), storage, dhtFirst, local) shouldBe
                OutboxIngestOutcome.ACCEPTED
            MailboxGossip.onGossipMessage(bytes, from, storage, dhtFirst, local) shouldBe ValidationResult.Invalid
            dhtFirst.size() shouldBe 1
        }

        test("acceptance policy: the DHT path declines exactly what the gossip path declines") {
            val sender = DualKeyIdentity.generate().secp256k1KeyPair
            val trusted = DualKeyIdentity.generate().secp256k1KeyPair
            val pointers = listOf(sender, trusted).map { pointerFrom(it, seed = 2) }

            fun check(
                name: String,
                acceptance: DmAcceptanceCheck,
            ) {
                for ((who, pointer) in listOf(sender, trusted).zip(pointers)) {
                    val gossipIndex = MailboxPointerIndex()
                    val dhtIndex = MailboxPointerIndex()
                    val viaGossip =
                        MailboxGossip.onGossipMessage(
                            MailboxPointerCodec.encode(pointer),
                            from,
                            storage,
                            gossipIndex,
                            local,
                            acceptance,
                        ) == ValidationResult.Valid
                    val viaDht =
                        MailboxGossip.onDhtEntry(
                            who.publicKey,
                            entryFor(pointer),
                            storage,
                            dhtIndex,
                            local,
                            acceptance,
                        ) ==
                            OutboxIngestOutcome.ACCEPTED
                    withClue("$name / ${who.publicKey.fingerprint()}") { viaDht shouldBe viaGossip }
                    dhtIndex.size() shouldBe gossipIndex.size()
                }
            }
            val graph = TrustGraph.fromEdges(listOf(Triple(local, trusted.publicKey, 1_000_000)))
            check(
                "veritas path",
                DmAcceptanceCheck(
                    gates = listOf(AcceptanceGate.VeritasPath),
                    trustGraph = graph,
                    karmaScoreOf = KarmaScoreLookup { 0.0 },
                ),
            )
            check(
                "karma",
                DmAcceptanceCheck(
                    gates = listOf(AcceptanceGate.KarmaThreshold(5.0)),
                    trustGraph = TrustGraph.fromEdges(emptyList()),
                    karmaScoreOf = KarmaScoreLookup { if (it == trusted.publicKey) 10.0 else 0.0 },
                ),
            )
            check(
                "accepted contact",
                DmAcceptanceCheck(
                    gates = listOf(AcceptanceGate.VeritasPath),
                    trustGraph = TrustGraph.fromEdges(emptyList()),
                    karmaScoreOf = KarmaScoreLookup { 0.0 },
                    isAcceptedContact = { contact -> contact == trusted.publicKey },
                ),
            )
            check(
                "accept all",
                DmAcceptanceCheck(
                    gates = DmAcceptancePolicy.ACCEPT_ALL,
                    trustGraph = TrustGraph.fromEdges(emptyList()),
                    karmaScoreOf = KarmaScoreLookup { 0.0 },
                ),
            )
        }

        test("a gated sender costs no persistence on the DHT path either") {
            val sender = DualKeyIdentity.generate().secp256k1KeyPair
            val index = MailboxPointerIndex()
            val acceptance =
                DmAcceptanceCheck(
                    gates = listOf(AcceptanceGate.VeritasPath),
                    trustGraph = TrustGraph.fromEdges(emptyList()),
                    karmaScoreOf = KarmaScoreLookup { 0.0 },
                )
            val pointer = pointerFrom(sender, seed = 9)
            MailboxGossip.onDhtEntry(sender.publicKey, entryFor(pointer), storage, index, local, acceptance) shouldBe
                OutboxIngestOutcome.REJECTED
            index.size() shouldBe 0
            index.pending().size shouldBe 0
        }

        test("with ACCEPT_ALL the deposit lookup is never invoked on the DHT path") {
            val sender = DualKeyIdentity.generate().secp256k1KeyPair
            var calls = 0
            val acceptance =
                DmAcceptanceCheck(
                    gates = DmAcceptancePolicy.ACCEPT_ALL,
                    trustGraph = TrustGraph.fromEdges(emptyList()),
                    karmaScoreOf = KarmaScoreLookup { 0.0 },
                    pointerDepositLookup = {
                        calls++
                        null
                    },
                )
            MailboxGossip.onDhtEntry(
                sender.publicKey,
                entryFor(pointerFrom(sender, seed = 11)),
                storage,
                MailboxPointerIndex(),
                local,
                acceptance,
            ) shouldBe OutboxIngestOutcome.ACCEPTED
            calls shouldBe 0
        }

        test("the mirrored size constant of the directory module is the real pointer maximum") {
            OutboxEntryKind.DM_MAILBOX_POINTER.maxPayloadBytes shouldBe MailboxPointerCodec.MAX_POINTER_BYTES
        }

        test("the validator functions reference neither the network, the clock nor the DHT") {
            val classes =
                listOf(
                    "net/lapisphilosophorum/lapisnet/dm/MailboxGossip",
                    "net/lapisphilosophorum/lapisnet/dm/MailboxGossip\$Companion",
                )
            val forbidden =
                listOf(
                    "NabuStorage.get",
                    "findProviders",
                    "Instant.now",
                    "currentTimeMillis",
                    "DirectoryDht",
                    "provide",
                )
            val text =
                classes.joinToString("\n") {
                    val stream = MailboxGossip::class.java.classLoader.getResourceAsStream("$it.class")
                    String(stream!!.readAllBytes(), Charsets.ISO_8859_1)
                }
            for (f in forbidden.filter { it != "NabuStorage.get" }) {
                withClue("MailboxGossip must not reference $f") { text.contains(f) shouldBe false }
            }
        }
    })

private inline fun withClue(
    clue: String,
    block: () -> Unit,
) = io.kotest.assertions.withClue(clue, block)
