package net.lapisphilosophorum.lapisnet.mail

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerId
import io.libp2p.core.PeerInfo
import net.lapisphilosophorum.lapisnet.directory.OutboxEntry
import net.lapisphilosophorum.lapisnet.directory.OutboxEntryKind
import net.lapisphilosophorum.lapisnet.directory.OutboxIngestOutcome
import net.lapisphilosophorum.lapisnet.directory.PeerCapability
import net.lapisphilosophorum.lapisnet.directory.PeerDirectoryGossip
import net.lapisphilosophorum.lapisnet.directory.PeerRecord
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.networking.deriveLibp2pPeerId
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import net.lapisphilosophorum.lapisnet.trust.TrustGraph
import java.nio.file.Files
import java.time.Duration
import java.time.Instant

/** A sender node A and a recipient node C, connected, with A's record in C's directory. */
private class MailRig(
    gated: Boolean = false,
) {
    val aIdentity = DualKeyIdentity.generate()
    val aNode = LapisNode.create(aIdentity).also { it.start(bootstrapPeers = emptyList()) }
    val aStorage = NabuStorage.attach(aNode, Files.createTempDirectory("mail-dht-a"))
    val aKey: Secp256k1PublicKey = aIdentity.secp256k1KeyPair.publicKey

    val cIdentity = DualKeyIdentity.generate()
    val cNode = LapisNode.create(cIdentity).also { it.start(bootstrapPeers = emptyList()) }
    val cStorage = NabuStorage.attach(cNode, Files.createTempDirectory("mail-dht-c"))
    val cPubsub = GossipPubSub.attach(cNode)
    val cDirectory = PeerDirectoryGossip.attach(cPubsub, cStorage)
    val cKey: Secp256k1PublicKey = cIdentity.secp256k1KeyPair.publicKey
    val inbox: InboxGossip =
        InboxGossip.attach(
            cPubsub,
            cStorage,
            cKey,
            if (gated) {
                MailAcceptanceCheck(
                    gates = listOf(MailAcceptanceGate.VeritasPath),
                    trustGraph = TrustGraph.fromEdges(emptyList()),
                    karmaScoreOf = KarmaScoreLookup { 0.0 },
                )
            } else {
                null
            },
        )
    val fetcher =
        InboxDhtFetcher(inbox, cStorage, cDirectory, cKey, 60, Duration.ofMillis(700), Duration.ofSeconds(20))

    init {
        cNode.connect(PeerInfo(aNode.peerId, aNode.listenAddresses()))
        announceA()
    }

    fun announceA() {
        cDirectory.announce(recordOf(aIdentity, aNode))
    }

    fun recordOf(
        identity: DualKeyIdentity,
        listenOn: LapisNode,
    ) = PeerRecord.create(
        identity,
        listenOn.listenAddresses(),
        setOf(PeerCapability.DM),
        System.nanoTime(),
        Instant.now().epochSecond + 3600,
    )

    /** Stores a mail on A the way [MailSender] does (without any gossip publish) and returns its envelope CID. */
    fun storeMail(
        signer: Secp256k1KeyPair = aIdentity.secp256k1KeyPair,
        recipients: List<Secp256k1PublicKey> = listOf(cKey),
        storeBody: Boolean = true,
        tamperSignature: Boolean = false,
        subject: String = "hello",
    ): Pair<Cid, MessageEnvelope> {
        val body = MessageBodyCodec.encode(MessageBody(subject = subject, body = "world"))
        val bodyCid = if (storeBody) aStorage.put(body) else MessageBodyCodec.cidFor(body)
        val envelope = MessageEnvelope.create(signer, recipients, bodyCid)
        val bytes = MessageEnvelopeCodec.encode(envelope)
        if (tamperSignature) bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 1).toByte()
        return aStorage.put(bytes) to envelope
    }

    fun queue(
        envelopeCid: Cid,
        sender: Secp256k1PublicKey = aKey,
        senderPeerId: PeerId = aNode.peerId,
        recipient: Secp256k1PublicKey = cKey,
        notValidAfter: Long = Instant.now().epochSecond + 3600,
    ): OutboxIngestOutcome =
        fetcher.consumer().onDhtOutboxEntry(
            sender,
            senderPeerId,
            OutboxEntry(
                OutboxEntryKind.MAIL_POINTER,
                recipient,
                notValidAfter,
                MailDhtPointerCodec.encode(MailDhtPointer(envelopeCid)),
            ),
        )

    fun stop() {
        runCatching { inbox.stop() }
        runCatching { cDirectory.stop() }
        runCatching { cPubsub.stop() }
        runCatching { cNode.stop() }
        runCatching { aNode.stop() }
    }
}

private fun withRig(
    gated: Boolean = false,
    body: (MailRig) -> Unit,
) {
    val rig = MailRig(gated)
    try {
        body(rig)
    } finally {
        rig.stop()
    }
}

private fun randomCid(seed: Int): Cid =
    Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { (seed + it).toByte() })

class InboxDhtFetcherTest :
    FunSpec({
        test("a queued pointer is fetched - envelope, then body - checked and delivered to the inbox") {
            withRig { rig ->
                val (cid, envelope) = rig.storeMail()
                rig.queue(cid) shouldBe OutboxIngestOutcome.ACCEPTED
                rig.fetcher.pendingCount() shouldBe 1
                rig.fetcher.pollOnce()
                rig.inbox.messages().size shouldBe 1
                rig.inbox
                    .messages()
                    .single()
                    .envelope
                    .contentId()
                    .contentEquals(envelope.contentId()) shouldBe true
                rig.fetcher.pendingCount() shouldBe 0
                rig.fetcher.fetchAttempts shouldBe 2
                // nothing left to do on the next pass
                rig.fetcher.pollOnce()
                rig.fetcher.fetchAttempts shouldBe 2
            }
        }

        test("an envelope with a broken signature is dropped without the body ever being asked for") {
            withRig { rig ->
                val (cid, _) = rig.storeMail(tamperSignature = true)
                rig.queue(cid)
                rig.fetcher.pollOnce()
                rig.inbox.messages().size shouldBe 0
                rig.fetcher.pendingCount() shouldBe 0
                rig.fetcher.fetchAttempts shouldBe 1
            }
        }

        test("an envelope not addressed to the local identity is dropped") {
            withRig { rig ->
                val (cid, _) = rig.storeMail(recipients = listOf(Secp256k1KeyPair.generate().publicKey))
                rig.queue(cid)
                rig.fetcher.pollOnce()
                rig.inbox.messages().size shouldBe 0
                rig.fetcher.pendingCount() shouldBe 0
                rig.fetcher.fetchAttempts shouldBe 1
            }
        }

        test("an envelope signed by somebody else than the value that carried the pointer is dropped") {
            withRig { rig ->
                val (cid, _) = rig.storeMail(signer = Secp256k1KeyPair.generate())
                rig.queue(cid)
                rig.fetcher.pollOnce()
                rig.inbox.messages().size shouldBe 0
                rig.fetcher.pendingCount() shouldBe 0
                rig.fetcher.fetchAttempts shouldBe 1
            }
        }

        test("the acceptance policy decides before the body is fetched: a rejected sender costs no body download") {
            withRig(gated = true) { rig ->
                val (cid, _) = rig.storeMail()
                rig.queue(cid)
                rig.fetcher.pollOnce()
                rig.inbox.messages().size shouldBe 0
                rig.fetcher.pendingCount() shouldBe 0
                rig.fetcher.fetchAttempts shouldBe 1
            }
        }

        test(
            "control: without a policy and with the body missing, the body IS asked for and the pointer stays pending",
        ) {
            withRig { rig ->
                val (cid, _) = rig.storeMail(storeBody = false)
                rig.queue(cid)
                rig.fetcher.pollOnce()
                rig.inbox.messages().size shouldBe 0
                rig.fetcher.pendingCount() shouldBe 1
                rig.fetcher.fetchAttempts shouldBe 2
            }
        }

        test("an expired pointer is dropped without any fetch and without needing a directory record") {
            withRig { rig ->
                rig.queue(randomCid(1), notValidAfter = 100)
                rig.fetcher.pollOnce(nowEpochSecond = 1000)
                rig.fetcher.pendingCount() shouldBe 0
                rig.fetcher.fetchAttempts shouldBe 0
            }
        }

        test("a sender whose DHT peer ID differs from its directory record is dropped without a fetch") {
            withRig { rig ->
                val (cid, _) = rig.storeMail()
                rig.queue(cid, senderPeerId = DualKeyIdentity.generate().deriveLibp2pPeerId())
                rig.fetcher.pollOnce()
                rig.fetcher.pendingCount() shouldBe 0
                rig.fetcher.fetchAttempts shouldBe 0
            }
        }

        test("a sender without a directory record stays pending and nothing is fetched") {
            withRig { rig ->
                val stranger = DualKeyIdentity.generate()
                rig.queue(
                    randomCid(2),
                    sender = stranger.secp256k1KeyPair.publicKey,
                    senderPeerId = stranger.deriveLibp2pPeerId(),
                )
                rig.fetcher.pollOnce()
                rig.fetcher.pendingCount() shouldBe 1
                rig.fetcher.fetchAttempts shouldBe 0
            }
        }

        test("an unreachable sender leaves the pointer pending; the pass ends") {
            withRig { rig ->
                val (cid, _) = rig.storeMail()
                rig.queue(cid)
                rig.aNode.stop()
                rig.fetcher.pollOnce()
                rig.inbox.messages().size shouldBe 0
                rig.fetcher.pendingCount() shouldBe 1
            }
        }

        test("a mail that already arrived by gossip is not stored twice and its body is not fetched") {
            withRig { rig ->
                val (cid, envelope) = rig.storeMail(storeBody = false)
                val body = MessageBodyCodec.encode(MessageBody(subject = "hello", body = "world"))
                rig.inbox.dhtIngest(envelope, MessageEnvelopeCodec.encode(envelope), body) shouldBe
                    InboxIngestOutcome.ACCEPTED
                rig.queue(cid)
                rig.fetcher.pollOnce()
                rig.inbox.messages().size shouldBe 1
                rig.fetcher.pendingCount() shouldBe 0
                rig.fetcher.fetchAttempts shouldBe 1
            }
        }

        test("one sender gets at most four fetch attempts per pass; the rest carries over") {
            withRig { rig ->
                repeat(6) { rig.queue(randomCid(10 + it)) shouldBe OutboxIngestOutcome.ACCEPTED }
                rig.fetcher.pollOnce()
                rig.fetcher.fetchAttempts shouldBe InboxDhtFetcher.MAX_FETCH_ATTEMPTS_PER_SENDER_PER_PASS.toLong()
                rig.fetcher.pendingCount() shouldBe 6
            }
        }

        test("the pass budget stops a pass and the next one resumes behind the entries already tried") {
            val rig = MailRig()
            val slow =
                InboxDhtFetcher(
                    rig.inbox,
                    rig.cStorage,
                    rig.cDirectory,
                    rig.cKey,
                    60,
                    Duration.ofMillis(600),
                    Duration.ofMillis(100),
                )
            try {
                val senders = List(3) { DualKeyIdentity.generate() }
                for (s in senders) {
                    rig.cDirectory.announce(rig.recordOf(s, rig.aNode))
                    slow.consumer().onDhtOutboxEntry(
                        s.secp256k1KeyPair.publicKey,
                        s.deriveLibp2pPeerId(),
                        OutboxEntry(
                            OutboxEntryKind.MAIL_POINTER,
                            rig.cKey,
                            Instant.now().epochSecond + 3600,
                            MailDhtPointerCodec.encode(MailDhtPointer(randomCid(s.hashCode()))),
                        ),
                    )
                }
                slow.pendingCount() shouldBe 3
                repeat(3) { slow.pollOnce() }
                (slow.fetchAttempts >= 3) shouldBe true
            } finally {
                rig.stop()
            }
        }

        test("the consumer queues valid pointers and refuses wrong kinds, wrong recipients and malformed payloads") {
            withRig { rig ->
                rig.queue(randomCid(1)) shouldBe OutboxIngestOutcome.ACCEPTED
                rig.queue(randomCid(1)) shouldBe OutboxIngestOutcome.DUPLICATE
                rig.queue(randomCid(2), recipient = Secp256k1KeyPair.generate().publicKey) shouldBe
                    OutboxIngestOutcome.REJECTED
                val consumer = rig.fetcher.consumer()
                consumer.onDhtOutboxEntry(
                    rig.aKey,
                    rig.aNode.peerId,
                    OutboxEntry(OutboxEntryKind.DM_MAILBOX_POINTER, rig.cKey, 1, ByteArray(20) { 1 }),
                ) shouldBe OutboxIngestOutcome.REJECTED
                consumer.onDhtOutboxEntry(
                    rig.aKey,
                    rig.aNode.peerId,
                    OutboxEntry(OutboxEntryKind.MAIL_POINTER, rig.cKey, 1, ByteArray(20) { 1 }),
                ) shouldBe OutboxIngestOutcome.REJECTED
                rig.fetcher.pendingCount() shouldBe 1
            }
        }

        test("the queueing consumer references neither storage, the DHT nor a clock") {
            val text =
                String(
                    MailPointerQueueConsumer::class.java.classLoader
                        .getResourceAsStream("net/lapisphilosophorum/lapisnet/mail/MailPointerQueueConsumer.class")!!
                        .readAllBytes(),
                    Charsets.ISO_8859_1,
                )
            for (forbidden in listOf(
                "NabuStorage",
                "findProviders",
                "java/time/Instant",
                "currentTimeMillis",
                "nanoTime",
                "DirectoryDht",
            )) {
                text.contains(forbidden) shouldBe false
            }
        }
    })
