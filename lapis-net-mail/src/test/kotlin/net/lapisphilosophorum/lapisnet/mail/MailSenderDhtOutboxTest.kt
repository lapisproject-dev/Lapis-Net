package net.lapisphilosophorum.lapisnet.mail

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.directory.DhtOutbox
import net.lapisphilosophorum.lapisnet.directory.OutboxEntryKind
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files
import java.time.Instant

class MailSenderDhtOutboxTest :
    FunSpec({
        val node = LapisNode.create(DualKeyIdentity.generate())
        node.start(bootstrapPeers = emptyList())
        val storage = NabuStorage.attach(node, Files.createTempDirectory("mail-sender-outbox"))
        val pubsub = GossipPubSub.attach(node)

        afterSpec {
            pubsub.stop()
            runCatching { node.stop() }
        }

        val sender = Secp256k1KeyPair.generate()

        test("every recipient but the sender gets one pointer to the stored envelope") {
            val outbox = DhtOutbox()
            val mailSender = MailSender(pubsub, storage, outbox, dhtEntryTtlSeconds = 1000)
            val r1 = Secp256k1KeyPair.generate().publicKey
            val r2 = Secp256k1KeyPair.generate().publicKey
            val sentAt = Instant.now().epochSecond
            val sent =
                mailSender.send(
                    sender,
                    listOf(r1, r2, sender.publicKey),
                    "subject",
                    "body",
                    encryption = EncryptionMode.HYBRID_ECIES,
                    sentAtEpochSecond = sentAt,
                )

            val envelopeBytes = MessageEnvelopeCodec.encode(sent.envelope)
            sent.envelopeCid shouldBe MessageBodyCodec.cidFor(envelopeBytes)
            storage.get(sent.envelopeCid!!) shouldBe envelopeBytes

            val entries = outbox.snapshot(sentAt)
            entries.size shouldBe 2
            entries.map { it.recipient }.toSet() shouldBe setOf(r1, r2)
            for (entry in entries) {
                entry.kind shouldBe OutboxEntryKind.MAIL_POINTER
                entry.notValidAfterEpochSecond shouldBe sentAt + 1000
                MailDhtPointerCodec.decode(entry.payload).envelopeCid shouldBe sent.envelopeCid
            }
        }

        test("plaintext (NONE) mail never leaves a pointer in the world-readable outbox") {
            val outbox = DhtOutbox()
            val mailSender = MailSender(pubsub, storage, outbox)
            val r = Secp256k1KeyPair.generate().publicKey
            val sent = mailSender.send(sender, listOf(r), "s", "b")
            (sent.envelopeCid != null) shouldBe true
            outbox.snapshot(Instant.now().epochSecond).size shouldBe 0
        }

        test("hybrid-encrypted mail leaves the same kind of pointer") {
            val outbox = DhtOutbox()
            val mailSender = MailSender(pubsub, storage, outbox)
            val r = Secp256k1KeyPair.generate().publicKey
            val sent = mailSender.send(sender, listOf(r), "s", "b", encryption = EncryptionMode.HYBRID_ECIES)
            val entry = outbox.snapshot(Instant.now().epochSecond).single()
            MailDhtPointerCodec.decode(entry.payload).envelopeCid shouldBe sent.envelopeCid
            entry.recipient shouldBe r
        }

        test("without an outbox the behavior is unchanged and the envelope CID is still reported") {
            val mailSender = MailSender(pubsub, storage)
            val sent = mailSender.send(sender, listOf(Secp256k1KeyPair.generate().publicKey), "s", "b")
            (sent.envelopeCid != null) shouldBe true
        }

        test("a non-positive entry lifetime is refused") {
            runCatching { MailSender(pubsub, storage, DhtOutbox(), dhtEntryTtlSeconds = 0) }.isFailure shouldBe true
        }
    })
