package net.lapisphilosophorum.lapisnet.mail

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair

private fun testCid(seed: Byte): Cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { seed })

private fun freshMessage(seed: Byte): InboxMessage {
    val sender = Secp256k1KeyPair.generate()
    val recipient = Secp256k1KeyPair.generate().publicKey
    val envelope = MessageEnvelope.create(sender, listOf(recipient), testCid(seed))
    val body = MessageBody(subject = "s$seed", body = "b$seed")
    return InboxMessage(envelope, body)
}

class InboxIndexTest :
    FunSpec({
        test("add returns true for a fresh message, false for the same envelope again") {
            val index = InboxIndex()
            val message = freshMessage(1)

            index.add(message) shouldBe true
            index.add(message) shouldBe false
        }

        test("add returns false, never throws, for a degenerate all-0xFF signature") {
            val sender = Secp256k1KeyPair.generate()
            val recipient = Secp256k1KeyPair.generate().publicKey
            val degenerate =
                MessageEnvelope.fromDecoded(
                    sender = sender.publicKey,
                    recipients = listOf(recipient),
                    sentAtEpochSecond = 1000,
                    encryption = EncryptionMode.NONE,
                    contentCid = testCid(1),
                    replyTo = null,
                    threadRoot = null,
                    signature = ByteArray(64) { 0xFF.toByte() },
                )
            val index = InboxIndex()

            index.add(InboxMessage(degenerate, MessageBody(subject = "s", body = "b"))) shouldBe false
        }

        test("canAccept is true before add, false after, and never mutates the index") {
            val index = InboxIndex()
            val message = freshMessage(1)

            index.canAccept(message.envelope) shouldBe true
            repeat(5) { index.canAccept(message.envelope) shouldBe true }
            index.size() shouldBe 0

            index.add(message) shouldBe true

            index.canAccept(message.envelope) shouldBe false
        }

        test("eviction: the oldest tracked entry is evicted once maxTracked is exceeded") {
            val index = InboxIndex(maxTracked = 2, maxPersisted = 100)
            val messages = (1..5).map { freshMessage(it.toByte()) }

            messages.forEach { index.add(it) shouldBe true }

            index.size() shouldBe 2
            val remainingSenders = messages.takeLast(2).map { it.envelope.sender }.toSet()
            index.senders() shouldBe remainingSenders
            messages.dropLast(2).forEach { index.messagesFrom(it.envelope.sender) shouldBe emptyList() }
            messages.takeLast(2).forEach { index.messagesFrom(it.envelope.sender) shouldBe listOf(it) }
        }

        test("the persistence cap is decoupled from the tracking cap") {
            val index = InboxIndex(maxTracked = 100, maxPersisted = 2)
            val messages = (1..5).map { freshMessage(it.toByte()) }

            messages.forEach { index.add(it) shouldBe true }
            index.size() shouldBe 5

            val reservations = messages.map { index.tryReservePersistence(it.envelope) }

            reservations.count { it } shouldBe 2
        }

        test("tryReservePersistence is idempotent per content id") {
            val index = InboxIndex(maxTracked = 100, maxPersisted = 1)
            val message = freshMessage(1)

            index.tryReservePersistence(message.envelope) shouldBe true
            repeat(5) { index.tryReservePersistence(message.envelope) shouldBe true }

            // The cap (1) is still consumed by only ONE distinct content id - a genuinely different
            // envelope must still fail.
            val other = freshMessage(2)
            index.tryReservePersistence(other.envelope) shouldBe false
        }

        test("latest returns messages in insertion order and is a defensive copy") {
            val index = InboxIndex()
            val messages = (1..3).map { freshMessage(it.toByte()) }
            messages.forEach { index.add(it) }

            val latest = index.latest().toMutableList()
            latest shouldBe messages

            latest.clear()

            index.latest() shouldBe messages
        }

        test("a Sealed-payload InboxMessage dedups and evicts identically to a Plaintext one") {
            val index = InboxIndex(maxTracked = 2, maxPersisted = 100)
            val sender = Secp256k1KeyPair.generate()
            val recipient = Secp256k1KeyPair.generate().publicKey
            val sealedBody = SealedBody(ByteArray(GCM_NONCE_SIZE), ByteArray(64))
            val envelope1 = MessageEnvelope.create(sender, listOf(recipient), testCid(101))
            val envelope2 = MessageEnvelope.create(sender, listOf(recipient), testCid(102))
            val envelope3 = MessageEnvelope.create(sender, listOf(recipient), testCid(103))
            val sealedMessage1 = InboxMessage(envelope1, sealedBody)
            val sealedMessage2 = InboxMessage(envelope2, sealedBody)
            val sealedMessage3 = InboxMessage(envelope3, sealedBody)

            index.add(sealedMessage1) shouldBe true
            index.add(sealedMessage1) shouldBe false // dedup
            index.add(sealedMessage2) shouldBe true
            index.add(sealedMessage3) shouldBe true // evicts sealedMessage1 (maxTracked = 2)

            index.size() shouldBe 2
            index.latest().map { it.envelope } shouldBe listOf(envelope2, envelope3)
            (sealedMessage2.payload is InboxPayload.Sealed) shouldBe true
            sealedMessage2.body shouldBe null
        }
    })
