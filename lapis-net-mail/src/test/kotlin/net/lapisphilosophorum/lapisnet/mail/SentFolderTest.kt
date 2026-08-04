package net.lapisphilosophorum.lapisnet.mail

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair

private fun testCid(seed: Byte): Cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { seed })

private fun freshSentMessage(seed: Byte): SentMessage {
    val sender = Secp256k1KeyPair.generate()
    val recipient = Secp256k1KeyPair.generate().publicKey
    val cid = testCid(seed)
    val envelope = MessageEnvelope.create(sender, listOf(recipient), cid)
    val body = MessageBody(subject = "s$seed", body = "b$seed")
    return SentMessage(envelope, body, cid, sealedBody = null, frameBytes = byteArrayOf(seed))
}

class SentFolderTest :
    FunSpec({
        test("add returns true for a fresh message, false for the same envelope again") {
            val folder = SentFolder()
            val sent = freshSentMessage(1)

            folder.add(sent) shouldBe true
            folder.add(sent) shouldBe false
            folder.size() shouldBe 1
        }

        test("eviction: the oldest tracked entry is evicted once maxTracked is exceeded") {
            val folder = SentFolder(maxTracked = 2)
            val messages = (1..5).map { freshSentMessage(it.toByte()) }

            messages.forEach { folder.add(it) shouldBe true }

            folder.size() shouldBe 2
            folder.latest().map { it.envelope } shouldBe messages.takeLast(2).map { it.envelope }
        }

        test("latest returns messages in insertion order and is a defensive copy") {
            val folder = SentFolder()
            val messages = (1..3).map { freshSentMessage(it.toByte()) }
            messages.forEach { folder.add(it) }

            val latest = folder.latest().toMutableList()
            latest.map { it.envelope } shouldBe messages.map { it.envelope }

            latest.clear()

            folder.latest().size shouldBe 3
        }

        test("toInboxMessage adapts a SentMessage to an InboxMessage with a Plaintext payload") {
            val sent = freshSentMessage(1)

            val adapted = sent.toInboxMessage()

            adapted.envelope shouldBe sent.envelope
            adapted.body shouldBe sent.body
        }
    })
