package net.lapisphilosophorum.lapisnet.mail

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair

private fun testCid(seed: Byte): Cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { seed })

class MailAadContextTest :
    FunSpec({
        test("contextBytes is stable across repeated calls for identical fields") {
            val sender = Secp256k1KeyPair.generate().publicKey
            val recipient = Secp256k1KeyPair.generate().publicKey
            val a = MailAadContext.forNewMessage(sender, listOf(recipient), sentAtEpochSecond = 1000)
            val b = MailAadContext.forNewMessage(sender, listOf(recipient), sentAtEpochSecond = 1000)

            a.contextBytes shouldBe b.contextBytes
        }

        test("a different sender changes contextBytes") {
            val recipient = Secp256k1KeyPair.generate().publicKey
            val a = MailAadContext.forNewMessage(Secp256k1KeyPair.generate().publicKey, listOf(recipient), 1000)
            val b = MailAadContext.forNewMessage(Secp256k1KeyPair.generate().publicKey, listOf(recipient), 1000)

            a.contextBytes shouldNotBe b.contextBytes
        }

        test("a different recipient set changes contextBytes") {
            val sender = Secp256k1KeyPair.generate().publicKey
            val a = MailAadContext.forNewMessage(sender, listOf(Secp256k1KeyPair.generate().publicKey), 1000)
            val b = MailAadContext.forNewMessage(sender, listOf(Secp256k1KeyPair.generate().publicKey), 1000)

            a.contextBytes shouldNotBe b.contextBytes
        }

        test("an additional recipient changes contextBytes") {
            val sender = Secp256k1KeyPair.generate().publicKey
            val r1 = Secp256k1KeyPair.generate().publicKey
            val r2 = Secp256k1KeyPair.generate().publicKey
            val a = MailAadContext.forNewMessage(sender, listOf(r1), 1000)
            val b = MailAadContext.forNewMessage(sender, listOf(r1, r2), 1000)

            a.contextBytes shouldNotBe b.contextBytes
        }

        test("a different sentAtEpochSecond changes contextBytes") {
            val sender = Secp256k1KeyPair.generate().publicKey
            val recipient = Secp256k1KeyPair.generate().publicKey
            val a = MailAadContext.forNewMessage(sender, listOf(recipient), 1000)
            val b = MailAadContext.forNewMessage(sender, listOf(recipient), 2000)

            a.contextBytes shouldNotBe b.contextBytes
        }

        test("replyTo present vs absent changes contextBytes") {
            val sender = Secp256k1KeyPair.generate().publicKey
            val recipient = Secp256k1KeyPair.generate().publicKey
            val a = MailAadContext.forNewMessage(sender, listOf(recipient), 1000)
            val b = MailAadContext.forNewMessage(sender, listOf(recipient), 1000, replyTo = testCid(1))

            a.contextBytes shouldNotBe b.contextBytes
        }

        test("threadRoot present vs absent changes contextBytes") {
            val sender = Secp256k1KeyPair.generate().publicKey
            val recipient = Secp256k1KeyPair.generate().publicKey
            val a = MailAadContext.forNewMessage(sender, listOf(recipient), 1000)
            val b = MailAadContext.forNewMessage(sender, listOf(recipient), 1000, threadRoot = testCid(1))

            a.contextBytes shouldNotBe b.contextBytes
        }

        // The precise scenario MailAadContext's own doc comment (§2.2) calls out: swapping which
        // of the two optional CIDs is present must never collide, because both are ALWAYS
        // length-prefixed with an explicit 0 for absent (unlike encodeSignedBody's flags-
        // conditional encoding).
        test("(replyTo=X, threadRoot=null) never collides with (replyTo=null, threadRoot=X)") {
            val sender = Secp256k1KeyPair.generate().publicKey
            val recipient = Secp256k1KeyPair.generate().publicKey
            val a = MailAadContext.forNewMessage(sender, listOf(recipient), 1000, replyTo = testCid(9))
            val b = MailAadContext.forNewMessage(sender, listOf(recipient), 1000, threadRoot = testCid(9))

            a.contextBytes shouldNotBe b.contextBytes
        }

        // The load-bearing invariant of the whole scheme: reconstructing a context from a
        // round-tripped envelope must reproduce byte-identical contextBytes to what the sender
        // used at seal() time - otherwise a legitimately-sealed message would fail to open for its
        // own intended recipient.
        test("MailAadContext.of(envelope) reproduces forNewMessage's bytes exactly for a round-tripped envelope") {
            val senderKeyPair = Secp256k1KeyPair.generate()
            val recipientKeyPair = Secp256k1KeyPair.generate()
            val forSealing =
                MailAadContext.forNewMessage(
                    sender = senderKeyPair.publicKey,
                    recipients = listOf(recipientKeyPair.publicKey),
                    sentAtEpochSecond = 1234,
                    replyTo = testCid(1),
                    threadRoot = testCid(2),
                )
            val sealed = HybridEcies.seal(MessageBody(subject = "s", body = "b"), senderKeyPair, forSealing)
            val envelope =
                MessageEnvelope.create(
                    sender = senderKeyPair,
                    recipients = listOf(recipientKeyPair.publicKey),
                    contentCid = sealed.contentCid,
                    sentAtEpochSecond = 1234,
                    encryption = EncryptionMode.HYBRID_ECIES,
                    replyTo = testCid(1),
                    threadRoot = testCid(2),
                    wraps = sealed.wraps,
                )

            val roundTripped = MessageEnvelopeCodec.decode(MessageEnvelopeCodec.encode(envelope))
            val reconstructed = MailAadContext.of(roundTripped)

            reconstructed.contextBytes shouldBe forSealing.contextBytes
        }
    })
