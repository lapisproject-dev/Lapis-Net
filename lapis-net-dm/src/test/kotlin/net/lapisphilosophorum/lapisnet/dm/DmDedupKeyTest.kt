package net.lapisphilosophorum.lapisnet.dm

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair

class DmDedupKeyTest :
    FunSpec({
        test(
            "preimage is domainSeparatedDigest(DOMAIN_TAG, senderIdentity.bytes, " +
                "ratchetPublicKey.bytes, messageNumber-big-endian-4) - NOT plain concatenation - " +
                "pins the exact contract V0.8.5's offline-mailbox redelivery path must reproduce to " +
                "produce a byte-identical key from a different code path (security audit round 1 " +
                "finding, 2026-08-11: DmDedupKey's own doc comment previously stated a plain-" +
                "concatenation formula that did not match this implementation)",
        ) {
            val sender = Secp256k1KeyPair.generate().publicKey
            val message = dmSampleRatchetMessage()
            val messageNumber = message.header.messageNumber
            val messageNumberBigEndian =
                byteArrayOf(
                    (messageNumber ushr 24).toByte(),
                    (messageNumber ushr 16).toByte(),
                    (messageNumber ushr 8).toByte(),
                    messageNumber.toByte(),
                )
            val expected =
                domainSeparatedDigest(
                    "LapisNet:dm-dedup:v1",
                    sender.bytes,
                    message.header.ratchetPublicKey.bytes,
                    messageNumberBigEndian,
                )
            DmDedupKey.of(sender, message) shouldBe expected
        }

        test("is deterministic for the same (senderIdentity, message) pair") {
            val sender = Secp256k1KeyPair.generate().publicKey
            val message = dmSampleRatchetMessage()
            DmDedupKey.of(sender, message) shouldBe DmDedupKey.of(sender, message)
        }

        test("is 32 bytes (SHA-256)") {
            val sender = Secp256k1KeyPair.generate().publicKey
            DmDedupKey.of(sender, dmSampleRatchetMessage()).size shouldBe 32
        }

        test("differs for different claimed senderIdentity, same message") {
            val message = dmSampleRatchetMessage()
            val senderA = Secp256k1KeyPair.generate().publicKey
            val senderB = Secp256k1KeyPair.generate().publicKey
            DmDedupKey.of(senderA, message) shouldNotBe DmDedupKey.of(senderB, message)
        }

        test("differs for different messages (different ratchet position), same sender") {
            val sender = Secp256k1KeyPair.generate().publicKey
            val (alice, _) = dmEstablishedPair()
            val first = alice.encrypt("one".toByteArray())
            val second = alice.encrypt("two".toByteArray())
            DmDedupKey.of(sender, first) shouldNotBe DmDedupKey.of(sender, second)
        }
    })
