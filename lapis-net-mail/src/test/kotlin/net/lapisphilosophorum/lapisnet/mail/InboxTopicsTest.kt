package net.lapisphilosophorum.lapisnet.mail

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldMatch
import net.lapisphilosophorum.lapisnet.core.crypto.fingerprintHex
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair

class InboxTopicsTest :
    FunSpec({
        test("forRecipient is deterministic for the same key") {
            val key = Secp256k1KeyPair.generate().publicKey

            InboxTopics.forRecipient(key) shouldBe InboxTopics.forRecipient(key)
        }

        test("two distinct keys produce distinct topics") {
            val a = Secp256k1KeyPair.generate().publicKey
            val b = Secp256k1KeyPair.generate().publicKey

            (InboxTopics.forRecipient(a) == InboxTopics.forRecipient(b)) shouldBe false
        }

        test("the topic matches the documented shape") {
            val key = Secp256k1KeyPair.generate().publicKey

            InboxTopics.forRecipient(key) shouldMatch Regex("^LapisNet:inbox:[0-9a-f]{64}:v1$")
        }

        test("the topic carries the full 32-byte digest, not the truncated fingerprintHex form - D6") {
            val key = Secp256k1KeyPair.generate().publicKey

            val topic = InboxTopics.forRecipient(key)
            val fingerprint = key.bytes.fingerprintHex()

            // fingerprintHex truncates to the first 8 bytes (16 hex chars) of SHA-256(bytes) - and
            // since InboxTopics.forRecipient hashes the exact same input with the exact same
            // algorithm, that truncated fingerprint is unavoidably a PREFIX of the topic's 64-hex-
            // char digest (not absent from it - a naive "does not contain" assertion would be
            // trivially false here for that reason, not a useful D6 regression guard). The actual
            // property D6 cares about is length: the topic must carry the FULL 32-byte digest, not
            // stop at fingerprintHex's 8-byte truncation, otherwise two distinct identities could
            // collide onto the same inbox topic.
            topic.startsWith("LapisNet:inbox:$fingerprint") shouldBe true
            topic.length shouldBe "LapisNet:inbox:".length + 64 + ":v1".length
        }
    })
