package net.lapisphilosophorum.lapisnet.dm

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldMatch
import net.lapisphilosophorum.lapisnet.core.crypto.fingerprintHex
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair

/**
 * V0.8.5 hardening pass finding: [MailboxTopics]' own doc comment makes the same non-collision claim
 * `net.lapisphilosophorum.lapisnet.mail.InboxTopics.forRecipient`'s doc comment does, but - unlike
 * that class - had no dedicated regression test. Mirrors
 * `net.lapisphilosophorum.lapisnet.mail.InboxTopicsTest` exactly, including its D6 "full digest, not
 * the truncated fingerprint" case, since [MailboxTopics.forRecipient] is byte-for-byte the same
 * construction (`"LapisNet:mailbox:<64 lowercase hex chars of sha256(compressed pubkey)>:v1"`) over a
 * different topic prefix.
 */
class MailboxTopicsTest :
    FunSpec({
        test("forRecipient is deterministic for the same key") {
            val key = Secp256k1KeyPair.generate().publicKey

            MailboxTopics.forRecipient(key) shouldBe MailboxTopics.forRecipient(key)
        }

        test("two distinct keys produce distinct topics") {
            val a = Secp256k1KeyPair.generate().publicKey
            val b = Secp256k1KeyPair.generate().publicKey

            (MailboxTopics.forRecipient(a) == MailboxTopics.forRecipient(b)) shouldBe false
        }

        test("the topic matches the documented shape") {
            val key = Secp256k1KeyPair.generate().publicKey

            MailboxTopics.forRecipient(key) shouldMatch Regex("^LapisNet:mailbox:[0-9a-f]{64}:v1$")
        }

        test("the topic carries the full 32-byte digest, not the truncated fingerprintHex form - D6") {
            val key = Secp256k1KeyPair.generate().publicKey

            val topic = MailboxTopics.forRecipient(key)
            val fingerprint = key.bytes.fingerprintHex()

            // fingerprintHex truncates to the first 8 bytes (16 hex chars) of SHA-256(bytes) - and
            // since MailboxTopics.forRecipient hashes the exact same input with the exact same
            // algorithm, that truncated fingerprint is unavoidably a PREFIX of the topic's 64-hex-
            // char digest (not absent from it - a naive "does not contain" assertion would be
            // trivially false here for that reason, not a useful D6 regression guard). The actual
            // property D6 cares about is length: the topic must carry the FULL 32-byte digest, not
            // stop at fingerprintHex's 8-byte truncation, otherwise two distinct identities could
            // collide onto the same mailbox topic - mirrors `InboxTopicsTest`'s identical case.
            topic.startsWith("LapisNet:mailbox:$fingerprint") shouldBe true
            topic.length shouldBe "LapisNet:mailbox:".length + 64 + ":v1".length
        }
    })
