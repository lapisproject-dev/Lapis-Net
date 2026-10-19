package net.lapisphilosophorum.lapisnet.directory

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.IdentityBinding
import java.time.Instant

class DirectoryDhtOutboxValidatorTest :
    FunSpec({
        val now = Instant.now().epochSecond

        fun validate(
            signedBy: DirectoryPublisher,
            value: DirectoryDhtValue,
            expected: DirectoryPublisher? = signedBy,
        ) = DirectoryDhtValidator.validate(
            ipnsValueOf(signedBy.peerId, DirectoryDhtValueCodec.encode(value)),
            expected?.key,
            now,
        )

        test("outbox entries of a valid value are passed on, with the publisher's peer ID") {
            val a = DirectoryPublisher()
            val entries = listOf(outboxEntry(), outboxEntry(kind = OutboxEntryKind.MAIL_POINTER, payloadSize = 50))
            val entry = validate(a, a.valueWithOutbox(entries))!!
            entry.outboxEntries shouldBe entries
            entry.publisher shouldBe a.peerId
            entry.identity shouldBe a.key
        }

        test("expired entries are dropped, the rest is kept") {
            val a = DirectoryPublisher()
            val live = outboxEntry()
            val entry = validate(a, a.valueWithOutbox(listOf(outboxEntry(expiresInSeconds = -5), live)))!!
            entry.outboxEntries shouldBe listOf(live)
        }

        test("a value whose entries have all expired and has no other part is rejected") {
            val a = DirectoryPublisher()
            validate(a, a.valueWithOutbox(listOf(outboxEntry(expiresInSeconds = -5)))) shouldBe null
        }

        test("an expired-entries-only outbox does not hide a valid directory part") {
            val a = DirectoryPublisher()
            val entry = validate(a, a.valueWithOutbox(listOf(outboxEntry(expiresInSeconds = -5)), withRecord = true))!!
            entry.outboxEntries shouldBe emptyList()
            (entry.peerRecord != null) shouldBe true
        }

        test("exact duplicates collapse to one entry") {
            val a = DirectoryPublisher()
            val e = outboxEntry()
            validate(a, a.valueWithOutbox(listOf(e, e, e)))!!.outboxEntries shouldBe listOf(e)
        }

        test("entries addressed to the publisher itself are dropped") {
            val a = DirectoryPublisher()
            val toSelf = outboxEntry(recipient = a.key)
            val other = outboxEntry()
            validate(a, a.valueWithOutbox(listOf(toSelf, other)))!!.outboxEntries shouldBe listOf(other)
            validate(a, a.valueWithOutbox(listOf(toSelf))) shouldBe null
        }

        test("a bad entry only drops itself - the consumer verifies payloads, the validator does not") {
            val a = DirectoryPublisher()
            val garbage = outboxEntry(payloadSize = 100) // opaque random bytes, no valid pointer inside
            validate(a, a.valueWithOutbox(listOf(garbage)))!!.outboxEntries shouldBe listOf(garbage)
        }

        test("without an expected identity the identity comes from the value, the proof chain stays mandatory") {
            val a = DirectoryPublisher()
            val value = a.valueWithOutbox(listOf(outboxEntry()))
            validate(a, value, expected = null)!!.identity shouldBe a.key
            // signed by a key that is not the binding's transport key
            validate(DirectoryPublisher(), value, expected = null) shouldBe null
        }

        test("without an expected identity a binding made by another identity is still rejected") {
            val a = DirectoryPublisher()
            val mallory = DirectoryPublisher()
            val foreign = IdentityBinding.create(mallory.identity.secp256k1KeyPair, a.identity.ed25519KeyPair.publicKey)
            val value = DirectoryDhtValue(a.key, foreign, null, null, listOf(outboxEntry()))
            validate(a, value, expected = null) shouldBe null
        }

        test("a value for another identity than the one asked for is rejected even with an outbox") {
            val a = DirectoryPublisher()
            val b = DirectoryPublisher()
            validate(a, a.valueWithOutbox(listOf(outboxEntry())), expected = b) shouldBe null
        }

        test("the validator references neither storage, providers nor a clock") {
            val text =
                String(
                    DirectoryDhtValidator::class.java.classLoader
                        .getResourceAsStream("net/lapisphilosophorum/lapisnet/directory/DirectoryDhtValidator.class")!!
                        .readAllBytes(),
                    Charsets.ISO_8859_1,
                )
            for (forbidden in listOf(
                "NabuStorage",
                "findProviders",
                "java/time/Instant",
                "currentTimeMillis",
                "nanoTime",
            )) {
                text.contains(forbidden) shouldBe false
            }
        }
    })
