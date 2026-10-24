package net.lapisphilosophorum.lapisnet.dm

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import net.lapisphilosophorum.lapisnet.directory.SealedMailboxBox
import net.lapisphilosophorum.lapisnet.directory.SealedMailboxKind
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair

class SealedMailboxItemCodecTest :
    FunSpec({
        val now = 1_000_000L
        val recipient = X25519KeyPair.generate()

        fun envelopeBytes(): ByteArray =
            DmEnvelopeCodec.encode(
                DmEnvelope(DmMessageType.TEXT, Secp256k1KeyPair.generate().publicKey, null, dmSampleRatchetMessage()),
            )

        test("seal and open round-trip returns the same envelope, item is exactly SEALED_ITEM_BYTES") {
            val bytes = envelopeBytes()
            val item = SealedMailboxItemCodec.seal(bytes, recipient.publicKey, now + 100)
            item.size shouldBe SealedMailboxItemCodec.SEALED_ITEM_BYTES
            val opened = SealedMailboxItemCodec.open(item, recipient.privateKey, now)
            opened shouldNotBe null
            DmEnvelopeCodec.encode(opened!!) shouldBe bytes
        }

        test("every single bit flip is refused") {
            val item = SealedMailboxItemCodec.seal(envelopeBytes(), recipient.publicKey, now + 100)
            // Flip one bit per byte position on a stride (full coverage of header, body and tag regions).
            for (i in item.indices step 7) {
                val tampered = item.copyOf()
                tampered[i] = (tampered[i].toInt() xor 0x01).toByte()
                SealedMailboxItemCodec.open(tampered, recipient.privateKey, now) shouldBe null
            }
            for (i in listOf(0, 1, 32, 33, 34, item.size - 17, item.size - 16, item.size - 1)) {
                val tampered = item.copyOf()
                tampered[i] = (tampered[i].toInt() xor 0x80).toByte()
                SealedMailboxItemCodec.open(tampered, recipient.privateKey, now) shouldBe null
            }
        }

        test("wrong key yields null") {
            val item = SealedMailboxItemCodec.seal(envelopeBytes(), recipient.publicKey, now + 100)
            SealedMailboxItemCodec.open(item, X25519KeyPair.generate().privateKey, now) shouldBe null
        }

        test("expired items are discarded") {
            val item = SealedMailboxItemCodec.seal(envelopeBytes(), recipient.publicKey, now - 1)
            SealedMailboxItemCodec.open(item, recipient.privateKey, now) shouldBe null
        }

        test("wrong length and wrong version are refused before any crypto") {
            val item = SealedMailboxItemCodec.seal(envelopeBytes(), recipient.publicKey, now + 100)
            SealedMailboxItemCodec.open(item.copyOf(item.size - 1), recipient.privateKey, now) shouldBe null
            SealedMailboxItemCodec.open(item + byteArrayOf(0), recipient.privateKey, now) shouldBe null
            SealedMailboxItemCodec.open(ByteArray(0), recipient.privateKey, now) shouldBe null
            val badVersion = item.copyOf().also { it[0] = 2 }
            SealedMailboxItemCodec.open(badVersion, recipient.privateKey, now) shouldBe null
        }

        test("an oversized envelope throws before sealing") {
            shouldThrow<SealedMailboxItemTooLargeException> {
                SealedMailboxItemCodec.seal(
                    ByteArray(SealedMailboxItemCodec.MAX_ENVELOPE_BYTES + 1) { 1 },
                    recipient.publicKey,
                    now,
                )
            }
        }

        test("two seals of the same envelope are different (fresh ephemeral key per announcement)") {
            val bytes = envelopeBytes()
            val a = SealedMailboxItemCodec.seal(bytes, recipient.publicKey, now + 100)
            val b = SealedMailboxItemCodec.seal(bytes, recipient.publicKey, now + 100)
            a.contentEquals(b) shouldBe false
        }

        test("fragments tile the item exactly") {
            (SealedMailboxItemCodec.FRAGMENT_BYTES * SealedMailboxItemCodec.FRAGMENT_COUNT) shouldBe
                SealedMailboxItemCodec.SEALED_ITEM_BYTES
        }

        test("capacity is 5,668 bytes since the kind byte moved into the sealed plaintext") {
            SealedMailboxItemCodec.MAX_ENVELOPE_BYTES shouldBe 5_668
        }

        test("a DM item does not open as MAIL, and a MAIL item does not open as a DM") {
            val dmItem = SealedMailboxItemCodec.seal(envelopeBytes(), recipient.publicKey, now + 100)
            SealedMailboxBox.open(dmItem, recipient.privateKey, now, SealedMailboxKind.MAIL) shouldBe null
            val mailItem =
                SealedMailboxBox.seal(SealedMailboxKind.MAIL, envelopeBytes(), recipient.publicKey, now + 100)
            SealedMailboxItemCodec.open(mailItem, recipient.privateKey, now) shouldBe null
        }
    })
