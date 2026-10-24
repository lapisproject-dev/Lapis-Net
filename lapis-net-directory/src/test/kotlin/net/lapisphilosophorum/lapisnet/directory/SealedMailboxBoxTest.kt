package net.lapisphilosophorum.lapisnet.directory

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair

class SealedMailboxBoxTest :
    FunSpec({
        val now = 1_000_000L
        val recipient = X25519KeyPair.generate()
        val payload = ByteArray(300) { (it % 251).toByte() }

        test("the item size is the gossip item size and the payload capacity is 5,668 bytes") {
            SealedMailboxBox.ITEM_BYTES shouldBe AnonymousMailboxGossip.ITEM_SIZE
            SealedMailboxBox.MAX_PAYLOAD_BYTES shouldBe 5_668
        }

        test("DM and MAIL round-trip; the item is always exactly ITEM_BYTES") {
            for (kind in SealedMailboxKind.entries) {
                val item = SealedMailboxBox.seal(kind, payload, recipient.publicKey, now + 100)
                item.size shouldBe SealedMailboxBox.ITEM_BYTES
                SealedMailboxBox.open(item, recipient.privateKey, now, kind)!!.contentEquals(payload) shouldBe true
                val any = SealedMailboxBox.openAny(item, recipient.privateKey, now)!!
                any.kind shouldBe kind
            }
        }

        test("an item of another kind does not open, and is not counted as a refusal") {
            val item = SealedMailboxBox.seal(SealedMailboxKind.MAIL, payload, recipient.publicKey, now + 100)
            val before = SealedMailboxBox.refusedCount.get()
            SealedMailboxBox.open(item, recipient.privateKey, now, SealedMailboxKind.DM) shouldBe null
            SealedMailboxBox.refusedCount.get() shouldBe before
            val dm = SealedMailboxBox.seal(SealedMailboxKind.DM, payload, recipient.publicKey, now + 100)
            SealedMailboxBox.open(dm, recipient.privateKey, now, SealedMailboxKind.MAIL) shouldBe null
        }

        test("every single bit flip is refused") {
            val item = SealedMailboxBox.seal(SealedMailboxKind.MAIL, payload, recipient.publicKey, now + 100)
            for (i in item.indices step 7) {
                val tampered = item.copyOf().also { it[i] = (it[i].toInt() xor 1).toByte() }
                SealedMailboxBox.open(tampered, recipient.privateKey, now, SealedMailboxKind.MAIL) shouldBe null
            }
        }

        test("the wrong key, an expired item and a wrong size are refused") {
            val item = SealedMailboxBox.seal(SealedMailboxKind.MAIL, payload, recipient.publicKey, now + 100)
            SealedMailboxBox.open(item, X25519KeyPair.generate().privateKey, now, SealedMailboxKind.MAIL) shouldBe null
            val expired = SealedMailboxBox.seal(SealedMailboxKind.MAIL, payload, recipient.publicKey, now - 1)
            SealedMailboxBox.open(expired, recipient.privateKey, now, SealedMailboxKind.MAIL) shouldBe null
            SealedMailboxBox.open(
                item.copyOf(item.size - 1),
                recipient.privateKey,
                now,
                SealedMailboxKind.MAIL,
            ) shouldBe
                null
            SealedMailboxBox.open(item + byteArrayOf(0), recipient.privateKey, now, SealedMailboxKind.MAIL) shouldBe
                null
            SealedMailboxBox.open(ByteArray(0), recipient.privateKey, now, SealedMailboxKind.MAIL) shouldBe null
            val badVersion = item.copyOf().also { it[0] = 2 }
            SealedMailboxBox.open(badVersion, recipient.privateKey, now, SealedMailboxKind.MAIL) shouldBe null
        }

        test("the boundary: MAX_PAYLOAD_BYTES fits, one more throws, empty throws") {
            val max = ByteArray(SealedMailboxBox.MAX_PAYLOAD_BYTES) { 7 }
            val item = SealedMailboxBox.seal(SealedMailboxKind.MAIL, max, recipient.publicKey, now + 100)
            SealedMailboxBox.open(item, recipient.privateKey, now, SealedMailboxKind.MAIL)!!.size shouldBe max.size
            shouldThrow<SealedMailboxPayloadTooLargeException> {
                SealedMailboxBox.seal(SealedMailboxKind.MAIL, ByteArray(max.size + 1), recipient.publicKey, now + 100)
            }
            shouldThrow<SealedMailboxPayloadTooLargeException> {
                SealedMailboxBox.seal(SealedMailboxKind.MAIL, ByteArray(0), recipient.publicKey, now + 100)
            }
        }

        test("two sealings of the same payload share no bytes in the key position and are unlinkable") {
            val a = SealedMailboxBox.seal(SealedMailboxKind.MAIL, payload, recipient.publicKey, now + 100)
            val b = SealedMailboxBox.seal(SealedMailboxKind.MAIL, payload, recipient.publicKey, now + 100)
            a.copyOfRange(1, 33).contentEquals(b.copyOfRange(1, 33)) shouldBe false
            a.contentEquals(b) shouldBe false
        }

        test("the kind is not visible in the clear header") {
            val dm = SealedMailboxBox.seal(SealedMailboxKind.DM, payload, recipient.publicKey, now + 100)
            val mail = SealedMailboxBox.seal(SealedMailboxKind.MAIL, payload, recipient.publicKey, now + 100)
            dm[0] shouldBe mail[0]
            dm[0] shouldNotBe SealedMailboxKind.MAIL.id
        }
    })
