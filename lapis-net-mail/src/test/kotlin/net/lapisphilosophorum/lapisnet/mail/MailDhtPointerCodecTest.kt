package net.lapisphilosophorum.lapisnet.mail

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.directory.OutboxEntryKind

private fun cidOf(seed: Byte): Cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { seed })

class MailDhtPointerCodecTest :
    FunSpec({
        test("a pointer round-trips") {
            val cid = cidOf(4)
            val bytes = MailDhtPointerCodec.encode(MailDhtPointer(cid))
            MailDhtPointerCodec.decode(bytes).envelopeCid shouldBe cid
            (bytes.size <= MailDhtPointerCodec.MAX_BYTES) shouldBe true
        }

        test("the mirrored size constant of the directory module is the real maximum") {
            OutboxEntryKind.MAIL_POINTER.maxPayloadBytes shouldBe MailDhtPointerCodec.MAX_BYTES
        }

        test("a wrong version, a wrong length, trailing bytes and truncation are malformed") {
            val bytes = MailDhtPointerCodec.encode(MailDhtPointer(cidOf(1)))
            shouldThrow<MalformedMailDhtPointerException> {
                MailDhtPointerCodec.decode(bytes.copyOf().also { it[0] = 2 })
            }
            shouldThrow<MalformedMailDhtPointerException> {
                MailDhtPointerCodec.decode(bytes.copyOf().also { it[1] = (it[1] + 1).toByte() })
            }
            shouldThrow<MalformedMailDhtPointerException> {
                MailDhtPointerCodec.decode(bytes.copyOf().also { it[1] = 0 })
            }
            shouldThrow<MalformedMailDhtPointerException> { MailDhtPointerCodec.decode(bytes + byteArrayOf(0)) }
            shouldThrow<MalformedMailDhtPointerException> { MailDhtPointerCodec.decode(bytes.copyOf(bytes.size - 1)) }
            shouldThrow<MalformedMailDhtPointerException> { MailDhtPointerCodec.decode(ByteArray(0)) }
            shouldThrow<MalformedMailDhtPointerException> { MailDhtPointerCodec.decode(ByteArray(2)) }
        }

        test("an oversized input is refused before anything is allocated from its length fields") {
            shouldThrow<MalformedMailDhtPointerException> {
                MailDhtPointerCodec.decode(ByteArray(MailDhtPointerCodec.MAX_BYTES + 1) { 1 })
            }
            // length byte claims 128 bytes but a CID with a hostile multihash length follows
            val hostile = ByteArray(2 + 128) { 0x7F }
            hostile[0] = 1
            hostile[1] = 127.toByte()
            shouldThrow<MalformedMailDhtPointerException> { MailDhtPointerCodec.decode(hostile.copyOf(2 + 127)) }
        }

        test("random garbage never throws anything but the codec's own exception") {
            val random = java.util.Random(11)
            repeat(300) {
                val garbage = ByteArray(random.nextInt(140)).also { random.nextBytes(it) }
                runCatching { MailDhtPointerCodec.decode(garbage) }.onFailure {
                    (it is MalformedMailDhtPointerException) shouldBe true
                }
            }
        }
    })
