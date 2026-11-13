package net.lapisphilosophorum.lapisnet.dm

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair

class DmX3dhRejectionCodecTest :
    FunSpec({
        val responder = DualKeyIdentity.generate()
        val initiator = DualKeyIdentity.generate()
        val responderX = X25519KeyPair.generate()
        val initiatorX = X25519KeyPair.generate()
        val rKey = responder.secp256k1KeyPair.publicKey
        val iKey = initiator.secp256k1KeyPair.publicKey

        fun fields(otk: Int? = 7) =
            DmX3dhRejectionCodec.Fields(
                rKey,
                X25519KeyPair.generate().publicKey,
                3,
                otk,
                DmX3dhRejectionReason.ONE_TIME_PREKEY_CONSUMED,
                1_700_000_000L,
            )

        fun rejection(otk: Int? = 7) =
            DmX3dhRejectionCodec.create(responderX.privateKey, initiatorX.publicKey, iKey, fields(otk))

        test("frame size is pinned and below the envelope ceiling") {
            DmX3dhRejectionCodec.FRAME_SIZE shouldBe 122
            (DmX3dhRejectionCodec.FRAME_SIZE < DmEnvelopeCodec.MAX_ENVELOPE_BYTES) shouldBe true
        }

        test("roundtrip with and without a one-time prekey id; the initiator verifies the tag") {
            for (otk in listOf(7, null)) {
                val r = rejection(otk)
                val decoded = DmX3dhRejectionCodec.decode(DmX3dhRejectionCodec.encode(r))
                decoded.oneTimePrekeyId shouldBe otk
                decoded.signedPrekeyId shouldBe 3
                decoded.reason shouldBe DmX3dhRejectionReason.ONE_TIME_PREKEY_CONSUMED
                DmX3dhRejectionCodec.verifyTag(initiatorX.privateKey, responderX.publicKey, iKey, decoded) shouldBe true
            }
        }

        test("every manipulated byte of the authenticated part or the tag breaks verification or decoding") {
            val bytes = DmX3dhRejectionCodec.encode(rejection())
            for (i in 7 until bytes.size) {
                val tampered = bytes.copyOf().also { it[i] = (it[i].toInt() xor 0x01).toByte() }
                val outcome = runCatching { DmX3dhRejectionCodec.decode(tampered) }
                outcome.fold(
                    {
                        DmX3dhRejectionCodec.verifyTag(initiatorX.privateKey, responderX.publicKey, iKey, it) shouldBe
                            false
                    },
                    { it.shouldBeInstanceOf<MalformedDmEnvelopeException>() },
                )
            }
        }

        test("a tag from a third party's key does not verify; a wrong initiator identity does not verify") {
            val third = X25519KeyPair.generate()
            val forged = DmX3dhRejectionCodec.create(third.privateKey, initiatorX.publicKey, iKey, fields())
            DmX3dhRejectionCodec.verifyTag(initiatorX.privateKey, responderX.publicKey, iKey, forged) shouldBe false
            val genuine = rejection()
            val other = DualKeyIdentity.generate().secp256k1KeyPair.publicKey
            DmX3dhRejectionCodec.verifyTag(initiatorX.privateKey, responderX.publicKey, other, genuine) shouldBe false
        }

        test("structurally malformed frames are rejected") {
            val bytes = DmX3dhRejectionCodec.encode(rejection())
            shouldThrow<MalformedDmEnvelopeException> { DmX3dhRejectionCodec.decode(bytes.copyOf(bytes.size - 1)) }
            shouldThrow<MalformedDmEnvelopeException> { DmX3dhRejectionCodec.decode(bytes + byteArrayOf(0)) }
            // unknown reason
            shouldThrow<MalformedDmEnvelopeException> {
                DmX3dhRejectionCodec.decode(
                    bytes.copyOf().also { it[81] = 9 },
                )
            }
            // all-zero ephemeral
            shouldThrow<MalformedDmEnvelopeException> {
                DmX3dhRejectionCodec.decode(bytes.copyOf().also { b -> for (i in 40 until 72) b[i] = 0 })
            }
            // negative signed-prekey id
            shouldThrow<MalformedDmEnvelopeException> {
                DmX3dhRejectionCodec.decode(
                    bytes.copyOf().also {
                        it[72] =
                            0x80.toByte()
                    },
                )
            }
            // absent otk with a non-zero id
            val noOtk = DmX3dhRejectionCodec.encode(rejection(null))
            shouldThrow<MalformedDmEnvelopeException> {
                DmX3dhRejectionCodec.decode(
                    noOtk.copyOf().also { it[80] = 1 },
                )
            }
        }

        test(
            "compatibility: decode() (mailbox paths, older nodes) rejects a type-4 frame; decodeFrame() tells them apart",
        ) {
            val bytes = DmX3dhRejectionCodec.encode(rejection())
            shouldThrow<MalformedDmEnvelopeException> { DmEnvelopeCodec.decode(bytes) }
            // even padded to a full envelope size, type 4 is never a DmEnvelope
            shouldThrow<MalformedDmEnvelopeException> { DmEnvelopeCodec.decode(bytes + ByteArray(400)) }
            DmEnvelopeCodec.decodeFrame(bytes).shouldBeInstanceOf<DmInboundFrame.X3dhRejection>()
            // an unknown future type (9) is malformed for decodeFrame as well: the live doors drop it silently
            shouldThrow<MalformedDmEnvelopeException> { DmEnvelopeCodec.decodeFrame(bytes.copyOf().also { it[6] = 9 }) }
        }

        test("toString never prints keys or the tag") {
            val r = rejection()
            r.toString().contains(rKey.fingerprint()) shouldBe false
        }
    })
