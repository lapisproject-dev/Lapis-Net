package net.lapisphilosophorum.lapisnet.dm

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import net.lapisphilosophorum.lapisnet.identity.EncryptionKeyBinding
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.ratchet.RatchetMessageCodec
import net.lapisphilosophorum.lapisnet.ratchet.X3dhPreKeyMessageHeader

private fun sampleX3dhHeader(
    initiatorIdentity: net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey,
): X3dhPreKeyMessageHeader {
    val x25519 = X25519KeyPair.generate()
    val binding = EncryptionKeyBinding.create(Secp256k1KeyPair.generate(), x25519.publicKey)
    return X3dhPreKeyMessageHeader(
        initiatorIdentity = initiatorIdentity,
        initiatorEncryptionBinding = binding,
        ephemeralPublicKey = X25519KeyPair.generate().publicKey,
        signedPrekeyId = 7,
        oneTimePrekeyId = 3,
    )
}

class DmEnvelopeCodecTest :
    FunSpec({
        test("TEXT envelope round-trips byte-exact") {
            val message = dmSampleRatchetMessage()
            val sender = Secp256k1KeyPair.generate().publicKey
            val envelope = DmEnvelope(DmMessageType.TEXT, sender, null, message)
            val bytes = DmEnvelopeCodec.encode(envelope)
            val decoded = DmEnvelopeCodec.decode(bytes)

            decoded.messageType shouldBe DmMessageType.TEXT
            decoded.senderIdentity shouldBe sender
            decoded.x3dhInitialHeader shouldBe null
            DmEnvelopeCodec.encode(decoded) shouldBe bytes
        }

        test("X3DH_INITIAL envelope round-trips byte-exact, including the embedded X3DH header") {
            val message = dmSampleRatchetMessage()
            val sender = Secp256k1KeyPair.generate().publicKey
            // sampleX3dhHeader signs its own EncryptionKeyBinding with an unrelated key - fine for a
            // pure codec round-trip test (the codec never checks binding signature validity, only
            // structural shape); DmEnvelope's own init requires header.initiatorIdentity ==
            // senderIdentity, so pass `sender` there explicitly.
            val header = sampleX3dhHeader(sender)
            val envelope = DmEnvelope(DmMessageType.X3DH_INITIAL, sender, header, message)
            val bytes = DmEnvelopeCodec.encode(envelope)
            val decoded = DmEnvelopeCodec.decode(bytes)

            decoded.messageType shouldBe DmMessageType.X3DH_INITIAL
            decoded.senderIdentity shouldBe sender
            decoded.x3dhInitialHeader shouldNotBe null
            DmEnvelopeCodec.encode(decoded) shouldBe bytes
        }

        test("X3DH_INITIAL header fields survive the round trip exactly") {
            val message = dmSampleRatchetMessage()
            val sender = Secp256k1KeyPair.generate().publicKey
            val header = sampleX3dhHeader(sender)
            val envelope = DmEnvelope(DmMessageType.X3DH_INITIAL, sender, header, message)
            val decoded = DmEnvelopeCodec.decode(DmEnvelopeCodec.encode(envelope))

            val decodedHeader = requireNotNull(decoded.x3dhInitialHeader)
            decodedHeader.initiatorIdentity shouldBe sender
            decodedHeader.initiatorEncryptionBinding.x25519PublicKey shouldBe
                header.initiatorEncryptionBinding.x25519PublicKey
            decodedHeader.initiatorEncryptionBinding.signature shouldBe header.initiatorEncryptionBinding.signature
            decodedHeader.ephemeralPublicKey shouldBe header.ephemeralPublicKey
            decodedHeader.signedPrekeyId shouldBe header.signedPrekeyId
            decodedHeader.oneTimePrekeyId shouldBe header.oneTimePrekeyId
        }

        test("X3DH_INITIAL with no one-time prekey (oneTimePrekeyId == null) round-trips") {
            val message = dmSampleRatchetMessage()
            val sender = Secp256k1KeyPair.generate().publicKey
            val x25519 = X25519KeyPair.generate()
            val binding = EncryptionKeyBinding.create(Secp256k1KeyPair.generate(), x25519.publicKey)
            val header =
                X3dhPreKeyMessageHeader(
                    initiatorIdentity = sender,
                    initiatorEncryptionBinding = binding,
                    ephemeralPublicKey = X25519KeyPair.generate().publicKey,
                    signedPrekeyId = 0,
                    oneTimePrekeyId = null,
                )
            val envelope = DmEnvelope(DmMessageType.X3DH_INITIAL, sender, header, message)
            val decoded = DmEnvelopeCodec.decode(DmEnvelopeCodec.encode(envelope))
            decoded.x3dhInitialHeader?.oneTimePrekeyId shouldBe null
        }

        test("RECEIPT messageType byte is rejected outright, before senderIdentity is parsed") {
            val message = dmSampleRatchetMessage()
            val sender = Secp256k1KeyPair.generate().publicKey
            val validTextEnvelope = DmEnvelope(DmMessageType.TEXT, sender, null, message)

            val receiptBytes = DmEnvelopeCodec.encode(validTextEnvelope).copyOf()
            receiptBytes[6] = DmMessageType.RECEIPT.wireValue
            shouldThrow<MalformedDmEnvelopeException> { DmEnvelopeCodec.decode(receiptBytes) }
        }

        // V0.8.7: CALL_SIGNAL is active, not rejected - see DmMessageType's own class doc comment.
        // A CALL_SIGNAL envelope decodes structurally exactly like a TEXT one (this codec is entirely
        // agnostic to what the ratchet plaintext frames - see DmEnvelopeCodec's own class doc
        // comment); DmSessionManager, not this codec, is what routes a decoded CALL_SIGNAL envelope
        // differently (see DmSessionManagerCallSignalTest/CallSignalMailboxRejectionTest).
        test("CALL_SIGNAL messageType byte decodes structurally cleanly and reports messageType == CALL_SIGNAL") {
            val message = dmSampleRatchetMessage()
            val sender = Secp256k1KeyPair.generate().publicKey
            val envelope = DmEnvelope(DmMessageType.CALL_SIGNAL, sender, null, message)
            val bytes = DmEnvelopeCodec.encode(envelope)
            val decoded = DmEnvelopeCodec.decode(bytes)

            decoded.messageType shouldBe DmMessageType.CALL_SIGNAL
            decoded.senderIdentity shouldBe sender
            decoded.x3dhInitialHeader shouldBe null
            DmEnvelopeCodec.encode(decoded) shouldBe bytes
        }

        test("an unknown messageType wire byte is rejected") {
            val message = dmSampleRatchetMessage()
            val sender = Secp256k1KeyPair.generate().publicKey
            val bytes = DmEnvelopeCodec.encode(DmEnvelope(DmMessageType.TEXT, sender, null, message)).copyOf()
            bytes[6] = 99
            shouldThrow<MalformedDmEnvelopeException> { DmEnvelopeCodec.decode(bytes) }
        }

        test("reserved flag bits set are rejected") {
            val message = dmSampleRatchetMessage()
            val sender = Secp256k1KeyPair.generate().publicKey
            val bytes = DmEnvelopeCodec.encode(DmEnvelope(DmMessageType.TEXT, sender, null, message)).copyOf()
            bytes[5] = 1
            shouldThrow<MalformedDmEnvelopeException> { DmEnvelopeCodec.decode(bytes) }
        }

        test("x3dhInitialHeaderPresent inconsistent with messageType is rejected - TEXT claiming present") {
            val message = dmSampleRatchetMessage()
            val sender = Secp256k1KeyPair.generate().publicKey
            val bytes = DmEnvelopeCodec.encode(DmEnvelope(DmMessageType.TEXT, sender, null, message)).copyOf()
            bytes[40] = 1
            shouldThrow<MalformedDmEnvelopeException> { DmEnvelopeCodec.decode(bytes) }
        }

        test("x3dhInitialHeaderPresent inconsistent with messageType is rejected - X3DH_INITIAL claiming absent") {
            val message = dmSampleRatchetMessage()
            val sender = Secp256k1KeyPair.generate().publicKey
            val header = sampleX3dhHeader(sender)
            val bytes = DmEnvelopeCodec.encode(DmEnvelope(DmMessageType.X3DH_INITIAL, sender, header, message)).copyOf()
            bytes[40] = 0
            shouldThrow<MalformedDmEnvelopeException> { DmEnvelopeCodec.decode(bytes) }
        }

        test("a non-zero byte anywhere in an absent X3DH section is tamper evidence and rejected") {
            val message = dmSampleRatchetMessage()
            val sender = Secp256k1KeyPair.generate().publicKey
            val bytes = DmEnvelopeCodec.encode(DmEnvelope(DmMessageType.TEXT, sender, null, message))
            // The 137-byte X3DH section spans offsets [41, 178). Sample offsets across it.
            listOf(41, 73, 100, 137, 169, 173, 174, 177).forEach { offset ->
                val tampered = bytes.copyOf()
                tampered[offset] = 1
                shouldThrow<MalformedDmEnvelopeException> { DmEnvelopeCodec.decode(tampered) }
            }
        }

        test("a bogus senderIdentity that is not a valid secp256k1 curve point is rejected") {
            val message = dmSampleRatchetMessage()
            val sender = Secp256k1KeyPair.generate().publicKey
            val bytes = DmEnvelopeCodec.encode(DmEnvelope(DmMessageType.TEXT, sender, null, message)).copyOf()
            for (offset in 7 until 40) bytes[offset] = 0xFF.toByte()
            shouldThrow<MalformedDmEnvelopeException> { DmEnvelopeCodec.decode(bytes) }
        }

        test("oversized ratchetMessageLength declared with no matching body is rejected before allocation") {
            val message = dmSampleRatchetMessage()
            val sender = Secp256k1KeyPair.generate().publicKey
            val bytes = DmEnvelopeCodec.encode(DmEnvelope(DmMessageType.TEXT, sender, null, message)).copyOf()
            // Declare the maximum possible ratchetMessageLength (0xFFFF) while leaving far fewer
            // actual trailing bytes - the exact malicious-length-style payload this codebase's
            // CID-length-OOM history demands checking for.
            bytes[178] = 0xFF.toByte()
            bytes[179] = 0xFF.toByte()
            val start = System.nanoTime()
            shouldThrow<MalformedDmEnvelopeException> { DmEnvelopeCodec.decode(bytes) }
            val elapsedMs = (System.nanoTime() - start) / 1_000_000
            // No allocation proportional to the declared 65535-byte length occurred - this should
            // reject near-instantly, not hang or visibly delay.
            (elapsedMs < 2000).shouldBe(true)
        }

        test("ratchetMessageLength of zero is rejected (must be >= 1)") {
            val message = dmSampleRatchetMessage()
            val sender = Secp256k1KeyPair.generate().publicKey
            val bytes = DmEnvelopeCodec.encode(DmEnvelope(DmMessageType.TEXT, sender, null, message)).copyOf()
            bytes[178] = 0
            bytes[179] = 0
            shouldThrow<MalformedDmEnvelopeException> { DmEnvelopeCodec.decode(bytes) }
        }

        test("declared ratchetMessageLength inconsistent with actual trailing bytes is rejected") {
            val message = dmSampleRatchetMessage()
            val sender = Secp256k1KeyPair.generate().publicKey
            val bytes = DmEnvelopeCodec.encode(DmEnvelope(DmMessageType.TEXT, sender, null, message))
            val truncated = bytes.copyOf(bytes.size - 5)
            shouldThrow<MalformedDmEnvelopeException> { DmEnvelopeCodec.decode(truncated) }
        }

        test("truncation at every major offset boundary is rejected cleanly") {
            val message = dmSampleRatchetMessage()
            val sender = Secp256k1KeyPair.generate().publicKey
            val header = sampleX3dhHeader(sender)
            val bytes = DmEnvelopeCodec.encode(DmEnvelope(DmMessageType.X3DH_INITIAL, sender, header, message))
            val boundaries = listOf(0, 1, 4, 5, 6, 7, 40, 41, 73, 137, 169, 173, 174, 178, 179, 180, bytes.size - 1)
            boundaries.forEach { cutAt ->
                shouldThrow<MalformedDmEnvelopeException> { DmEnvelopeCodec.decode(bytes.copyOf(cutAt)) }
            }
        }

        test("oversized total frame (> MAX_ENVELOPE_BYTES) is rejected on the first line") {
            val oversized = ByteArray(DmEnvelopeCodec.MAX_ENVELOPE_BYTES + 1)
            shouldThrow<MalformedDmEnvelopeException> { DmEnvelopeCodec.decode(oversized) }
        }

        test("bad magic is rejected") {
            val message = dmSampleRatchetMessage()
            val sender = Secp256k1KeyPair.generate().publicKey
            val bytes = DmEnvelopeCodec.encode(DmEnvelope(DmMessageType.TEXT, sender, null, message)).copyOf()
            bytes[0] = (bytes[0] + 1).toByte()
            shouldThrow<MalformedDmEnvelopeException> { DmEnvelopeCodec.decode(bytes) }
        }

        test("unsupported version is rejected") {
            val message = dmSampleRatchetMessage()
            val sender = Secp256k1KeyPair.generate().publicKey
            val bytes = DmEnvelopeCodec.encode(DmEnvelope(DmMessageType.TEXT, sender, null, message)).copyOf()
            bytes[4] = 2
            shouldThrow<MalformedDmEnvelopeException> { DmEnvelopeCodec.decode(bytes) }
        }

        test("garbage random bytes never throw anything other than MalformedDmEnvelopeException") {
            val random = java.security.SecureRandom()
            repeat(50) {
                val garbage = ByteArray(200 + random.nextInt(500)).also(random::nextBytes)
                shouldThrow<MalformedDmEnvelopeException> { DmEnvelopeCodec.decode(garbage) }
            }
        }

        test("MAX_ENVELOPE_BYTES matches the documented formula") {
            DmEnvelopeCodec.MAX_ENVELOPE_BYTES shouldBe
                DmEnvelopeCodec.DM_ENVELOPE_FIXED_PREFIX_SIZE + 2 + RatchetMessageCodec.MAX_MESSAGE_BYTES
            DmEnvelopeCodec.DM_ENVELOPE_FIXED_PREFIX_SIZE shouldBe 178
        }
    })
