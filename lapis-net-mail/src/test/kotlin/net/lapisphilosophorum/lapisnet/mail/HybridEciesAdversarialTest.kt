package net.lapisphilosophorum.lapisnet.mail

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.libp2p.core.pubsub.ValidationResult
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.identity.ecdhSharedSecret
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.networking.deriveLibp2pPeerId
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.file.Files
import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Offset of the wrap section's first byte (`wrapCount`) inside a [MessageEnvelopeCodec.encode]
 * output for an envelope with NO replyTo/threadRoot - mirrors the `encryptionByteOffset` arithmetic
 * idiom already established in `MessageEnvelopeCodecTest`/`MailEnvelopeAbuseTest`. */
private fun wrapSectionOffset(
    recipientCount: Int,
    contentCidByteSize: Int,
): Int = 4 + 1 + 1 + 33 + 2 + 33 * recipientCount + 8 + 1 + 2 + contentCidByteSize

/**
 * The security-critical spec of V0.9.2. See [MailAadContext]'s and [HybridEcies]'s class doc
 * comments for the design this proves is actually load-bearing.
 */
class HybridEciesAdversarialTest :
    FunSpec({
        test(
            "(a) WRAP TRANSPLANT: a legitimately-sealed body+wraps attached to a different-sender envelope fails to open",
        ) {
            val s1 = Secp256k1KeyPair.generate()
            val s2 = Secp256k1KeyPair.generate()
            val r1 = Secp256k1KeyPair.generate()
            val body = MessageBody(subject = "secret", body = "for r1's eyes only")

            val contextA =
                MailAadContext.forNewMessage(s1.publicKey, listOf(r1.publicKey), sentAtEpochSecond = 5_000)
            val sealed = HybridEcies.seal(body, s1, contextA)
            val envelopeA =
                MessageEnvelope.create(
                    sender = s1,
                    recipients = listOf(r1.publicKey),
                    contentCid = sealed.contentCid,
                    sentAtEpochSecond = 5_000,
                    encryption = EncryptionMode.HYBRID_ECIES,
                    wraps = sealed.wraps,
                )

            // Envelope B: same recipients, same contentCid, same timestamp/reply/thread, SAME
            // wraps (W_A) and sealed body - but a DIFFERENT, genuinely-signing sender S2.
            val envelopeB =
                MessageEnvelope.create(
                    sender = s2,
                    recipients = listOf(r1.publicKey),
                    contentCid = sealed.contentCid,
                    sentAtEpochSecond = 5_000,
                    encryption = EncryptionMode.HYBRID_ECIES,
                    wraps = sealed.wraps,
                )

            // 1. Envelope B is genuinely, cryptographically valid.
            MessageEnvelope.verify(envelopeB) shouldBe true

            // 2. Every V0.9.1 layer accepts the forgery - this establishes that nothing but the
            // AAD stands between the attacker and success.
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("wrap-transplant"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val frameB = MailFrameCodec.encode(MessageEnvelopeCodec.encode(envelopeB), sealed.sealedBodyBytes)
                val index = InboxIndex()

                val result = InboxGossip.onGossipMessage(frameB, from, storage, index, r1.publicKey)

                result shouldBe ValidationResult.Valid

                // 3. The recipient's decrypt call still fails.
                shouldThrow<MailDecryptionException> { HybridEcies.open(envelopeB, sealed.sealedBody, r1) }

                // 4. LOAD-BEARING PROOF: open the IDENTICAL wraps/sealedBody/localIdentity under
                // two different MailAadContexts - only the context differs.
                val contextForA = MailAadContext.of(envelopeA)
                val contextForB = MailAadContext.of(envelopeB)

                val openedUnderA =
                    HybridEcies.openWithContext(contextForA, sealed.contentCid, sealed.wraps, sealed.sealedBody, r1)
                openedUnderA shouldBe body

                val transplantException =
                    shouldThrow<MailDecryptionException> {
                        HybridEcies.openWithContext(contextForB, sealed.contentCid, sealed.wraps, sealed.sealedBody, r1)
                    }
                // Assert it failed for the RIGHT reason: contextForB.recipients is still [r1], so
                // slot resolution still succeeds and execution reaches the AEAD - the AAD mismatch
                // is what fails the wrap's GCM tag, not an earlier "no wrap for you" short-circuit.
                // Mirrors test (d)'s identical assertion, so a future change to slot-resolution that
                // accidentally short-circuits before the AEAD would turn this assertion red instead
                // of silently no longer exercising the AAD binding at all.
                transplantException.cause shouldNotBe null
                (transplantException.cause is AEADBadTagException) shouldBe true

                // Pin WHICH binding did the work: the two contexts differ, specifically at the
                // sender field's offset inside contextBytes (5..37, see MailAadContext's layout).
                contextForA.contextBytes shouldNotBe contextForB.contextBytes
                val senderRangeA = contextForA.contextBytes.copyOfRange(5, 38)
                val senderRangeB = contextForB.contextBytes.copyOfRange(5, 38)
                senderRangeA shouldNotBe senderRangeB
                senderRangeA shouldBe s1.publicKey.bytes
                senderRangeB shouldBe s2.publicKey.bytes

                // 5. Recipient-set-extension variant: sender stays S1, but recipients become
                // [R1, R2] while reusing A's original signature (via fromDecoded, padding the wrap
                // list to satisfy the count invariant with a dummy wrap for R2). The signature
                // alone already rejects this - but the AAD is independently sufficient too.
                val r2 = Secp256k1KeyPair.generate()
                val paddedWraps =
                    sealed.wraps + EciesWrap(Secp256k1KeyPair.generate().publicKey, ByteArray(WRAPPED_KEY_SIZE))
                val envelopeBPrime =
                    MessageEnvelope.fromDecoded(
                        sender = s1.publicKey,
                        recipients = listOf(r1.publicKey, r2.publicKey),
                        sentAtEpochSecond = 5_000,
                        encryption = EncryptionMode.HYBRID_ECIES,
                        contentCid = sealed.contentCid,
                        replyTo = null,
                        threadRoot = null,
                        signature = envelopeA.signature,
                        wraps = paddedWraps,
                    )

                MessageEnvelope.verify(envelopeBPrime) shouldBe false

                val contextForBPrime = MailAadContext.of(envelopeBPrime)
                shouldThrow<MailDecryptionException> {
                    HybridEcies.openWithContext(contextForBPrime, sealed.contentCid, paddedWraps, sealed.sealedBody, r1)
                }
            } finally {
                node.stop()
            }
        }

        test("(b) a tampered (but valid) ephemeral public key in a wrap fails to open") {
            val sender = Secp256k1KeyPair.generate()
            val recipient = Secp256k1KeyPair.generate()
            val body = MessageBody(subject = "s", body = "b")
            val context = MailAadContext.forNewMessage(sender.publicKey, listOf(recipient.publicKey), 1_000)
            val sealed = HybridEcies.seal(body, sender, context)
            val envelope =
                MessageEnvelope.create(
                    sender,
                    listOf(recipient.publicKey),
                    sealed.contentCid,
                    1_000,
                    encryption = EncryptionMode.HYBRID_ECIES,
                    wraps = sealed.wraps,
                )

            val substituteEphemeral = Secp256k1KeyPair.generate().publicKey
            val tamperedWraps =
                sealed.wraps.mapIndexed { i, wrap ->
                    if (i ==
                        0
                    ) {
                        EciesWrap(substituteEphemeral, wrap.wrappedKey)
                    } else {
                        wrap
                    }
                }

            shouldThrow<MailDecryptionException> {
                HybridEcies.openWithContext(context, sealed.contentCid, tamperedWraps, sealed.sealedBody, recipient)
            }
        }

        test("(c1) an off-curve ephemeral 'public key' is rejected by Secp256k1PublicKey's own constructor") {
            val offCurveBytes = byteArrayOf(0x02) + ByteArray(32) { 0xFF.toByte() }

            val exception = shouldThrow<IllegalArgumentException> { Secp256k1PublicKey(offCurveBytes) }
            exception.message?.contains("valid point on the curve") shouldBe true
        }

        test("(c2) an off-curve ephemeral public key on the wire never reaches ECDH - rejected at decode/validator") {
            val sender = Secp256k1KeyPair.generate()
            val recipient = Secp256k1KeyPair.generate()
            val body = MessageBody(subject = "s", body = "b")
            val context = MailAadContext.forNewMessage(sender.publicKey, listOf(recipient.publicKey), 1_000)
            val sealed = HybridEcies.seal(body, sender, context)
            val envelope =
                MessageEnvelope.create(
                    sender,
                    listOf(recipient.publicKey),
                    sealed.contentCid,
                    1_000,
                    encryption = EncryptionMode.HYBRID_ECIES,
                    wraps = sealed.wraps,
                )
            val bytes = MessageEnvelopeCodec.encode(envelope)

            val contentCidByteSize = sealed.contentCid.toBytes().size
            val wrapSectionStart = wrapSectionOffset(recipientCount = 1, contentCidByteSize = contentCidByteSize)
            // wrapCount(2) then the first wrap's 33-byte ephemeral public key.
            val firstWrapEphemeralOffset = wrapSectionStart + 2
            val offCurveBytes = byteArrayOf(0x02) + ByteArray(32) { 0xFF.toByte() }
            val corrupted = bytes.copyOf()
            offCurveBytes.copyInto(corrupted, destinationOffset = firstWrapEphemeralOffset)

            shouldThrow<MalformedMessageEnvelopeException> { MessageEnvelopeCodec.decode(corrupted) }

            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("offcurve-wire"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val frame = MailFrameCodec.encode(corrupted, sealed.sealedBodyBytes)
                val index = InboxIndex()

                InboxGossip.onGossipMessage(frame, from, storage, index, recipient.publicKey) shouldBe
                    ValidationResult.Invalid
            } finally {
                node.stop()
            }
        }

        test(
            "(d) a single-bit flip in a wrap's ciphertext fails cleanly - AEADBadTagException never escapes as itself",
        ) {
            val sender = Secp256k1KeyPair.generate()
            val recipient = Secp256k1KeyPair.generate()
            val body = MessageBody(subject = "s", body = "b")
            val context = MailAadContext.forNewMessage(sender.publicKey, listOf(recipient.publicKey), 1_000)
            val sealed = HybridEcies.seal(body, sender, context)

            listOf(0, WRAPPED_KEY_SIZE / 2, WRAPPED_KEY_SIZE - 1).forEach { byteIndex ->
                val tamperedKey = sealed.wraps[0].wrappedKey
                tamperedKey[byteIndex] = (tamperedKey[byteIndex].toInt() xor 0x01).toByte()
                val tamperedWraps =
                    sealed.wraps.mapIndexed { i, wrap ->
                        if (i == 0) EciesWrap(wrap.ephemeralPublicKey, tamperedKey) else wrap
                    }

                val exception =
                    shouldThrow<MailDecryptionException> {
                        HybridEcies.openWithContext(
                            context,
                            sealed.contentCid,
                            tamperedWraps,
                            sealed.sealedBody,
                            recipient,
                        )
                    }
                exception.cause shouldNotBe null
                (exception.cause is AEADBadTagException) shouldBe true
            }
        }

        test("(e) a tampered GCM tag / nonce on the body ciphertext fails cleanly") {
            val sender = Secp256k1KeyPair.generate()
            val recipient = Secp256k1KeyPair.generate()
            val body = MessageBody(subject = "s", body = "b")
            val context = MailAadContext.forNewMessage(sender.publicKey, listOf(recipient.publicKey), 1_000)
            val sealed = HybridEcies.seal(body, sender, context)

            val tamperedTag = sealed.sealedBody.ciphertext
            tamperedTag[tamperedTag.size - 1] = (tamperedTag[tamperedTag.size - 1].toInt() xor 0x01).toByte()
            val bodyWithTamperedTag = SealedBody(sealed.sealedBody.nonce, tamperedTag)
            shouldThrow<MailDecryptionException> {
                HybridEcies.openWithContext(context, sealed.contentCid, sealed.wraps, bodyWithTamperedTag, recipient)
            }

            val tamperedNonce = sealed.sealedBody.nonce
            tamperedNonce[0] = (tamperedNonce[0].toInt() xor 0x01).toByte()
            val bodyWithTamperedNonce = SealedBody(tamperedNonce, sealed.sealedBody.ciphertext)
            shouldThrow<MailDecryptionException> {
                HybridEcies.openWithContext(context, sealed.contentCid, sealed.wraps, bodyWithTamperedNonce, recipient)
            }
        }

        test(
            "(f1) codec rejects a wrap-count that does not match recipientCount + 1 - before allocation, not truncation",
        ) {
            val sender = Secp256k1KeyPair.generate()
            val r1 = Secp256k1KeyPair.generate()
            val r2 = Secp256k1KeyPair.generate()
            val body = MessageBody(subject = "s", body = "b")
            val context = MailAadContext.forNewMessage(sender.publicKey, listOf(r1.publicKey, r2.publicKey), 1_000)
            val sealed = HybridEcies.seal(body, sender, context)

            // Only r1's wrap is present (2 wraps instead of the required 3) - hand-built via the
            // raw encodeSignedBody overload, which writes wraps with no consistency check.
            val truncatedWraps = listOf(sealed.wraps[0], sealed.wraps[2]) // r1's wrap + sender's self-wrap, skip r2
            val rawBody =
                MessageEnvelopeCodec.encodeSignedBody(
                    sender = sender.publicKey,
                    recipients = listOf(r1.publicKey, r2.publicKey),
                    sentAtEpochSecond = 1_000,
                    encryption = EncryptionMode.HYBRID_ECIES,
                    contentCid = sealed.contentCid,
                    replyTo = null,
                    threadRoot = null,
                    wraps = truncatedWraps,
                )
            val signature =
                sender.sign(
                    java.security.MessageDigest
                        .getInstance("SHA-256")
                        .digest(rawBody),
                )
            val truncatedEnvelopeBytes = rawBody + signature

            val exception =
                shouldThrow<MalformedMessageEnvelopeException> { MessageEnvelopeCodec.decode(truncatedEnvelopeBytes) }
            exception.message?.contains("wrap count") shouldBe true
            exception.message?.contains("truncated") shouldBe false

            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("recipient-truncation"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val frame = MailFrameCodec.encode(truncatedEnvelopeBytes, sealed.sealedBodyBytes)
                val index = InboxIndex()

                InboxGossip.onGossipMessage(frame, from, storage, index, r1.publicKey) shouldBe ValidationResult.Invalid
            } finally {
                node.stop()
            }
        }

        test(
            "(f2) the constructor enforces the same wrap-count invariant - cannot be bypassed via fromDecoded either",
        ) {
            val sender = Secp256k1KeyPair.generate()
            val r1 = Secp256k1KeyPair.generate()
            val r2 = Secp256k1KeyPair.generate()
            val body = MessageBody(subject = "s", body = "b")
            val context = MailAadContext.forNewMessage(sender.publicKey, listOf(r1.publicKey, r2.publicKey), 1_000)
            val sealed = HybridEcies.seal(body, sender, context)
            val onlyR1Wrap = listOf(sealed.wraps[0])

            shouldThrow<IllegalArgumentException> {
                MessageEnvelope.fromDecoded(
                    sender = sender.publicKey,
                    recipients = listOf(r1.publicKey, r2.publicKey),
                    sentAtEpochSecond = 1_000,
                    encryption = EncryptionMode.HYBRID_ECIES,
                    contentCid = sealed.contentCid,
                    replyTo = null,
                    threadRoot = null,
                    signature = ByteArray(64),
                    wraps = onlyR1Wrap,
                )
            }
        }

        test("(f3) a missing wrap at a valid recipient's slot fails cleanly - never IndexOutOfBoundsException") {
            val sender = Secp256k1KeyPair.generate()
            val r1 = Secp256k1KeyPair.generate()
            val r2 = Secp256k1KeyPair.generate()
            val body = MessageBody(subject = "s", body = "b")
            val context = MailAadContext.forNewMessage(sender.publicKey, listOf(r1.publicKey, r2.publicKey), 1_000)
            val sealed = HybridEcies.seal(body, sender, context)

            // r2 is a legitimate recipient (slotIndex 1) but the wrap list passed to
            // openWithContext only has 1 entry - r2 must not be able to fabricate access, and this
            // must fail as MailDecryptionException, not crash.
            val onlyR1Wrap = listOf(sealed.wraps[0])

            val exception =
                shouldThrow<MailDecryptionException> {
                    HybridEcies.openWithContext(context, sealed.contentCid, onlyR1Wrap, sealed.sealedBody, r2)
                }
            exception.message?.contains("no wrap") shouldBe true
        }

        test("(g1) an oversized declared recipientCount is rejected before allocation") {
            val sender = Secp256k1KeyPair.generate()
            val out = ByteArrayOutputStream()
            DataOutputStream(out).apply {
                write("LNME".toByteArray(Charsets.US_ASCII))
                writeByte(1)
                writeByte(0)
                write(sender.publicKey.bytes)
                writeShort(1000)
            }

            val exception =
                shouldThrow<MalformedMessageEnvelopeException> { MessageEnvelopeCodec.decode(out.toByteArray()) }
            exception.message?.contains("too many recipients") shouldBe true
            exception.message?.contains("truncated") shouldBe false
        }

        test(
            "(g2) an oversized declared wrapCount (1000) on a legal 1-recipient envelope is rejected before allocation",
        ) {
            val sender = Secp256k1KeyPair.generate()
            val recipient = Secp256k1KeyPair.generate().publicKey
            val out = ByteArrayOutputStream()
            DataOutputStream(out).apply {
                write("LNME".toByteArray(Charsets.US_ASCII))
                writeByte(1)
                writeByte(0)
                write(sender.publicKey.bytes)
                writeShort(1)
                write(recipient.bytes)
                writeLong(1_000L)
                writeByte(EncryptionMode.HYBRID_ECIES.wireValue.toInt())
                val cidBytes = testCidBytes()
                writeShort(cidBytes.size)
                write(cidBytes)
                writeShort(1000) // wrapCount, wildly larger than any wrap data that follows
            }

            val exception =
                shouldThrow<MalformedMessageEnvelopeException> { MessageEnvelopeCodec.decode(out.toByteArray()) }
            exception.message?.contains("wrap count") shouldBe true
            exception.message?.contains("truncated") shouldBe false
        }

        test("(g3) wrapCount == 0 and wrapCount == 65535 are both rejected") {
            val sender = Secp256k1KeyPair.generate()
            val recipient = Secp256k1KeyPair.generate().publicKey

            fun buildWithWrapCount(wrapCount: Int): ByteArray {
                val out = ByteArrayOutputStream()
                DataOutputStream(out).apply {
                    write("LNME".toByteArray(Charsets.US_ASCII))
                    writeByte(1)
                    writeByte(0)
                    write(sender.publicKey.bytes)
                    writeShort(1)
                    write(recipient.bytes)
                    writeLong(1_000L)
                    writeByte(EncryptionMode.HYBRID_ECIES.wireValue.toInt())
                    val cidBytes = testCidBytes()
                    writeShort(cidBytes.size)
                    write(cidBytes)
                    writeShort(wrapCount)
                }
                return out.toByteArray()
            }

            shouldThrow<MalformedMessageEnvelopeException> { MessageEnvelopeCodec.decode(buildWithWrapCount(0)) }
            shouldThrow<MalformedMessageEnvelopeException> { MessageEnvelopeCodec.decode(buildWithWrapCount(65535)) }
        }

        test("(h) freshness: two seal() calls over identical (body, context, sender) never reuse bytes") {
            val sender = Secp256k1KeyPair.generate()
            val recipients = (1..3).map { Secp256k1KeyPair.generate() }
            val body = MessageBody(subject = "s", body = "b")
            val context = MailAadContext.forNewMessage(sender.publicKey, recipients.map { it.publicKey }, 1_000)

            repeat(8) {
                val sealedA = HybridEcies.seal(body, sender, context)
                val sealedB = HybridEcies.seal(body, sender, context)

                sealedA.sealedBody.ciphertext shouldNotBe sealedB.sealedBody.ciphertext
                sealedA.sealedBody.nonce shouldNotBe sealedB.sealedBody.nonce
                sealedA.wraps[0].ephemeralPublicKey shouldNotBe sealedB.wraps[0].ephemeralPublicKey
                sealedA.wraps[0].wrappedKey shouldNotBe sealedB.wraps[0].wrappedKey

                // Within a SINGLE seal, every wrap has a distinct wrappedKey - the shared ephemeral
                // key with per-slot HKDF contexts must not collapse to identical wrap keys.
                val wrappedKeysA = sealedA.wraps.map { it.wrappedKey.toList() }
                wrappedKeysA.toSet().size shouldBe wrappedKeysA.size

                recipients.forEach { recipient ->
                    HybridEcies.open(envelopeFor(sender, recipients, sealedA), sealedA.sealedBody, recipient) shouldBe
                        body
                }
                recipients.forEach { recipient ->
                    HybridEcies.open(envelopeFor(sender, recipients, sealedB), sealedB.sealedBody, recipient) shouldBe
                        body
                }
            }
        }

        test(
            "(i) HOSTILE SENDER FORGERY: a self-authored wrap/body pair that authenticates cleanly but decodes " +
                "to garbage throws MalformedMessageBodyException UNCHANGED - never MailDecryptionException, " +
                "never any other type. Security-audit follow-up (V0.9.2 hardening item 1): reimplements " +
                "seal()'s ECDH/HKDF/AES-GCM steps entirely OUTSIDE HybridEcies, exactly as this class's and " +
                "MailAadContext's own doc comments say an attacker can - zero secret material beyond what any " +
                "real sender legitimately owns (their own signing key + the victim's PUBLIC key).",
        ) {
            val attacker = Secp256k1KeyPair.generate() // signs with THEIR OWN key - envelope verifies genuinely
            val victim = Secp256k1KeyPair.generate()
            val context = MailAadContext.forNewMessage(attacker.publicKey, listOf(victim.publicKey), 9_000)

            // 1. Forge the body: an attacker-chosen content key encrypts an arbitrary plaintext that is
            // NOT a valid MessageBodyCodec encoding.
            val contentKey = ByteArray(CONTENT_KEY_SIZE).also(SecureRandom()::nextBytes)
            val garbagePlaintext = "not a MessageBody at all".toByteArray(Charsets.UTF_8)
            val bodyNonce = ByteArray(GCM_NONCE_SIZE).also(SecureRandom()::nextBytes)
            val bodyCipher = Cipher.getInstance("AES/GCM/NoPadding")
            bodyCipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(contentKey, "AES"), GCMParameterSpec(128, bodyNonce))
            bodyCipher.updateAAD(context.aadForBody())
            val garbageCiphertext = bodyCipher.doFinal(garbagePlaintext)
            val garbageSealedBody = SealedBody(bodyNonce, garbageCiphertext)
            val contentCid = MessageBodyCodec.cidFor(SealedBodyCodec.encode(garbageSealedBody))

            // 2. Forge both wraps (victim's slot 0, attacker's own self-wrap slot 1) with one ephemeral
            // keypair, mirroring HybridEcies.seal's private deriveWrapKeyAndNonce construction exactly:
            // HKDF-SHA256(ecdh-shared-secret, salt=ephemeralPublicKey.bytes, info=LABEL||aad, L=44).
            val ephemeral = Secp256k1KeyPair.generate()

            fun forgeWrap(
                slotIndex: Int,
                slotPublicKey: Secp256k1PublicKey,
            ): EciesWrap {
                val shared = ecdhSharedSecret(ephemeral.privateKey, slotPublicKey)
                val aad = context.aadForWrap(slotIndex, slotPublicKey, ephemeral.publicKey, contentCid)
                val info = "LapisNet:mail-hybrid-ecies:v1:wrap-key".toByteArray(Charsets.US_ASCII) + aad
                val generator = HKDFBytesGenerator(SHA256Digest())
                generator.init(HKDFParameters(shared, ephemeral.publicKey.bytes, info))
                val okm = ByteArray(CONTENT_KEY_SIZE + GCM_NONCE_SIZE)
                generator.generateBytes(okm, 0, okm.size)
                val wrapKey = okm.copyOfRange(0, CONTENT_KEY_SIZE)
                val wrapNonce = okm.copyOfRange(CONTENT_KEY_SIZE, okm.size)
                val wrapCipher = Cipher.getInstance("AES/GCM/NoPadding")
                wrapCipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(wrapKey, "AES"), GCMParameterSpec(128, wrapNonce))
                wrapCipher.updateAAD(aad)
                val wrappedKey = wrapCipher.doFinal(contentKey)
                return EciesWrap(ephemeral.publicKey, wrappedKey)
            }
            val wrapForVictim = forgeWrap(0, victim.publicKey)
            val wrapForSelf = forgeWrap(1, attacker.publicKey)

            val envelope =
                MessageEnvelope.create(
                    sender = attacker,
                    recipients = listOf(victim.publicKey),
                    contentCid = contentCid,
                    sentAtEpochSecond = 9_000,
                    encryption = EncryptionMode.HYBRID_ECIES,
                    wraps = listOf(wrapForVictim, wrapForSelf),
                )

            // 3. The forged envelope is genuinely, cryptographically valid - the signature check alone
            // cannot catch this.
            MessageEnvelope.verify(envelope) shouldBe true

            // 4. LOAD-BEARING PROOF: open() still funnels the failure into exactly one type, and it is
            // NOT MailDecryptionException.
            val exception =
                shouldThrow<MalformedMessageBodyException> {
                    HybridEcies.open(envelope, garbageSealedBody, victim)
                }
            exception.message?.contains("bad magic") shouldBe true
        }
    })

private fun testCidBytes(): ByteArray {
    val cid =
        io.ipfs.cid.Cid.buildCidV1(
            io.ipfs.cid.Cid.Codec.Raw,
            io.ipfs.multihash.Multihash.Type.sha2_256,
            ByteArray(32) { 7 },
        )
    return cid.toBytes()
}

private fun envelopeFor(
    sender: Secp256k1KeyPair,
    recipients: List<Secp256k1KeyPair>,
    sealed: SealedMessage,
): MessageEnvelope =
    MessageEnvelope.create(
        sender = sender,
        recipients = recipients.map { it.publicKey },
        contentCid = sealed.contentCid,
        sentAtEpochSecond = 1_000,
        encryption = EncryptionMode.HYBRID_ECIES,
        wraps = sealed.wraps,
    )
