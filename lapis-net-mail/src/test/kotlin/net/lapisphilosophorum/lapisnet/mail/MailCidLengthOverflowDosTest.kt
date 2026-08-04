package net.lapisphilosophorum.lapisnet.mail

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.longs.shouldBeLessThan
import io.kotest.matchers.shouldBe
import io.libp2p.core.pubsub.ValidationResult
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.networking.deriveLibp2pPeerId
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.file.Files

/**
 * A wall-clock ceiling well above anything [CidBytesValidation.isSafeToCast]'s rejection should
 * ever need (a plain, allocation-free varint parse over an 8-byte candidate - microseconds), but
 * far below what an unbounded `new byte[0x7FFFFFFF]` allocation attempt costs on any JVM, whether
 * it fails fast with `OutOfMemoryError` or stalls the allocator/GC first trying to satisfy it.
 * Generous on purpose: this is a regression guard against the oversized allocation being attempted
 * at all, not a tight performance benchmark.
 */
private const val MAX_ALLOWED_MILLIS = 5_000L

private fun testCid(seed: Byte): Cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { seed })

private fun elapsedMillis(block: () -> Unit): Long {
    val start = System.nanoTime()
    block()
    return (System.nanoTime() - start) / 1_000_000
}

/** Writes an unsigned LEB128 varint exactly as `io.ipfs.multihash.Multihash.putUvarint`/
 * `readVarint` define it - the same format a candidate CID's leading fields (version, codec,
 * multihash type, multihash length) are encoded in before `io.ipfs.cid.Cid.cast` ever sees them. */
private fun writeVarint(
    out: ByteArrayOutputStream,
    value: Long,
) {
    var x = value
    while (x < 0 || x >= 0x80) {
        out.write(((x and 0x7f) or 0x80).toInt())
        x = x ushr 7
    }
    out.write(x.toInt())
}

/**
 * Hand-builds a candidate CID byte array - `version(varint) | codec(varint) | multihash-
 * type(varint) | multihash-length(varint)` - that declares [declaredMultihashLength] but supplies
 * NO actual hash bytes after it. This is exactly the security audit's reproduction shape: CID
 * version 1, codec Raw (`0x55`), multihash type sha2_256 (`0x12`), then a declared length wildly
 * larger than anything that could possibly follow. For both malicious lengths this test exercises
 * (`0x7FFFFFFF` and `1_073_741_824`), the header alone comes to exactly 8 bytes - matching the
 * audit's "8-byte malicious CID payload" finding precisely.
 */
private fun maliciousCidBytes(declaredMultihashLength: Long): ByteArray {
    val sha2256TypeIndex = Multihash.Type.sha2_256.index
    val out = ByteArrayOutputStream()
    writeVarint(out, 1) // CID version 1
    writeVarint(out, Cid.Codec.Raw.type) // codec
    writeVarint(out, sha2256TypeIndex.toLong()) // multihash type
    writeVarint(out, declaredMultihashLength) // multihash length - the attack payload
    return out.toByteArray()
}

private fun envelopeBytesWithContentCid(
    sender: Secp256k1KeyPair,
    recipient: Secp256k1PublicKey,
    contentCidBytes: ByteArray,
): ByteArray {
    val out = ByteArrayOutputStream()
    DataOutputStream(out).apply {
        write("LNME".toByteArray(Charsets.US_ASCII))
        writeByte(1)
        writeByte(0) // flags: no replyTo, no threadRoot
        write(sender.publicKey.bytes)
        writeShort(1)
        write(recipient.bytes)
        writeLong(1000L)
        writeByte(0) // encryption = NONE
        writeShort(contentCidBytes.size)
        write(contentCidBytes)
        // No replyTo/threadRoot/signature needed - decode() must throw while parsing contentCid,
        // well before it would ever reach them.
    }
    return out.toByteArray()
}

private fun envelopeBytesWithReplyTo(
    sender: Secp256k1KeyPair,
    recipient: Secp256k1PublicKey,
    replyToBytes: ByteArray,
): ByteArray {
    val contentCidBytes = testCid(1).toBytes()
    val out = ByteArrayOutputStream()
    DataOutputStream(out).apply {
        write("LNME".toByteArray(Charsets.US_ASCII))
        writeByte(1)
        writeByte(0x01) // flags: FLAG_HAS_REPLY_TO
        write(sender.publicKey.bytes)
        writeShort(1)
        write(recipient.bytes)
        writeLong(1000L)
        writeByte(0) // encryption = NONE
        writeShort(contentCidBytes.size)
        write(contentCidBytes)
        writeShort(replyToBytes.size)
        write(replyToBytes)
    }
    return out.toByteArray()
}

private fun envelopeBytesWithThreadRoot(
    sender: Secp256k1KeyPair,
    recipient: Secp256k1PublicKey,
    threadRootBytes: ByteArray,
): ByteArray {
    val contentCidBytes = testCid(1).toBytes()
    val out = ByteArrayOutputStream()
    DataOutputStream(out).apply {
        write("LNME".toByteArray(Charsets.US_ASCII))
        writeByte(1)
        writeByte(0x02) // flags: FLAG_HAS_THREAD_ROOT
        write(sender.publicKey.bytes)
        writeShort(1)
        write(recipient.bytes)
        writeLong(1000L)
        writeByte(0) // encryption = NONE
        writeShort(contentCidBytes.size)
        write(contentCidBytes)
        writeShort(threadRootBytes.size)
        write(threadRootBytes)
    }
    return out.toByteArray()
}

private fun bodyBytesWithAttachmentCid(attachmentCidBytes: ByteArray): ByteArray {
    val subjectBytes = "s".toByteArray(Charsets.UTF_8)
    val bodyBytes = "b".toByteArray(Charsets.UTF_8)
    val nameBytes = "f".toByteArray(Charsets.UTF_8)
    val mimeBytes = "text/plain".toByteArray(Charsets.UTF_8)
    val out = ByteArrayOutputStream()
    DataOutputStream(out).apply {
        write("LNMB".toByteArray(Charsets.US_ASCII))
        writeByte(1)
        writeByte(0)
        writeShort(subjectBytes.size)
        write(subjectBytes)
        writeShort(bodyBytes.size)
        write(bodyBytes)
        writeShort(1) // attachmentCount
        writeShort(attachmentCidBytes.size)
        write(attachmentCidBytes)
        writeShort(nameBytes.size)
        write(nameBytes)
        writeShort(mimeBytes.size)
        write(mimeBytes)
        writeLong(1L) // size
        writeShort(0) // headerCount
    }
    return out.toByteArray()
}

/**
 * Regression test for a CRITICAL, auditor-confirmed remote DoS in `lapis-net-mail`'s V0.9.1 codecs
 * (not yet merged to `master` when found). A CID field capped to
 * [MessageEnvelopeCodec.MAX_CID_BYTES]/[MessageBodyCodec.MAX_CID_BYTES] (128 bytes) at the wire-
 * field level could still carry a multihash length varint declaring an arbitrarily large value
 * (e.g. `0x7FFFFFFF`), which `io.ipfs.multihash.Multihash.deserialize` allocated via `new
 * byte[declaredLength]` BEFORE its own constructor's 127-byte bound check ever ran. That surfaced
 * as an uncaught `OutOfMemoryError` escaping [MessageEnvelopeCodec.decode]/[MessageBodyCodec
 * .decode] (neither one's catch blocks covered `Error`) and, from there, [InboxGossip
 * .onGossipMessage] itself (whose only catch clauses are the module's own `Malformed*Exception`
 * types) - reachable BEFORE signature verification and BEFORE the addressing check, so no valid
 * signature or correct addressing was required, just the ability to publish on a public-key-
 * derived inbox topic. Fixed by [CidBytesValidation.isSafeToCast], run at all four CID decode call
 * sites ([MessageEnvelopeCodec]'s `contentCid`/`replyTo`/`threadRoot`, [MessageBodyCodec]'s
 * per-attachment CID) before `io.ipfs.cid.Cid.cast(...)` is ever invoked, plus a defense-in-depth
 * `OutOfMemoryError` catch in both codecs' `decode()`.
 */
class MailCidLengthOverflowDosTest :
    FunSpec({
        val maliciousLengths = listOf(0x7FFFFFFFL, 1_073_741_824L)

        // Deterministic, allocation-free, timing-independent proof that the guard itself rejects
        // exactly these byte patterns - stronger than the wall-clock-bound tests below, which can
        // only observe the guard's EFFECT (decode() throwing quickly) rather than the guard's
        // decision directly. Kept alongside the wall-clock tests, not instead of them, because the
        // wall-clock tests are what actually pin that every call site invokes the guard at all.
        test("CidBytesValidation.isSafeToCast rejects both malicious declared multihash lengths") {
            maliciousLengths.forEach { declaredLength ->
                CidBytesValidation.isSafeToCast(maliciousCidBytes(declaredLength)) shouldBe false
            }
        }

        test("CidBytesValidation.isSafeToCast accepts a genuine CIDv1 sha2-256 byte encoding") {
            CidBytesValidation.isSafeToCast(testCid(1).toBytes()) shouldBe true
        }

        maliciousLengths.forEach { declaredLength ->
            test("MessageEnvelopeCodec.decode rejects a contentCid declaring multihash length $declaredLength") {
                val sender = Secp256k1KeyPair.generate()
                val recipient = Secp256k1KeyPair.generate().publicKey
                val bytes = envelopeBytesWithContentCid(sender, recipient, maliciousCidBytes(declaredLength))

                val elapsed =
                    elapsedMillis {
                        shouldThrow<MalformedMessageEnvelopeException> { MessageEnvelopeCodec.decode(bytes) }
                    }
                elapsed shouldBeLessThan MAX_ALLOWED_MILLIS
            }

            test("MessageEnvelopeCodec.decode rejects a replyTo declaring multihash length $declaredLength") {
                val sender = Secp256k1KeyPair.generate()
                val recipient = Secp256k1KeyPair.generate().publicKey
                val bytes = envelopeBytesWithReplyTo(sender, recipient, maliciousCidBytes(declaredLength))

                val elapsed =
                    elapsedMillis {
                        shouldThrow<MalformedMessageEnvelopeException> { MessageEnvelopeCodec.decode(bytes) }
                    }
                elapsed shouldBeLessThan MAX_ALLOWED_MILLIS
            }

            test("MessageEnvelopeCodec.decode rejects a threadRoot declaring multihash length $declaredLength") {
                val sender = Secp256k1KeyPair.generate()
                val recipient = Secp256k1KeyPair.generate().publicKey
                val bytes = envelopeBytesWithThreadRoot(sender, recipient, maliciousCidBytes(declaredLength))

                val elapsed =
                    elapsedMillis {
                        shouldThrow<MalformedMessageEnvelopeException> { MessageEnvelopeCodec.decode(bytes) }
                    }
                elapsed shouldBeLessThan MAX_ALLOWED_MILLIS
            }

            test("MessageBodyCodec.decode rejects an attachment cid declaring multihash length $declaredLength") {
                val bytes = bodyBytesWithAttachmentCid(maliciousCidBytes(declaredLength))

                val elapsed =
                    elapsedMillis {
                        shouldThrow<MalformedMessageBodyException> { MessageBodyCodec.decode(bytes) }
                    }
                elapsed shouldBeLessThan MAX_ALLOWED_MILLIS
            }
        }

        test(
            "end-to-end: InboxGossip.onGossipMessage rejects a gossip frame with a length-overflow " +
                "contentCid as Invalid, never crashes, never persists",
        ) {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("mail-cid-overflow-dos"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val localIdentity = identity.secp256k1KeyPair.publicKey
                val sender = Secp256k1KeyPair.generate()

                val envelopeBytes = envelopeBytesWithContentCid(sender, localIdentity, maliciousCidBytes(0x7FFFFFFFL))
                val frameBytes = MailFrameCodec.encode(envelopeBytes, ByteArray(0))
                val index = InboxIndex()

                val elapsed =
                    elapsedMillis {
                        val result = InboxGossip.onGossipMessage(frameBytes, from, storage, index, localIdentity)
                        result shouldBe ValidationResult.Invalid
                    }
                elapsed shouldBeLessThan MAX_ALLOWED_MILLIS
                index.latest() shouldBe emptyList()
            } finally {
                node.stop()
            }
        }
    })
