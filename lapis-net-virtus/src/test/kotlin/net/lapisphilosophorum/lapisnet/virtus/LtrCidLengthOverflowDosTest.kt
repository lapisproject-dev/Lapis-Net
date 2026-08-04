package net.lapisphilosophorum.lapisnet.virtus

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.longs.shouldBeLessThan
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.libp2p.core.pubsub.ValidationResult
import net.lapisphilosophorum.lapisnet.core.cid.CidBytesValidation
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.networking.deriveLibp2pPeerId
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.file.Files

private const val MAX_ALLOWED_MILLIS = 5_000L

private fun testCid(seed: Byte): Cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { seed })

private fun elapsedMillis(block: () -> Unit): Long {
    val start = System.nanoTime()
    block()
    return (System.nanoTime() - start) / 1_000_000
}

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

private fun maliciousCidBytes(declaredMultihashLength: Long): ByteArray {
    val sha2256TypeIndex = Multihash.Type.sha2_256.index
    val out = ByteArrayOutputStream()
    writeVarint(out, 1)
    writeVarint(out, Cid.Codec.Raw.type)
    writeVarint(out, sha2256TypeIndex.toLong())
    writeVarint(out, declaredMultihashLength)
    return out.toByteArray()
}

/**
 * Hand-builds an `LtrRecord` wire encoding (`LtrRecordCodec`'s layout - see its class doc comment)
 * carrying [cidBytes] as its `cid` field. No `initialValueMsat`/`timestampSeconds`/`nonce`/
 * `proof`/signature - `decode()` must throw while parsing `cid`, well before it would ever reach
 * them.
 */
private fun recordBytesWithCid(
    payer: Secp256k1PublicKey,
    viewId: Secp256k1PublicKey,
    cidBytes: ByteArray,
): ByteArray {
    val out = ByteArrayOutputStream()
    DataOutputStream(out).apply {
        write("LNLR".toByteArray(Charsets.US_ASCII))
        writeByte(1) // version
        write(payer.bytes)
        write(viewId.bytes)
        writeShort(cidBytes.size)
        write(cidBytes)
    }
    return out.toByteArray()
}

/**
 * Regression test for the same CRITICAL OOM-DoS construct `MailCidLengthOverflowDosTest` covers for
 * `lapis-net-mail`, found (2026-08-04, post-V0.9.4) to also affect `LtrRecordCodec`'s `cid` field
 * decode (unfixed since V0.2.1). Fixed by running the same, now-shared
 * `CidBytesValidation.isSafeToCast` (relocated from `lapis-net-mail` to `lapis-net-core`) before
 * `Cid.cast(...)`, plus a defense-in-depth `OutOfMemoryError` catch in `LtrRecordCodec.decode()`.
 */
class LtrCidLengthOverflowDosTest :
    FunSpec({
        val maliciousLengths = listOf(0x7FFFFFFFL, 1_073_741_824L)

        test("CidBytesValidation.isSafeToCast rejects both malicious declared multihash lengths") {
            maliciousLengths.forEach { declaredLength ->
                CidBytesValidation.isSafeToCast(maliciousCidBytes(declaredLength)) shouldBe false
            }
        }

        test("CidBytesValidation.isSafeToCast accepts a genuine CIDv1 sha2-256 byte encoding") {
            CidBytesValidation.isSafeToCast(testCid(1).toBytes()) shouldBe true
        }

        maliciousLengths.forEach { declaredLength ->
            test("LtrRecordCodec.decode rejects a cid declaring multihash length $declaredLength") {
                val payer = Secp256k1KeyPair.generate().publicKey
                val viewId = Secp256k1KeyPair.generate().publicKey
                val bytes = recordBytesWithCid(payer, viewId, maliciousCidBytes(declaredLength))

                val elapsed =
                    elapsedMillis {
                        shouldThrow<MalformedLtrRecordException> { LtrRecordCodec.decode(bytes) }
                    }
                elapsed shouldBeLessThan MAX_ALLOWED_MILLIS
            }
        }

        test(
            "end-to-end: LtrGossip.onGossipMessage rejects a gossip frame with a length-overflow " +
                "cid as Invalid, never crashes, never persists",
        ) {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("ltr-cid-overflow-dos"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val payer = identity.secp256k1KeyPair.publicKey
                val viewId = Secp256k1KeyPair.generate().publicKey

                val bytes = recordBytesWithCid(payer, viewId, maliciousCidBytes(0x7FFFFFFFL))
                val index = LtrRecordIndex()

                val elapsed =
                    elapsedMillis {
                        val result = LtrGossip.onGossipMessage(bytes, from, storage, index)
                        result shouldBe ValidationResult.Invalid
                    }
                elapsed shouldBeLessThan MAX_ALLOWED_MILLIS
                index.allPairs() shouldBe emptySet()

                val otherNode = LapisNode.create(DualKeyIdentity.generate())
                otherNode.start(bootstrapPeers = emptyList())
                val mintedCid =
                    try {
                        NabuStorage.attach(otherNode, Files.createTempDirectory("ltr-cid-overflow-mint")).put(bytes)
                    } finally {
                        otherNode.stop()
                    }
                storage.get(mintedCid).shouldBeNull()
            } finally {
                node.stop()
            }
        }
    })
