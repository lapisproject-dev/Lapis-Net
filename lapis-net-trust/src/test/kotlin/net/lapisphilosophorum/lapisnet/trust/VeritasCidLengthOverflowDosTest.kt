package net.lapisphilosophorum.lapisnet.trust

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

/** See `MailCidLengthOverflowDosTest`'s identical constant for the reasoning. */
private const val MAX_ALLOWED_MILLIS = 5_000L

private fun testCid(seed: Byte): Cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { seed })

private fun elapsedMillis(block: () -> Unit): Long {
    val start = System.nanoTime()
    block()
    return (System.nanoTime() - start) / 1_000_000
}

/** Mirrors `MailCidLengthOverflowDosTest.writeVarint` exactly - see that function's doc comment. */
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

/** Mirrors `MailCidLengthOverflowDosTest.maliciousCidBytes` exactly - see that function's doc comment. */
private fun maliciousCidBytes(declaredMultihashLength: Long): ByteArray {
    val sha2256TypeIndex = Multihash.Type.sha2_256.index
    val out = ByteArrayOutputStream()
    writeVarint(out, 1) // CID version 1
    writeVarint(out, Cid.Codec.Raw.type) // codec
    writeVarint(out, sha2256TypeIndex.toLong()) // multihash type
    writeVarint(out, declaredMultihashLength) // multihash length - the attack payload
    return out.toByteArray()
}

/**
 * Hand-builds a `VeritasGrant` wire encoding (`VeritasGrantCodec`'s layout - see its class doc
 * comment) carrying [occasionCidBytes] as its sole occasion reference. No `previousGrantId`, no
 * comment, no signature - `decode()` must throw while parsing the occasion-reference CID, well
 * before it would ever reach them.
 */
private fun grantBytesWithOccasionCid(
    truster: Secp256k1PublicKey,
    target: Secp256k1PublicKey,
    occasionCidBytes: ByteArray,
): ByteArray {
    val out = ByteArrayOutputStream()
    DataOutputStream(out).apply {
        write("LNVG".toByteArray(Charsets.US_ASCII))
        writeByte(1) // version
        writeByte(0) // flags: no previous grant
        write(truster.bytes)
        write(target.bytes)
        writeInt(500_000) // trustMicros, within MIN_TRUST_MICROS..MAX_TRUST_MICROS
        writeShort(0) // commentLen
        writeShort(1) // occasionCount
        writeShort(occasionCidBytes.size)
        write(occasionCidBytes)
    }
    return out.toByteArray()
}

/**
 * Regression test for the same CRITICAL OOM-DoS construct `MailCidLengthOverflowDosTest` covers for
 * `lapis-net-mail`, found (2026-08-04, post-V0.9.4) to also affect `VeritasGrantCodec`'s
 * occasion-reference CID decode (unfixed since V0.1.5). Fixed by running the same, now-shared
 * `CidBytesValidation.isSafeToCast` (relocated from `lapis-net-mail` to `lapis-net-core`) before
 * `Cid.cast(...)`, plus a defense-in-depth `OutOfMemoryError` catch in `VeritasGrantCodec.decode()`.
 */
class VeritasCidLengthOverflowDosTest :
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
            test(
                "VeritasGrantCodec.decode rejects an occasion-reference CID declaring multihash length $declaredLength",
            ) {
                val truster = Secp256k1KeyPair.generate().publicKey
                val target = Secp256k1KeyPair.generate().publicKey
                val bytes = grantBytesWithOccasionCid(truster, target, maliciousCidBytes(declaredLength))

                val elapsed =
                    elapsedMillis {
                        shouldThrow<MalformedVeritasGrantException> { VeritasGrantCodec.decode(bytes) }
                    }
                elapsed shouldBeLessThan MAX_ALLOWED_MILLIS
            }
        }

        test(
            "end-to-end: VeritasGossip.onGossipMessage rejects a gossip frame with a length-overflow " +
                "occasion-reference CID as Invalid, never crashes, never persists",
        ) {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("veritas-cid-overflow-dos"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val truster = identity.secp256k1KeyPair.publicKey
                val target = Secp256k1KeyPair.generate().publicKey

                val bytes = grantBytesWithOccasionCid(truster, target, maliciousCidBytes(0x7FFFFFFFL))
                val index = VeritasGrantIndex()

                val elapsed =
                    elapsedMillis {
                        val result = VeritasGossip.onGossipMessage(bytes, from, storage, index)
                        result shouldBe ValidationResult.Invalid
                    }
                elapsed shouldBeLessThan MAX_ALLOWED_MILLIS
                index.allPairs() shouldBe emptySet()

                // Prove the malicious frame was never persisted: mint the CID for these exact
                // bytes on a separate, never-connected node's own blockstore, then confirm the
                // node-under-test's storage has no local copy - mirrors
                // VeritasGossipOnGossipMessageTest's own "mint CIDs on a separate node" technique.
                val otherNode = LapisNode.create(DualKeyIdentity.generate())
                otherNode.start(bootstrapPeers = emptyList())
                val mintedCid =
                    try {
                        NabuStorage.attach(otherNode, Files.createTempDirectory("veritas-cid-overflow-mint")).put(bytes)
                    } finally {
                        otherNode.stop()
                    }
                storage.get(mintedCid).shouldBeNull()
            } finally {
                node.stop()
            }
        }
    })
