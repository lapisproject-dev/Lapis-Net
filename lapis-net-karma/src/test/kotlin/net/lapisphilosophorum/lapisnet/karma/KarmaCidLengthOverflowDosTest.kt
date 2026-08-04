package net.lapisphilosophorum.lapisnet.karma

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
 * Hand-builds a `KarmaVote` wire encoding (`KarmaVoteCodec`'s layout - see its class doc comment)
 * carrying [cidBytes] as its `targetCid` field. No `timestampSeconds`/`anchorType`/`anchorBytes`/
 * `nonce`/signature - `decode()` must throw while parsing `targetCid`, well before it would ever
 * reach them.
 */
private fun voteBytesWithCid(
    voter: Secp256k1PublicKey,
    cidBytes: ByteArray,
): ByteArray {
    val out = ByteArrayOutputStream()
    DataOutputStream(out).apply {
        write("LNKV".toByteArray(Charsets.US_ASCII))
        writeByte(1) // version
        write(voter.bytes)
        writeShort(cidBytes.size)
        write(cidBytes)
    }
    return out.toByteArray()
}

/**
 * Regression test for the same CRITICAL OOM-DoS construct `MailCidLengthOverflowDosTest` covers for
 * `lapis-net-mail`, found (2026-08-04, post-V0.9.4) to also affect `KarmaVoteCodec`'s `targetCid`
 * field decode (unfixed since V0.3). Fixed by running the same, now-shared
 * `CidBytesValidation.isSafeToCast` (relocated from `lapis-net-mail` to `lapis-net-core`) before
 * `Cid.cast(...)`, plus a defense-in-depth `OutOfMemoryError` catch in `KarmaVoteCodec.decode()`.
 */
class KarmaCidLengthOverflowDosTest :
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
            test("KarmaVoteCodec.decode rejects a targetCid declaring multihash length $declaredLength") {
                val voter = Secp256k1KeyPair.generate().publicKey
                val bytes = voteBytesWithCid(voter, maliciousCidBytes(declaredLength))

                val elapsed =
                    elapsedMillis {
                        shouldThrow<MalformedKarmaVoteException> { KarmaVoteCodec.decode(bytes) }
                    }
                elapsed shouldBeLessThan MAX_ALLOWED_MILLIS
            }
        }

        test(
            "end-to-end: KarmaGossip.onGossipMessage rejects a gossip frame with a length-overflow " +
                "targetCid as Invalid, never crashes, never persists",
        ) {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("karma-cid-overflow-dos"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val voter = identity.secp256k1KeyPair.publicKey

                val bytes = voteBytesWithCid(voter, maliciousCidBytes(0x7FFFFFFFL))
                val index = KarmaVoteIndex()

                val elapsed =
                    elapsedMillis {
                        val result = KarmaGossip.onGossipMessage(bytes, from, storage, index)
                        result shouldBe ValidationResult.Invalid
                    }
                elapsed shouldBeLessThan MAX_ALLOWED_MILLIS
                index.allTargets() shouldBe emptySet()

                val otherNode = LapisNode.create(DualKeyIdentity.generate())
                otherNode.start(bootstrapPeers = emptyList())
                val mintedCid =
                    try {
                        NabuStorage.attach(otherNode, Files.createTempDirectory("karma-cid-overflow-mint")).put(bytes)
                    } finally {
                        otherNode.stop()
                    }
                storage.get(mintedCid).shouldBeNull()
            } finally {
                node.stop()
            }
        }
    })
