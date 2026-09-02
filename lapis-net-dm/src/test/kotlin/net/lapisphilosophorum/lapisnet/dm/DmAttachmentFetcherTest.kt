package net.lapisphilosophorum.lapisnet.dm

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.libp2p.core.multiformats.Multiaddr
import net.lapisphilosophorum.lapisnet.directory.PeerCapability
import net.lapisphilosophorum.lapisnet.directory.PeerRecord
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.deriveLibp2pPeerId
import java.time.Instant

/**
 * Branch coverage for [DmAttachmentFetcher.fetch]/[DmAttachmentFetcher.fetchAndDecrypt] - review
 * finding (2026-09): this class shipped with zero tests in the V0.8.6 wave despite being
 * network-touching, untrusted-input-facing code. Most cases below deliberately use the LOCAL
 * blockstore hit path (`storage.getLocal`) so they stay fast and deterministic - only one test
 * ("a real cross-node fetch...") exercises the actual Bitswap wire path, mirroring
 * `TwoNodeBitswapDirectFetchTest`'s established pattern.
 */
class DmAttachmentFetcherTest :
    FunSpec({
        test("fetch: a locally-stored blob is returned without ever consulting the peer directory") {
            val fetcher = buildDmTestNode()
            try {
                val payload = "local hit, no peer directory record needed".toByteArray()
                val cid = fetcher.storage.put(payload)
                val neverAnnouncedSender = DualKeyIdentity.generate().secp256k1KeyPair.publicKey

                val result =
                    DmAttachmentFetcher.fetch(cid, neverAnnouncedSender, fetcher.peerDirectory, fetcher.storage)

                result shouldBe payload
            } finally {
                fetcher.stop()
            }
        }

        test("fetch: no peer directory record for the claimed sender returns null, no network call attempted") {
            val fetcher = buildDmTestNode()
            try {
                val neverStoredCid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { 7 })
                val strangerSender = DualKeyIdentity.generate().secp256k1KeyPair.publicKey

                val result =
                    DmAttachmentFetcher.fetch(neverStoredCid, strangerSender, fetcher.peerDirectory, fetcher.storage)

                result.shouldBeNull()
            } finally {
                fetcher.stop()
            }
        }

        test("fetch: a sender record whose only address is wildcard is refused - no dial attempted") {
            val fetcher = buildDmTestNode()
            try {
                val senderIdentity = DualKeyIdentity.generate()
                val record =
                    PeerRecord.create(
                        identity = senderIdentity,
                        addresses = listOf(Multiaddr("/ip4/0.0.0.0/tcp/4001")),
                        capabilities = setOf(PeerCapability.DM),
                        sequenceNumber = 1,
                        notValidAfterEpochSecond = Instant.now().epochSecond + 3600,
                    )
                fetcher.peerDirectory.announce(record)
                val neverStoredCid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { 8 })

                val result =
                    DmAttachmentFetcher.fetch(
                        neverStoredCid,
                        senderIdentity.secp256k1KeyPair.publicKey,
                        fetcher.peerDirectory,
                        fetcher.storage,
                    )

                result.shouldBeNull()
            } finally {
                fetcher.stop()
            }
        }

        test("fetch: an address already carrying a conflicting /p2p component is skipped, not thrown") {
            val fetcher = buildDmTestNode()
            try {
                val senderIdentity = DualKeyIdentity.generate()
                val unrelatedPeerId = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val record =
                    PeerRecord.create(
                        identity = senderIdentity,
                        addresses = listOf(Multiaddr("/ip4/127.0.0.1/tcp/4001/p2p/$unrelatedPeerId")),
                        capabilities = setOf(PeerCapability.DM),
                        sequenceNumber = 1,
                        notValidAfterEpochSecond = Instant.now().epochSecond + 3600,
                    )
                fetcher.peerDirectory.announce(record)
                val neverStoredCid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { 9 })

                // Every candidate address is skipped (conflicting /p2p component) rather than
                // crashing withP2P's IllegalArgumentException outward - the fetch still completes
                // cleanly, just with nothing left to dial.
                val result =
                    DmAttachmentFetcher.fetch(
                        neverStoredCid,
                        senderIdentity.secp256k1KeyPair.publicKey,
                        fetcher.peerDirectory,
                        fetcher.storage,
                    )

                result.shouldBeNull()
            } finally {
                fetcher.stop()
            }
        }

        test("fetch: an unreachable registered address fails cleanly - returns null, never throws") {
            val fetcher = buildDmTestNode()
            try {
                val senderIdentity = DualKeyIdentity.generate()
                val record =
                    PeerRecord.create(
                        identity = senderIdentity,
                        // Well-formed, non-wildcard, but nothing is actually listening there.
                        addresses = listOf(Multiaddr("/ip4/127.0.0.1/tcp/1")),
                        capabilities = setOf(PeerCapability.DM),
                        sequenceNumber = 1,
                        notValidAfterEpochSecond = Instant.now().epochSecond + 3600,
                    )
                fetcher.peerDirectory.announce(record)
                val neverStoredCid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { 10 })

                val result =
                    DmAttachmentFetcher.fetch(
                        neverStoredCid,
                        senderIdentity.secp256k1KeyPair.publicKey,
                        fetcher.peerDirectory,
                        fetcher.storage,
                    )

                result.shouldBeNull()
            } finally {
                fetcher.stop()
            }
        }

        test("fetchAndDecrypt: a real cross-node Bitswap fetch decrypts to the exact original plaintext") {
            val sender = buildDmTestNode()
            val receiver = buildDmTestNode()
            try {
                connectAndConverge(sender, receiver)

                val plaintext = "the real cross-node attachment payload".repeat(50).toByteArray()
                val encrypted = DmAttachmentCipher.encrypt(plaintext)
                val cid = sender.storage.put(EncryptedDmAttachmentBlobCodec.encode(encrypted.blob))
                val ref =
                    DmAttachmentRef(
                        cid = cid,
                        name = "file.bin",
                        mime = "application/octet-stream",
                        size = plaintext.size.toLong(),
                        encryptionKey = encrypted.key,
                    )

                val result =
                    DmAttachmentFetcher.fetchAndDecrypt(
                        ref,
                        sender.identity.secp256k1KeyPair.publicKey,
                        receiver.peerDirectory,
                        receiver.storage,
                    )

                result shouldBe plaintext
            } finally {
                sender.stop()
                receiver.stop()
            }
        }

        test("fetchAndDecrypt: a ref declaring a size that does not match the decrypted plaintext is rejected") {
            val fetcher = buildDmTestNode()
            try {
                val plaintext = "sixteen bytes!!!".toByteArray()
                val encrypted = DmAttachmentCipher.encrypt(plaintext)
                val cid = fetcher.storage.put(EncryptedDmAttachmentBlobCodec.encode(encrypted.blob))
                val lyingRef =
                    DmAttachmentRef(
                        cid = cid,
                        name = "file.bin",
                        mime = "application/octet-stream",
                        size = 1L, // the real decrypted plaintext is 16 bytes, not 1
                        encryptionKey = encrypted.key,
                    )

                val result =
                    DmAttachmentFetcher.fetchAndDecrypt(
                        lyingRef,
                        DualKeyIdentity.generate().secp256k1KeyPair.publicKey,
                        fetcher.peerDirectory,
                        fetcher.storage,
                    )

                result.shouldBeNull()
            } finally {
                fetcher.stop()
            }
        }

        test("fetchAndDecrypt: a wrong encryption key fails to decrypt and returns null, never throws") {
            val fetcher = buildDmTestNode()
            try {
                val plaintext = "attachment content".toByteArray()
                val encrypted = DmAttachmentCipher.encrypt(plaintext)
                val cid = fetcher.storage.put(EncryptedDmAttachmentBlobCodec.encode(encrypted.blob))
                val wrongKeyRef =
                    DmAttachmentRef(
                        cid = cid,
                        name = "file.bin",
                        mime = "application/octet-stream",
                        size = plaintext.size.toLong(),
                        encryptionKey = DmAttachmentCipher.encrypt("unrelated".toByteArray()).key,
                    )

                val result =
                    DmAttachmentFetcher.fetchAndDecrypt(
                        wrongKeyRef,
                        DualKeyIdentity.generate().secp256k1KeyPair.publicKey,
                        fetcher.peerDirectory,
                        fetcher.storage,
                    )

                result.shouldBeNull()
            } finally {
                fetcher.stop()
            }
        }

        test("fetchAndDecrypt: bytes that do not decode as an EncryptedDmAttachmentBlob are rejected") {
            val fetcher = buildDmTestNode()
            try {
                val notABlob = "this is not an EncryptedDmAttachmentBlob".toByteArray()
                val cid = fetcher.storage.put(notABlob)
                val ref =
                    DmAttachmentRef(
                        cid = cid,
                        name = "file.bin",
                        mime = "application/octet-stream",
                        size = 1L,
                        encryptionKey = ByteArray(32) { 1 },
                    )

                val result =
                    DmAttachmentFetcher.fetchAndDecrypt(
                        ref,
                        DualKeyIdentity.generate().secp256k1KeyPair.publicKey,
                        fetcher.peerDirectory,
                        fetcher.storage,
                    )

                result.shouldBeNull()
            } finally {
                fetcher.stop()
            }
        }

        test("fetchAndDecrypt: a blob larger than MAX_BLOB_BYTES is rejected before ever reaching decode") {
            val fetcher = buildDmTestNode()
            try {
                val oversized = ByteArray(EncryptedDmAttachmentBlobCodec.MAX_BLOB_BYTES + 1)
                val cid = fetcher.storage.put(oversized)
                val ref =
                    DmAttachmentRef(
                        cid = cid,
                        name = "file.bin",
                        mime = "application/octet-stream",
                        size = 1L,
                        encryptionKey = ByteArray(32) { 1 },
                    )

                val result =
                    DmAttachmentFetcher.fetchAndDecrypt(
                        ref,
                        DualKeyIdentity.generate().secp256k1KeyPair.publicKey,
                        fetcher.peerDirectory,
                        fetcher.storage,
                    )

                result.shouldBeNull()
            } finally {
                fetcher.stop()
            }
        }
    })
