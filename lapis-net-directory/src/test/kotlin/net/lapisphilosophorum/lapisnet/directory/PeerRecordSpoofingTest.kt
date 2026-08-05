package net.lapisphilosophorum.lapisnet.directory

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerId
import io.libp2p.core.multiformats.Multiaddr
import io.libp2p.core.pubsub.ValidationResult
import io.libp2p.crypto.keys.unmarshalEd25519PublicKey
import net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.IdentityBinding
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.networking.deriveLibp2pPeerId
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files
import java.time.Instant

private fun testAddress(port: Int): Multiaddr = Multiaddr("/ip4/127.0.0.1/tcp/$port")

private fun record(
    identity: DualKeyIdentity,
    sequenceNumber: Long,
    addresses: List<Multiaddr> = listOf(testAddress(4000 + sequenceNumber.toInt())),
): PeerRecord = PeerRecord.create(identity, addresses, setOf(PeerCapability.DM), sequenceNumber, 9_999_999_999L)

/** Genuinely self-signed by [signingIdentity] (so [PeerRecord.verify] is true), but embedding a
 * DIFFERENT identity's [IdentityBinding] - so [PeerRecord.verifyBinding] is false. Bypasses
 * [PeerRecord.create]'s own `require(identity.verifyBinding())` guard by building the signed body
 * and signature directly with the same digest [PeerRecord.create] itself would produce. */
private fun spoofedRecord(
    signingIdentity: DualKeyIdentity,
    victimBinding: IdentityBinding,
    addresses: List<Multiaddr> = emptyList(),
    capabilities: Set<PeerCapability> = emptySet(),
    sequenceNumber: Long = 0,
    notValidAfterEpochSecond: Long = 9_999_999_999L,
): PeerRecord {
    val body =
        PeerRecordCodec.encodeSignedBody(
            identity = signingIdentity.secp256k1KeyPair.publicKey,
            binding = victimBinding,
            possessionProof = ByteArray(64),
            addresses = addresses,
            capabilities = capabilities,
            sequenceNumber = sequenceNumber,
            notValidAfterEpochSecond = notValidAfterEpochSecond,
        )
    val digest = domainSeparatedDigest("LapisNet:peer-record:v1", body)
    val signature = signingIdentity.secp256k1KeyPair.sign(digest)
    return PeerRecord.fromDecoded(
        identity = signingIdentity.secp256k1KeyPair.publicKey,
        binding = victimBinding,
        addresses = addresses,
        capabilities = capabilities,
        sequenceNumber = sequenceNumber,
        notValidAfterEpochSecond = notValidAfterEpochSecond,
        signature = signature,
    )
}

/**
 * The mandatory adversarial spec for this wave - see the V0.8.1 plan's test list, cases (a)
 * through (e), plus the minimum-republish-interval enforcement (delegated to
 * [PeerPresenceAnnouncerTest] per the plan's own recommended split).
 */
class PeerRecordSpoofingTest :
    FunSpec({
        test("(a) peerId-spoofing: a genuinely self-signed record with a mismatched binding is rejected end-to-end") {
            val identityA = DualKeyIdentity.generate() // attacker
            val identityB = DualKeyIdentity.generate() // victim
            val addresses = listOf(testAddress(4321))

            val spoofed =
                spoofedRecord(
                    signingIdentity = identityA,
                    victimBinding = identityB.binding,
                    addresses = addresses,
                    capabilities = setOf(PeerCapability.DM),
                )

            // The outer signature genuinely IS valid - proving this is NOT a signature-failure case.
            PeerRecord.verify(spoofed) shouldBe true
            // The embedded binding does NOT verify against the signing identity.
            spoofed.verifyBinding() shouldBe false

            // What the missing check would have let through: identityA's spoofed record's peerId
            // is exactly identityB's REAL peerId - i.e. if verifyBinding() were skipped, identityA
            // could successfully claim identityB's real network addresses under identityA's own,
            // legitimately-self-signed record.
            val victimRealPeerId =
                PeerId.fromPubKey(unmarshalEd25519PublicKey(identityB.ed25519KeyPair.publicKey.bytes))
            spoofed.peerId shouldBe victimRealPeerId
            spoofed.peerId shouldBe identityB.deriveLibp2pPeerId()

            // End-to-end: the validator must reject it, and nothing gets persisted or indexed.
            val node = LapisNode.create(identityA)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("spoofing-a"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = PeerRecordIndex()
                val bytes = PeerRecordCodec.encode(spoofed)

                val result = PeerDirectoryGossip.onGossipMessage(bytes, from, storage, index)

                result shouldBe ValidationResult.Invalid
                index.allIdentities() shouldBe emptySet()

                val mintingNode = LapisNode.create(DualKeyIdentity.generate())
                mintingNode.start(bootstrapPeers = emptyList())
                try {
                    val mintingStorage = NabuStorage.attach(mintingNode, Files.createTempDirectory("spoofing-a-mint"))
                    storage.get(mintingStorage.put(bytes)).shouldBeNull()
                } finally {
                    mintingNode.stop()
                }
            } finally {
                node.stop()
            }
        }

        test("(b) sequence-number rollback never overwrites a newer, already-indexed record") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("spoofing-b"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = PeerRecordIndex()

                val newer = record(identity, 5)
                index.add(newer) shouldBe true

                val rollback = record(identity, 3)
                val bytes = PeerRecordCodec.encode(rollback)

                val result = PeerDirectoryGossip.onGossipMessage(bytes, from, storage, index)

                result shouldBe ValidationResult.Invalid
                index.current(identity.secp256k1KeyPair.publicKey) shouldBe newer
            } finally {
                node.stop()
            }
        }

        test("(c) an expired record is never returned by lookup(), even though it is still stored") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("spoofing-c"))
                val pubsub = GossipPubSub.attach(node)
                val gossip = PeerDirectoryGossip.attach(pubsub, storage)

                val expired =
                    PeerRecord.create(
                        identity,
                        addresses = listOf(testAddress(4001)),
                        capabilities = setOf(PeerCapability.DM),
                        sequenceNumber = 0,
                        notValidAfterEpochSecond = Instant.now().epochSecond - 3600,
                    )
                gossip.announce(expired)

                gossip.lookup(identity.secp256k1KeyPair.publicKey).shouldBeNull()

                val pastNow = Instant.now().epochSecond - 7200
                val stillStored = gossip.lookup(identity.secp256k1KeyPair.publicKey, nowEpochSecond = pastNow)
                stillStored.shouldNotBeNull()
                stillStored shouldBe expired
            } finally {
                node.stop()
            }
        }

        test("(d) a flood of distinct fabricated identities is bounded by the index caps") {
            val cap = 50
            val floodSize = 200
            val index = PeerRecordIndex(maxTracked = cap, maxPersisted = cap)

            repeat(floodSize) {
                val identity = DualKeyIdentity.generate()
                val r = record(identity, 0)
                index.add(r)
                (index.size() <= cap) shouldBe true
            }

            index.size() shouldBe cap
        }

        test("(e) an all-zero signature is rejected cleanly, never thrown, both at verify() and in the validator") {
            val record = record(DualKeyIdentity.generate(), 0)
            val bytes = PeerRecordCodec.encode(record)
            val allZeroBytes = bytes.copyOf()
            for (i in (bytes.size - 64) until bytes.size) allZeroBytes[i] = 0

            val decodedAllZero = PeerRecordCodec.decode(allZeroBytes) // must not throw - structurally well-formed
            PeerRecord.verify(decodedAllZero) shouldBe false

            val node = LapisNode.create(DualKeyIdentity.generate())
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("spoofing-e-zero"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = PeerRecordIndex()

                PeerDirectoryGossip.onGossipMessage(allZeroBytes, from, storage, index) shouldBe
                    ValidationResult.Invalid
            } finally {
                node.stop()
            }
        }

        test("(e) an all-0xFF signature is rejected cleanly, never thrown, both at verify() and in the validator") {
            val record = record(DualKeyIdentity.generate(), 0)
            val bytes = PeerRecordCodec.encode(record)
            val allOnesBytes = bytes.copyOf()
            for (i in (bytes.size - 64) until bytes.size) allOnesBytes[i] = 0xFF.toByte()

            val decodedAllOnes = PeerRecordCodec.decode(allOnesBytes) // must not throw
            PeerRecord.verify(decodedAllOnes) shouldBe false

            val node = LapisNode.create(DualKeyIdentity.generate())
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("spoofing-e-ones"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = PeerRecordIndex()

                PeerDirectoryGossip.onGossipMessage(allOnesBytes, from, storage, index) shouldBe
                    ValidationResult.Invalid
            } finally {
                node.stop()
            }
        }

        // Security regression (V0.8.1 sub-wave audit round 1, major finding 1): closes the
        // end-to-end attack the auditor's PROBE1 demonstrated - a self-consistent binding (attacker
        // signs their OWN garbage ed25519 bytes with their OWN secp256k1 key) that made both
        // PeerRecord.verify() and verifyBinding() pass, got indexed/persisted/re-propagated, and
        // only THEN threw IllegalArgumentException from record.peerId/toString(). Attacking via raw
        // wire bytes (rather than PeerRecord.create/IdentityBinding.create) because, after the fix,
        // constructing an Ed25519PublicKey from garbage bytes now throws immediately - so this is
        // the only way left to even attempt reaching the validator with such a record.
        test(
            "(f) a garbage (non-curve-point) ed25519 binding key is rejected end-to-end - " +
                "never indexed, .peerId/.toString() never throw on any record the index holds",
        ) {
            val identity = DualKeyIdentity.generate()
            val bytes = PeerRecordCodec.encode(record(identity, 0)).copyOf()
            // edPublicKeyBytes(32) sits right after magic(4)+version(1)+flags(1)+identity(33).
            val edKeyOffset = 4 + 1 + 1 + 33
            for (i in 0 until 32) bytes[edKeyOffset + i] = 0xFF.toByte()

            val node = LapisNode.create(DualKeyIdentity.generate())
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("spoofing-f"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = PeerRecordIndex()

                val result = PeerDirectoryGossip.onGossipMessage(bytes, from, storage, index)

                result shouldBe ValidationResult.Invalid
                index.allIdentities() shouldBe emptySet()
                // Every record the index DOES hold must have a peerId/toString() that never
                // throws - the whole point of rejecting the malformed key at decode()-time.
                index.allIdentities().forEach { id ->
                    val current = index.current(id)
                    current?.peerId
                    current?.toString()
                }
            } finally {
                node.stop()
            }
        }

        // Security regression (V0.8.1 sub-wave audit round 1, major finding 2): the anti-rollback
        // high-water mark must survive eviction of the actual record body from the tracking index.
        // Before the fix, canAccept/add compared a replayed record only against currentByIdentity,
        // which removeEldestEntry clears the moment a record is evicted from recordsByContentId -
        // after that, a stale record for the SAME identity was accepted as if it were the first one
        // ever seen. This test flags the exact scenario the auditor's PROBE2 demonstrated: a
        // higher-sequence-number record is accepted, then a flood of freshly-fabricated identities
        // pushes it out of the tracking cap, then the OLD stale record is replayed - and must still
        // be rejected, through the REAL PeerDirectoryGossip.onGossipMessage validator, not just the
        // index's own add()/canAccept() in isolation.
        test(
            "(g) sequence-number rollback is still rejected after the victim's record is evicted " +
                "from the tracking cap by a flood of fresh identities",
        ) {
            val cap = 10
            val floodSize = 20
            val index = PeerRecordIndex(maxTracked = cap, maxPersisted = cap + floodSize + 1)
            val node = LapisNode.create(DualKeyIdentity.generate())
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("spoofing-g"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()

                val victim = DualKeyIdentity.generate()
                val fresh = record(victim, 99, addresses = listOf(testAddress(5002)))
                PeerDirectoryGossip.onGossipMessage(PeerRecordCodec.encode(fresh), from, storage, index) shouldBe
                    ValidationResult.Valid
                index.current(victim.secp256k1KeyPair.publicKey) shouldBe fresh

                // Flood past maxTracked with freshly-fabricated identities - each is a legitimately
                // signed record for a brand-new identity, so every one is accepted, and eventually
                // the victim's record is evicted from recordsByContentId (and, per removeEldestEntry,
                // un-linked from currentByIdentity too).
                repeat(floodSize) {
                    val floodRecord = record(DualKeyIdentity.generate(), 0)
                    PeerDirectoryGossip.onGossipMessage(PeerRecordCodec.encode(floodRecord), from, storage, index)
                }
                index.current(victim.secp256k1KeyPair.publicKey).shouldBeNull() // evicted, as expected

                // Replay the victim's OLD, stale seq=1 record - must still be rejected, even though
                // the index no longer has a live record for this identity to compare against.
                val stale = record(victim, 1, addresses = listOf(testAddress(5001)))
                val result = PeerDirectoryGossip.onGossipMessage(PeerRecordCodec.encode(stale), from, storage, index)

                result shouldBe ValidationResult.Invalid
                index.current(victim.secp256k1KeyPair.publicKey).shouldBeNull()
            } finally {
                node.stop()
            }
        }

        // Security regression (V0.8.1 sub-wave audit round 2, major finding 1): the REAL
        // cross-binding attack the auditor's PROBE A demonstrated - genuinely DIFFERENT from case
        // (a) above. Case (a) reuses the VICTIM's own IdentityBinding object verbatim, which fails
        // verifyBinding() outright (the embedded signature was made by the victim's key, so it
        // cannot verify against the attacker's identity). THIS attack instead RE-SIGNS a FRESH
        // IdentityBinding - IdentityBinding.create(attackerSecpKeyPair, victimEd25519PublicKey) -
        // which is genuinely, legitimately self-consistent: the attacker's own secp256k1 key
        // correctly signed it. Both PeerRecord.verify() AND verifyBinding() therefore pass, exactly
        // reproducing the auditor's PROBE A result against the real validator (outerSignatureValid
        // =true, verifyBinding=true, recordPeerId==victimRealPeerId=true, validatorResult=Valid
        // before this fix). Only verifyPossession() - the NEW Ed25519 proof-of-possession
        // counter-signature - closes it: the attacker never held the victim's Ed25519 PRIVATE key,
        // only the public key it copied off an earlier, legitimately-published record, so it cannot
        // produce a possessionProof binding.ed25519PublicKey.verify() accepts.
        test(
            "(h) peerId cross-binding via a RE-SIGNED (not reused) IdentityBinding is rejected end-to-end " +
                "by verifyPossession(), even though verify() and verifyBinding() both genuinely pass",
        ) {
            val attacker = DualKeyIdentity.generate()
            val victim = DualKeyIdentity.generate()
            val addresses = listOf(testAddress(4322))

            // The attacker mints a BRAND-NEW binding, self-signed with their OWN secp256k1 key,
            // over the victim's PUBLIC (and therefore freely copyable) Ed25519 key - NOT the
            // victim's own binding object.
            val forgedBinding = IdentityBinding.create(attacker.secp256k1KeyPair, victim.ed25519KeyPair.publicKey)
            IdentityBinding.verify(attacker.secp256k1KeyPair.publicKey, forgedBinding) shouldBe true

            val body =
                PeerRecordCodec.encodeSignedBody(
                    identity = attacker.secp256k1KeyPair.publicKey,
                    binding = forgedBinding,
                    // The attacker does not hold the victim's Ed25519 private key, so this can only
                    // ever be a placeholder, never a genuine possession proof.
                    possessionProof = ByteArray(64),
                    addresses = addresses,
                    capabilities = setOf(PeerCapability.DM),
                    sequenceNumber = 0,
                    notValidAfterEpochSecond = 9_999_999_999L,
                )
            val signature =
                attacker.secp256k1KeyPair.sign(domainSeparatedDigest("LapisNet:peer-record:v1", body))
            val forged =
                PeerRecord.fromDecoded(
                    identity = attacker.secp256k1KeyPair.publicKey,
                    binding = forgedBinding,
                    addresses = addresses,
                    capabilities = setOf(PeerCapability.DM),
                    sequenceNumber = 0,
                    notValidAfterEpochSecond = 9_999_999_999L,
                    signature = signature,
                )

            // Both checks that closed case (a) genuinely pass here - this is NOT a signature or
            // binding failure, proving this is a materially different attack shape.
            PeerRecord.verify(forged) shouldBe true
            forged.verifyBinding() shouldBe true
            // ...and it really does claim the victim's real, derivable peerId.
            val victimRealPeerId =
                PeerId.fromPubKey(unmarshalEd25519PublicKey(victim.ed25519KeyPair.publicKey.bytes))
            forged.peerId shouldBe victimRealPeerId
            forged.peerId shouldBe victim.deriveLibp2pPeerId()
            // Only the NEW check fails.
            forged.verifyPossession() shouldBe false

            // End-to-end: the real validator must reject it, and nothing gets persisted or indexed.
            val node = LapisNode.create(attacker)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("spoofing-h"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = PeerRecordIndex()
                val bytes = PeerRecordCodec.encode(forged)

                val result = PeerDirectoryGossip.onGossipMessage(bytes, from, storage, index)

                result shouldBe ValidationResult.Invalid
                index.allIdentities() shouldBe emptySet()
            } finally {
                node.stop()
            }
        }
    })
