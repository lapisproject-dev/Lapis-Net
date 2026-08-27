package net.lapisphilosophorum.lapisnet.trust

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.libp2p.core.pubsub.ValidationResult
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.networking.deriveLibp2pPeerId
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions

/**
 * Unit-level tests of [VeritasGossip.onGossipMessage] itself - the actual GossipSub validator
 * function, called directly rather than through a full two-node gossip mesh. Only a single,
 * never-connected [LapisNode] + [NabuStorage] is needed (no [net.lapisphilosophorum.lapisnet.networking.GossipPubSub],
 * no `connect()`), since [VeritasGossip.onGossipMessage] already takes [NabuStorage]/
 * [VeritasGrantIndex] as plain parameters - this is exactly the test seam its doc comment
 * describes, made `internal` for precisely this purpose.
 *
 * This is the regression test for round-2's C2 fix: [VeritasGrantIndex.canAccept] (cheap,
 * in-memory) must gate [NabuStorage.put] (expensive, durable), not the other way around - and,
 * since round-3, ALSO the regression test proving that [VeritasGrantIndex.tryReservePersistence]
 * (a separate, non-evicting cap) is what actually bounds [NabuStorage.put] calls, since round-2's
 * own M2 eviction change silently made [VeritasGrantIndex.canAccept] alone insufficient for that
 * (see the "distinct grants beyond the persistence cap" test below). A two-node/mesh-level
 * integration test cannot cleanly observe "was this specific message ever persisted" without
 * racing GossipSub's own asynchronous mesh formation - a direct unit call sidesteps that entirely.
 */
class VeritasGossipOnGossipMessageTest :
    FunSpec({
        test("a duplicate (already-tracked) grant is declined by canAccept before storage.put ever runs") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("veritas-ongossip-a"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()

                val truster = identity.secp256k1KeyPair
                val target = Secp256k1KeyPair.generate().publicKey
                val grant = VeritasGrant.create(truster, target, trustMicros = 500_000)
                val bytes = VeritasGrantCodec.encode(grant)

                // Pre-populate the index directly (bypassing onGossipMessage) so the *next*
                // delivery of the identical grant is a true duplicate-by-content-id - this does
                // NOT touch storage, only the in-memory index.
                val index = VeritasGrantIndex()
                index.add(grant) shouldBe true

                val result = VeritasGossip.onGossipMessage(bytes, from, storage, index)

                result shouldBe ValidationResult.Invalid

                // Prove the duplicate delivery was never persisted: mint the CID for these exact
                // bytes on a separate, never-connected node's own blockstore (content-addressing
                // means the CID is a pure function of the bytes, computable independently of which
                // node stores them - mirrors NabuStorageLocalRoundTripTest's "never stored on the
                // node under test" pattern), then confirm the node-under-test's storage has no
                // local copy of it.
                val otherNode = LapisNode.create(DualKeyIdentity.generate())
                otherNode.start(bootstrapPeers = emptyList())
                val cid =
                    try {
                        NabuStorage.attach(otherNode, Files.createTempDirectory("veritas-ongossip-mint")).put(bytes)
                    } finally {
                        otherNode.stop()
                    }
                storage.get(cid).shouldBeNull()
            } finally {
                node.stop()
            }
        }

        test("a fresh, valid, non-duplicate grant is persisted, indexed, and accepted") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("veritas-ongossip-b"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()

                val truster = identity.secp256k1KeyPair
                val target = Secp256k1KeyPair.generate().publicKey
                val grant = VeritasGrant.create(truster, target, trustMicros = 500_000)
                val bytes = VeritasGrantCodec.encode(grant)
                val index = VeritasGrantIndex()

                val result = VeritasGossip.onGossipMessage(bytes, from, storage, index)

                result shouldBe ValidationResult.Valid
                index.grantsFor(truster.publicKey, target) shouldBe listOf(grant)
                storage.get(storage.put(bytes)) shouldBe bytes
            } finally {
                node.stop()
            }
        }

        // --- round-3 regression: canAccept() alone (post-M2 eviction) no longer bounds persistence ---

        test(
            "distinct grants beyond the persistence cap are all still Valid and indexed, but only up to the " +
                "cap are actually persisted to disk - tryReservePersistence, not canAccept, bounds storage.put()",
        ) {
            // This directly reproduces the round-3 security re-auditor's repro: with a small
            // persistence cap, many distinct, cheaply-signed grants (fresh free keypair each) must
            // NOT all land in NabuStorage, even though the round-2-only fix (gating storage.put()
            // purely on VeritasGrantIndex.canAccept()) would have let every single one of them
            // through - canAccept() only predicts exact-content-id duplication, and every grant
            // here has a distinct content id, so under the pre-round-3 code every one of these 10
            // grants would have called storage.put() unconditionally. If this test is run against
            // the round-2 code, assertion (b) below fails: MORE than persistCap distinct CIDs are
            // found readable via storage.get(), because tryReservePersistence() does not exist yet
            // and nothing else in the round-2 onGossipMessage() would have declined the put() call.
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("veritas-ongossip-persist-cap"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()

                val persistCap = 2
                val totalGrants = 10
                val index = VeritasGrantIndex(maxTracked = 100, maxPersisted = persistCap)

                data class Sent(
                    val truster: Secp256k1PublicKey,
                    val target: Secp256k1PublicKey,
                    val bytes: ByteArray,
                )

                val sent =
                    (1..totalGrants).map {
                        // Fresh, free keypair per grant - a cheap attacker's exact scenario: no
                        // proof-of-work, no cost beyond generating a keypair and a signature.
                        val truster = Secp256k1KeyPair.generate()
                        val target = Secp256k1KeyPair.generate().publicKey
                        val grant = VeritasGrant.create(truster, target, trustMicros = 500_000)
                        Sent(truster.publicKey, target, VeritasGrantCodec.encode(grant))
                    }

                val results = sent.map { VeritasGossip.onGossipMessage(it.bytes, from, storage, index) }

                // (a) All 10 are still tracked/propagated - a full disk budget on this node does not
                // make an otherwise-valid, non-duplicate grant invalid.
                results shouldBe List(totalGrants) { ValidationResult.Valid }

                // (c) The in-memory index reflects ALL 10 grants regardless of persistence status -
                // trust-view correctness does not depend on this node's disk budget.
                sent.forEach { index.grantsFor(it.truster, it.target) shouldHaveSize 1 }
                index.allPairs().size shouldBe totalGrants

                // (b) Only up to persistCap actually made it to durable storage. Verify this
                // concretely against the real NabuStorage: mint each grant's CID independently
                // (content-addressing means the CID is a pure function of the bytes) via a
                // separate, never-connected node's own blockstore, then check how many of those
                // CIDs the node-under-test's storage can actually serve.
                val mintingNode = LapisNode.create(DualKeyIdentity.generate())
                mintingNode.start(bootstrapPeers = emptyList())
                val persistedCount =
                    try {
                        val mintingStorage =
                            NabuStorage.attach(mintingNode, Files.createTempDirectory("veritas-ongossip-persist-mint"))
                        sent.count { storage.get(mintingStorage.put(it.bytes)) != null }
                    } finally {
                        mintingNode.stop()
                    }
                persistedCount shouldBe persistCap
            } finally {
                node.stop()
            }
        }

        // --- NabuStorage synchronous-exception-funnel regression (V0.8.5) ---

        test(
            "a genuine local I/O failure during storage.put (read-only blockstore directory) returns Invalid " +
                "and never crashes with a raw RuntimeException - VeritasGossip is the class every other gossip " +
                "validator's persist/catch(NabuStorageException)/reject shape was modeled after (see this file's " +
                "own doc comment), so this proves the NabuStorage.awaitOrWrap synchronous-throw fix genuinely " +
                "propagates up through a real call site, not just through NabuStorage's own unit tests. Without " +
                "the fix, Nabu's FileBlockstore.put rethrows the local IOException as a bare RuntimeException " +
                "synchronously - before NabuStorage.put's awaitOrWrap ever sees a failed CompletableFuture - and " +
                "this test crashes instead of observing ValidationResult.Invalid",
        ) {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val blockstoreDir = Files.createTempDirectory("veritas-ongossip-readonly")
                val storage = NabuStorage.attach(node, blockstoreDir)
                val blocksDir = blockstoreDir.resolve("blocks")
                if ("posix" !in blocksDir.fileSystem.supportedFileAttributeViews()) return@test

                Files.setPosixFilePermissions(blocksDir, PosixFilePermissions.fromString("r-xr-xr-x"))
                try {
                    val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                    val truster = identity.secp256k1KeyPair
                    val target = Secp256k1KeyPair.generate().publicKey
                    val grant = VeritasGrant.create(truster, target, trustMicros = 500_000)
                    val bytes = VeritasGrantCodec.encode(grant)
                    val index = VeritasGrantIndex()

                    val result = VeritasGossip.onGossipMessage(bytes, from, storage, index)

                    result shouldBe ValidationResult.Invalid
                    // VeritasGossip deliberately never indexes a grant it failed to persist -
                    // persist-before-index, per this function's own doc comment.
                    index.grantsFor(truster.publicKey, target) shouldBe emptyList()
                } finally {
                    Files.setPosixFilePermissions(blocksDir, PosixFilePermissions.fromString("rwxr-xr-x"))
                }
            } finally {
                node.stop()
            }
        }
    })
