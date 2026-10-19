package net.lapisphilosophorum.lapisnet.directory

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundleCodec
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files
import java.nio.file.Path

private fun Path.breakDirectory() {
    toFile().deleteRecursively()
    Files.writeString(this, "not a directory any more")
}

/**
 * The refactored tail of the gossip validators ([PeerDirectoryGossip.ingestVerified],
 * [PrekeyBundleGossip.ingestVerified]) is also the entry point of the DHT fallback, so its failure
 * handling and the purity of the gossip validators are pinned here.
 */
class DirectoryDhtIngestTest :
    FunSpec({
        test("a failing storage.put releases the persistence reservation again - peer records") {
            val node = LapisNode.create(DualKeyIdentity.generate())
            node.start(bootstrapPeers = emptyList())
            try {
                val dir = Files.createTempDirectory("ingest-release-peer")
                val storage = NabuStorage.attach(node, dir)
                val index = PeerRecordIndex(maxPersisted = 1)
                val a = DirectoryPublisher()
                val b = DirectoryPublisher()
                val first = a.peerRecord()
                val second = b.peerRecord()

                dir.breakDirectory()
                PeerDirectoryGossip.ingestVerified(
                    first,
                    PeerRecordCodec.encode(first),
                    "test",
                    storage,
                    index,
                ) shouldBe
                    IngestOutcome.PERSIST_FAILED
                index.size() shouldBe 0

                // the single persistence slot is free again: a second record can reserve it
                index.tryReservePersistence(second) shouldBe true
            } finally {
                runCatching { node.stop() }
            }
        }

        test("a failing storage.put releases the persistence reservation again - prekey bundles") {
            val node = LapisNode.create(DualKeyIdentity.generate())
            node.start(bootstrapPeers = emptyList())
            try {
                val dir = Files.createTempDirectory("ingest-release-bundle")
                val storage = NabuStorage.attach(node, dir)
                val index = PrekeyBundleIndex(maxPersisted = 1)
                val a = DirectoryPublisher()
                val b = DirectoryPublisher()
                val first = a.bundle()
                val second = b.bundle()

                dir.breakDirectory()
                PrekeyBundleGossip.ingestVerified(
                    first,
                    PrekeyBundleCodec.encode(first),
                    "test",
                    storage,
                    index,
                ) shouldBe
                    IngestOutcome.PERSIST_FAILED
                index.size() shouldBe 0
                index.tryReservePersistence(second) shouldBe true
            } finally {
                runCatching { node.stop() }
            }
        }

        test("ingestVerified accepts once and declines the duplicate and the stale one") {
            val node = LapisNode.create(DualKeyIdentity.generate())
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("ingest-outcomes"))
                val index = PeerRecordIndex()
                val a = DirectoryPublisher()
                val newer = a.peerRecord(sequence = 2)
                val older = a.peerRecord(sequence = 1)
                PeerDirectoryGossip.ingestVerified(
                    newer,
                    PeerRecordCodec.encode(newer),
                    "test",
                    storage,
                    index,
                ) shouldBe
                    IngestOutcome.ACCEPTED
                PeerDirectoryGossip.ingestVerified(
                    newer,
                    PeerRecordCodec.encode(newer),
                    "test",
                    storage,
                    index,
                ) shouldBe
                    IngestOutcome.DECLINED
                PeerDirectoryGossip.ingestVerified(
                    older,
                    PeerRecordCodec.encode(older),
                    "test",
                    storage,
                    index,
                ) shouldBe
                    IngestOutcome.DECLINED
                index.current(a.key) shouldBe newer
            } finally {
                runCatching { node.stop() }
            }
        }

        test("the gossip validators know nothing of the DHT, the network or the clock") {
            // Their compiled companion classes must not even mention these - the structural guarantee that the
            // validators stay free of network and clock access (the TTL is a read-time filter only).
            for (name in listOf("PeerDirectoryGossip\$Companion", "PrekeyBundleGossip\$Companion")) {
                val bytes =
                    DirectoryDhtIngestTest::class.java
                        .getResourceAsStream("/net/lapisphilosophorum/lapisnet/directory/$name.class")!!
                        .use { it.readBytes() }
                val text = String(bytes, Charsets.ISO_8859_1)
                for (forbidden in listOf(
                    "DirectoryDht",
                    "IpnsValueStore",
                    "java/time/Instant",
                    "nanoTime",
                    "currentTimeMillis",
                )) {
                    (forbidden in text) shouldBe false
                }
            }
            val validators =
                PeerDirectoryGossip.Companion::class.java.declaredMethods
                    .filter { it.name.startsWith("onGossipMessage") }
            (validators.isNotEmpty()) shouldBe true
            validators.flatMap { it.parameterTypes.toList() }.none {
                it.simpleName.contains("DirectoryDht") || it.simpleName.contains("IpnsValueStore")
            } shouldBe true
        }
    })
