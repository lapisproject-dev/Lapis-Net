package net.lapisphilosophorum.lapisnet.storage

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import java.nio.file.Files

/**
 * Single-node local put/get round trip - no network, no Bitswap wire protocol, no DHT. Exercises
 * only [NabuStorage.put]/[NabuStorage.get]'s local-blockstore path, so this must always pass
 * regardless of sandbox networking restrictions.
 */
class NabuStorageLocalRoundTripTest :
    FunSpec({
        test("put then get on the same node returns the original bytes") {
            val node = LapisNode.create(DualKeyIdentity.generate())
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("nabu-storage-test"))
                val payload = "hello lapis net storage".toByteArray()

                val cid = storage.put(payload)
                val fetched = storage.get(cid)

                fetched shouldBe payload
            } finally {
                node.stop()
            }
        }

        test("put then get of an empty byte array round-trips correctly") {
            val node = LapisNode.create(DualKeyIdentity.generate())
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("nabu-storage-test"))

                val cid = storage.put(ByteArray(0))
                val fetched = storage.get(cid)

                fetched shouldBe ByteArray(0)
            } finally {
                node.stop()
            }
        }

        test("getLocal returns a locally-put blob without any network/DHT activity") {
            val node = LapisNode.create(DualKeyIdentity.generate())
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("nabu-storage-test"))
                val payload = "getLocal round trip".toByteArray()

                val cid = storage.put(payload)
                val fetched = storage.getLocal(cid)

                fetched shouldBe payload
            } finally {
                node.stop()
            }
        }

        test("getLocal on a CID never stored on this node returns null") {
            val otherNode = LapisNode.create(DualKeyIdentity.generate())
            otherNode.start(bootstrapPeers = emptyList())
            val neverStoredCid =
                try {
                    NabuStorage
                        .attach(otherNode, Files.createTempDirectory("nabu-storage-test-other"))
                        .put("never stored on the node under test".toByteArray())
                } finally {
                    otherNode.stop()
                }

            val node = LapisNode.create(DualKeyIdentity.generate())
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("nabu-storage-test"))
                storage.getLocal(neverStoredCid).shouldBeNull()
            } finally {
                node.stop()
            }
        }

        test("get on a CID that was never stored, with no peers, returns null") {
            // Mint a CID that genuinely was never put on the node under test, by putting it on
            // a separate, never-connected node's own blockstore instead.
            val otherNode = LapisNode.create(DualKeyIdentity.generate())
            otherNode.start(bootstrapPeers = emptyList())
            val neverStoredCid =
                try {
                    NabuStorage
                        .attach(otherNode, Files.createTempDirectory("nabu-storage-test-other"))
                        .put("never stored on the node under test".toByteArray())
                } finally {
                    otherNode.stop()
                }

            val node = LapisNode.create(DualKeyIdentity.generate())
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("nabu-storage-test"))
                storage.get(neverStoredCid).shouldBeNull()
            } finally {
                node.stop()
            }
        }
    })
