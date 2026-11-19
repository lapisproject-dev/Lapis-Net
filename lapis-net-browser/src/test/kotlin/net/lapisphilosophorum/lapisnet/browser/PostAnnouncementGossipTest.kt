package net.lapisphilosophorum.lapisnet.browser

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.libp2p.core.pubsub.ValidationResult
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.networking.deriveLibp2pPeerId
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files

private fun testBody(text: String = "hello lapis net"): ByteArray = text.toByteArray(Charsets.UTF_8)

/**
 * Unit-level tests of [PostAnnouncementGossip.onGossipMessage] itself, called directly rather than
 * through a full two-node gossip mesh - mirrors
 * [net.lapisphilosophorum.lapisnet.virtus.LtrGossipOnGossipMessageTest]'s exact test seam
 * reasoning (a single, never-connected [LapisNode] + [NabuStorage] is enough, since the function
 * takes both as plain parameters).
 */
class PostAnnouncementGossipTest :
    FunSpec({
        test("a fresh, valid, non-duplicate announcement is persisted, indexed, and accepted") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("post-ongossip-a"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()

                val author = identity.secp256k1KeyPair
                val announcement = PostAnnouncement.create(author, testBody())
                val bytes = PostAnnouncementCodec.encode(announcement)
                val index = PostAnnouncementIndex()

                val result = PostAnnouncementGossip.onGossipMessage(bytes, from, storage, index)

                result shouldBe ValidationResult.Valid
                index.all() shouldHaveSize 1
                index.all().single().announcement shouldBe announcement
            } finally {
                node.stop()
            }
        }

        test(
            "the receiving side can fetch the post body bytes back from its own local storage via the " +
                "derived Cid - proves the embed-bytes-derive-locally design actually works",
        ) {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("post-ongossip-cid"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()

                val author = identity.secp256k1KeyPair
                val body = testBody("proving content-addressed re-derivation works")
                val announcement = PostAnnouncement.create(author, body)
                val bytes = PostAnnouncementCodec.encode(announcement)
                val index = PostAnnouncementIndex()

                val result = PostAnnouncementGossip.onGossipMessage(bytes, from, storage, index)

                result shouldBe ValidationResult.Valid
                val derivedCid = index.all().single().cid
                val fetched = storage.get(derivedCid)
                fetched.shouldNotBeNull()
                fetched.contentEquals(body) shouldBe true
            } finally {
                node.stop()
            }
        }

        test("a signature-corrupted announcement is rejected as Invalid and never persisted") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("post-ongossip-sig"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()

                val author = identity.secp256k1KeyPair
                val announcement = PostAnnouncement.create(author, testBody())
                val bytes = PostAnnouncementCodec.encode(announcement)
                bytes[bytes.size - 1] = (bytes[bytes.size - 1] + 1).toByte() // tamper the signature
                val index = PostAnnouncementIndex()

                val result = PostAnnouncementGossip.onGossipMessage(bytes, from, storage, index)

                result shouldBe ValidationResult.Invalid
                index.all() shouldBe emptyList()
            } finally {
                node.stop()
            }
        }

        test("body bytes altered after signing are rejected as Invalid") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("post-ongossip-body"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()

                val author = identity.secp256k1KeyPair
                val announcement = PostAnnouncement.create(author, testBody())
                val bytes = PostAnnouncementCodec.encode(announcement)

                // bodyBytes starts right after magic(4)+version(1)+author(33)+bodyLen(2).
                val bodyOffset = 4 + 1 + 33 + 2
                bytes[bodyOffset] = (bytes[bodyOffset] + 1).toByte()

                val index = PostAnnouncementIndex()

                val result = PostAnnouncementGossip.onGossipMessage(bytes, from, storage, index)

                result shouldBe ValidationResult.Invalid
                index.all() shouldBe emptyList()
            } finally {
                node.stop()
            }
        }

        test("a replayed (identical bytes) delivery is declined by canAccept - not re-persisted or re-indexed") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("post-ongossip-replay"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()

                val author = identity.secp256k1KeyPair
                val announcement = PostAnnouncement.create(author, testBody())
                val bytes = PostAnnouncementCodec.encode(announcement)
                val index = PostAnnouncementIndex()

                val first = PostAnnouncementGossip.onGossipMessage(bytes, from, storage, index)
                val second = PostAnnouncementGossip.onGossipMessage(bytes, from, storage, index)

                first shouldBe ValidationResult.Valid
                second shouldBe ValidationResult.Invalid
                index.all() shouldHaveSize 1
            } finally {
                node.stop()
            }
        }

        test(
            "distinct announcements beyond the persistence cap are all still Valid and indexed, and the body " +
                "bytes are always stored regardless of the cap - only the wrapper bytes are capped",
        ) {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("post-ongossip-persist-cap"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()

                val persistCap = 2
                val totalAnnouncements = 6
                val index = PostAnnouncementIndex(maxTracked = 100, maxPersisted = persistCap)

                val sent =
                    (1..totalAnnouncements).map { i ->
                        val author = Secp256k1KeyPair.generate()
                        val announcement = PostAnnouncement.create(author, testBody("post number $i"))
                        announcement to PostAnnouncementCodec.encode(announcement)
                    }

                val results =
                    sent.map { (_, bytes) ->
                        PostAnnouncementGossip.onGossipMessage(
                            bytes,
                            from,
                            storage,
                            index,
                        )
                    }

                results shouldBe List(totalAnnouncements) { ValidationResult.Valid }
                index.all() shouldHaveSize totalAnnouncements

                // Every body's bytes are fetchable via its own derived Cid, regardless of the
                // persistence cap on the wrapper bytes - this is the whole point of the
                // unconditional body-bytes put() in onGossipMessage.
                index.all().forEach { indexed ->
                    val fetched = storage.get(indexed.cid)
                    fetched.shouldNotBeNull()
                    fetched.contentEquals(indexed.announcement.bodyBytes) shouldBe true
                }
            } finally {
                node.stop()
            }
        }

        test(
            "distinct announcements beyond the BODY persistence cap are still Valid and indexed, but their " +
                "body bytes are NOT written to storage - closes the unbounded-disk-growth gap",
        ) {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("post-ongossip-body-cap"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()

                val bodyPersistCap = 2
                val totalAnnouncements = 6
                val index =
                    PostAnnouncementIndex(
                        maxTracked = 100,
                        maxPersisted = 100,
                        maxPersistedBodies = bodyPersistCap,
                    )

                val sent =
                    (1..totalAnnouncements).map { i ->
                        val author = Secp256k1KeyPair.generate()
                        val announcement = PostAnnouncement.create(author, testBody("distinct body number $i"))
                        announcement to PostAnnouncementCodec.encode(announcement)
                    }

                val results =
                    sent.map { (_, bytes) ->
                        PostAnnouncementGossip.onGossipMessage(bytes, from, storage, index)
                    }

                // Every announcement is still accepted, regardless of the body-persistence cap -
                // declining that cap must never decline the message itself (mirrors the wrapper
                // cap's identical, already-established contract).
                results shouldBe List(totalAnnouncements) { ValidationResult.Valid }
                index.all() shouldHaveSize totalAnnouncements

                // Only the first bodyPersistCap distinct bodies were actually written to storage;
                // the rest were declined by tryReserveBodyPersistence and must NOT be fetchable.
                val fetched = index.all().map { indexed -> storage.get(indexed.cid) }
                fetched.count { it != null } shouldBe bodyPersistCap
                fetched.count { it == null } shouldBe (totalAnnouncements - bodyPersistCap)
            } finally {
                node.stop()
            }
        }

        test(
            "re-announcing the SAME body content (same Cid) via a different wrapper does not double-count " +
                "against the body persistence cap",
        ) {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("post-ongossip-body-cap-dedup"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()

                val bodyPersistCap = 1
                val index =
                    PostAnnouncementIndex(
                        maxTracked = 100,
                        maxPersisted = 100,
                        maxPersistedBodies = bodyPersistCap,
                    )

                val sharedBody = testBody("shared content re-announced by two different authors")
                val firstAnnouncement = PostAnnouncement.create(Secp256k1KeyPair.generate(), sharedBody)
                val secondAnnouncement = PostAnnouncement.create(Secp256k1KeyPair.generate(), sharedBody)

                val firstResult =
                    PostAnnouncementGossip.onGossipMessage(
                        PostAnnouncementCodec.encode(firstAnnouncement),
                        from,
                        storage,
                        index,
                    )
                val secondResult =
                    PostAnnouncementGossip.onGossipMessage(
                        PostAnnouncementCodec.encode(secondAnnouncement),
                        from,
                        storage,
                        index,
                    )

                firstResult shouldBe ValidationResult.Valid
                secondResult shouldBe ValidationResult.Valid
                index.all() shouldHaveSize 2

                // Both announcements share one Cid (identical body bytes) - the cap (size 1) was
                // only spent once, so the shared body IS durably stored, for both entries.
                index.all().forEach { indexed ->
                    val body = storage.get(indexed.cid)
                    body.shouldNotBeNull()
                    body.contentEquals(sharedBody) shouldBe true
                }
            } finally {
                node.stop()
            }
        }

        test("a duplicate delivery's wrapper bytes are never persisted twice, verified against the real blockstore") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("post-ongossip-dup-persist"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()

                val author = identity.secp256k1KeyPair
                val announcement = PostAnnouncement.create(author, testBody())
                val bytes = PostAnnouncementCodec.encode(announcement)

                val index = PostAnnouncementIndex()
                val cid = storage.put(announcement.bodyBytes)
                index.add(announcement, cid) shouldBe true

                val result = PostAnnouncementGossip.onGossipMessage(bytes, from, storage, index)

                result shouldBe ValidationResult.Invalid

                val otherNode = LapisNode.create(DualKeyIdentity.generate())
                otherNode.start(bootstrapPeers = emptyList())
                val mintedCid =
                    try {
                        NabuStorage.attach(otherNode, Files.createTempDirectory("post-ongossip-dup-mint")).put(bytes)
                    } finally {
                        otherNode.stop()
                    }
                storage.get(mintedCid).shouldBeNull()
            } finally {
                node.stop()
            }
        }

        test("Q20: onBodyStored is called once after the body was stored, for an own and for a gossiped post") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("post-q20-callback"))
                val seen = java.util.concurrent.CopyOnWriteArrayList<io.ipfs.cid.Cid>()
                val gossip =
                    PostAnnouncementGossip.attach(
                        net.lapisphilosophorum.lapisnet.networking.GossipPubSub
                            .attach(node),
                        storage,
                    ) { cid ->
                        // at call time the body is already in the served store
                        storage.isServed(cid) shouldBe true
                        seen += cid
                    }
                val own = PostAnnouncement.create(identity.secp256k1KeyPair, testBody("own post"))
                val ownCid = gossip.announce(own)
                seen shouldBe listOf(ownCid)

                // a gossiped post goes through the same callback (validator path)
                val index = PostAnnouncementIndex()
                val received = PostAnnouncement.create(Secp256k1KeyPair.generate(), testBody("received post"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val calls = java.util.concurrent.CopyOnWriteArrayList<io.ipfs.cid.Cid>()
                PostAnnouncementGossip.onGossipMessage(
                    PostAnnouncementCodec.encode(received),
                    from,
                    storage,
                    index,
                ) { calls += it } shouldBe ValidationResult.Valid
                calls shouldBe listOf(deriveBodyCid(received.bodyBytes))
                gossip.stop()
            } finally {
                node.stop()
            }
        }

        test("Q20: onBodyStored is not called for a capped body, a duplicate or an invalid signature") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("post-q20-nocall"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val calls = java.util.concurrent.CopyOnWriteArrayList<io.ipfs.cid.Cid>()
                val callback: (io.ipfs.cid.Cid) -> Unit = { calls += it }

                // cap of 0 bodies: accepted and indexed, but the body is not stored, so no callback
                val capped = PostAnnouncementIndex(maxTracked = 10, maxPersisted = 10, maxPersistedBodies = 0)
                val a = PostAnnouncement.create(Secp256k1KeyPair.generate(), testBody("capped"))
                PostAnnouncementGossip.onGossipMessage(
                    PostAnnouncementCodec.encode(a),
                    from,
                    storage,
                    capped,
                    callback,
                ) shouldBe
                    ValidationResult.Valid
                calls shouldBe emptyList()

                // duplicate: the first delivery calls back, the second does not
                val index = PostAnnouncementIndex()
                val b =
                    PostAnnouncementCodec.encode(
                        PostAnnouncement.create(Secp256k1KeyPair.generate(), testBody("dup")),
                    )
                PostAnnouncementGossip.onGossipMessage(b, from, storage, index, callback) shouldBe
                    ValidationResult.Valid
                PostAnnouncementGossip.onGossipMessage(b, from, storage, index, callback) shouldBe
                    ValidationResult.Invalid
                calls shouldHaveSize 1

                // invalid signature
                val c =
                    PostAnnouncementCodec.encode(
                        PostAnnouncement.create(Secp256k1KeyPair.generate(), testBody("bad sig")),
                    )
                c[c.size - 1] = (c[c.size - 1] + 1).toByte()
                PostAnnouncementGossip.onGossipMessage(c, from, storage, index, callback) shouldBe
                    ValidationResult.Invalid
                calls shouldHaveSize 1
            } finally {
                node.stop()
            }
        }

        test("Q20: a failing body write calls nothing back") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val dir = Files.createTempDirectory("post-q20-readonly")
                val storage = NabuStorage.attach(node, dir)
                val blocksDir = dir.resolve("blocks")
                if ("posix" !in blocksDir.fileSystem.supportedFileAttributeViews()) return@test
                val calls = java.util.concurrent.CopyOnWriteArrayList<io.ipfs.cid.Cid>()
                java.nio.file.Files.setPosixFilePermissions(
                    blocksDir,
                    java.nio.file.attribute.PosixFilePermissions
                        .fromString("r-xr-xr-x"),
                )
                try {
                    val bytes =
                        PostAnnouncementCodec.encode(
                            PostAnnouncement.create(Secp256k1KeyPair.generate(), testBody("not writable")),
                        )
                    PostAnnouncementGossip.onGossipMessage(
                        bytes,
                        DualKeyIdentity.generate().deriveLibp2pPeerId(),
                        storage,
                        PostAnnouncementIndex(),
                    ) { calls += it } shouldBe ValidationResult.Invalid
                    calls shouldBe emptyList()
                } finally {
                    java.nio.file.Files.setPosixFilePermissions(
                        blocksDir,
                        java.nio.file.attribute.PosixFilePermissions
                            .fromString("rwxr-xr-x"),
                    )
                }
            } finally {
                node.stop()
            }
        }

        test("Q20: a throwing onBodyStored changes neither the validation result nor announce") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("post-q20-throw"))
                val throwing: (io.ipfs.cid.Cid) -> Unit = { throw IllegalStateException("callback failed") }
                val bytes =
                    PostAnnouncementCodec.encode(PostAnnouncement.create(Secp256k1KeyPair.generate(), testBody("t")))
                val index = PostAnnouncementIndex()
                PostAnnouncementGossip.onGossipMessage(
                    bytes,
                    DualKeyIdentity.generate().deriveLibp2pPeerId(),
                    storage,
                    index,
                    throwing,
                ) shouldBe ValidationResult.Valid
                index.all() shouldHaveSize 1
                val gossip =
                    PostAnnouncementGossip.attach(
                        net.lapisphilosophorum.lapisnet.networking.GossipPubSub
                            .attach(node),
                        storage,
                        throwing,
                    )
                val own = PostAnnouncement.create(identity.secp256k1KeyPair, testBody("own, throwing callback"))
                val cid = gossip.announce(own)
                storage.getLocal(cid).shouldNotBeNull()
                gossip.currentPosts() shouldHaveSize 1
                gossip.stop()
            } finally {
                node.stop()
            }
        }
    })
