package net.lapisphilosophorum.lapisnet.browser

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.testing.testApplication
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import net.lapisphilosophorum.lapisnet.directory.PeerDirectoryGossip
import net.lapisphilosophorum.lapisnet.directory.PrekeyBundleGossip
import net.lapisphilosophorum.lapisnet.dm.DmAcceptedContacts
import net.lapisphilosophorum.lapisnet.dm.DmAttachmentCipher
import net.lapisphilosophorum.lapisnet.dm.DmAttachmentRef
import net.lapisphilosophorum.lapisnet.dm.DmContent
import net.lapisphilosophorum.lapisnet.dm.DmContentCodec
import net.lapisphilosophorum.lapisnet.dm.DmDeliveryState
import net.lapisphilosophorum.lapisnet.dm.DmInboundMessage
import net.lapisphilosophorum.lapisnet.dm.DmSessionManager
import net.lapisphilosophorum.lapisnet.dm.DmStore
import net.lapisphilosophorum.lapisnet.dm.EncryptedDmAttachmentBlobCodec
import net.lapisphilosophorum.lapisnet.dm.MailboxGossip
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.karma.BitcoinTimeAnchorSource
import net.lapisphilosophorum.lapisnet.karma.KarmaGossip
import net.lapisphilosophorum.lapisnet.karma.TimeAnchorLookupResult
import net.lapisphilosophorum.lapisnet.mail.InboxGossip
import net.lapisphilosophorum.lapisnet.mail.MailSender
import net.lapisphilosophorum.lapisnet.mail.SentFolder
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyStore
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import net.lapisphilosophorum.lapisnet.trust.VeritasGossip
import net.lapisphilosophorum.lapisnet.virtus.LtrGossip
import java.nio.file.Files
import java.security.SecureRandom
import java.time.Instant
import java.util.Base64

private val json = Json { ignoreUnknownKeys = true }

private object DmTestNoAnchorSource : BitcoinTimeAnchorSource {
    override fun findFirstOutgoingTransaction(
        pubkey: net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey,
    ): TimeAnchorLookupResult = TimeAnchorLookupResult.NotFound

    override fun currentChainTipHeight(): Int = 0
}

/**
 * Single-node harness, mirroring [MailTestHarness] (`BrowserApiMailRoutingTest.kt`) exactly -
 * duplicated locally for the same "that class is `private` to its own file" reason that file's own
 * doc comment gives. A single, never-connected [LapisNode] is enough for every test below: history
 * listing/reading/accepting is exercised by writing directly into [DmStore]/[DmAcceptedContacts]
 * (mirroring [DmSessionManager.addInboundListener]'s own intended caller, without needing a real
 * two-node handshake) - see [TwoNodeDmBrowserIntegrationTest] for the real two-node, real-gossip,
 * real-send proof this file deliberately does not attempt.
 */
private class DmTestHarness(
    val identity: DualKeyIdentity = DualKeyIdentity.generate(),
) {
    val node: LapisNode = LapisNode.create(identity)
    val storage: NabuStorage
    val pubsub: GossipPubSub
    val veritas: VeritasGossip
    val virtus: LtrGossip
    val karma: KarmaGossip
    val posts: PostAnnouncementGossip
    val mailInbox: InboxGossip
    val peerDirectory: PeerDirectoryGossip
    val prekeyBundleGossip: PrekeyBundleGossip
    val mailboxGossip: MailboxGossip
    val dmSessionManager: DmSessionManager
    val dmStore = DmStore()
    val dmAcceptedContacts = DmAcceptedContacts()
    val deps: BrowserApiDependencies

    init {
        node.start(bootstrapPeers = emptyList())
        storage = NabuStorage.attach(node, Files.createTempDirectory("dm-api-routing-test"))
        pubsub = GossipPubSub.attach(node)
        veritas = VeritasGossip.attach(pubsub, storage)
        virtus = LtrGossip.attach(pubsub, storage)
        karma = KarmaGossip.attach(pubsub, storage)
        posts = PostAnnouncementGossip.attach(pubsub, storage)
        val karmaAnchorCache = KarmaAnchorCache(DmTestNoAnchorSource)
        mailInbox = InboxGossip.attach(pubsub, storage, identity.secp256k1KeyPair.publicKey)
        val mailSender = MailSender(pubsub, storage)
        val sentFolder = SentFolder()

        peerDirectory = PeerDirectoryGossip.attach(pubsub, storage)
        prekeyBundleGossip = PrekeyBundleGossip.attach(pubsub, storage)
        mailboxGossip = MailboxGossip.attach(pubsub, storage, identity.secp256k1KeyPair.publicKey)
        val prekeyStore =
            PrekeyStore.create(
                Files.createTempDirectory("dm-api-routing-test-prekeys"),
                identity,
                oneTimePrekeyCount = 2,
            )
        dmSessionManager =
            DmSessionManager.attach(
                identity,
                prekeyStore,
                node,
                peerDirectory,
                prekeyBundleGossip,
                mailboxGossip,
                storage,
                pubsub,
                Files.createTempDirectory("dm-api-routing-test-sessions"),
                "test-passphrase".toCharArray(),
            )

        deps =
            BrowserApiDependencies(
                identity,
                node,
                storage,
                veritas,
                virtus,
                karma,
                posts,
                karmaAnchorCache,
                mailInbox,
                mailSender,
                sentFolder,
                dm = DmApiDependencies(peerDirectory, dmSessionManager, dmStore, dmAcceptedContacts),
            )
    }

    fun putEncryptedAttachment(bytes: ByteArray): DmAttachmentRef {
        val encrypted = DmAttachmentCipher.encrypt(bytes, SecureRandom())
        val cid = storage.put(EncryptedDmAttachmentBlobCodec.encode(encrypted.blob))
        return DmAttachmentRef(cid, "note.txt", "text/plain", bytes.size.toLong(), encrypted.key)
    }

    fun stop() {
        runCatching { dmSessionManager.stop() }
        mailboxGossip.stop()
        prekeyBundleGossip.stop()
        peerDirectory.stop()
        mailInbox.stop()
        posts.stop()
        karma.stop()
        virtus.stop()
        veritas.stop()
        pubsub.stop()
        storage.stop()
        runCatching { node.stop() }
    }
}

private fun hexOf(publicKey: net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey): String =
    publicKey.bytes.joinToString("") { "%02x".format(it) }

class DmApiRoutingTest :
    FunSpec({
        test("GET /api/dm lists conversations with last-message preview and accepted flag") {
            val harness = DmTestHarness()
            val peer = DualKeyIdentity.generate().secp256k1KeyPair.publicKey
            try {
                harness.dmStore.recordInbound(
                    DmInboundMessage(
                        sender = peer,
                        plaintext = ByteArray(0),
                        content = DmContent("hello there"),
                        quarantined = true,
                        dedupKey = ByteArray(1),
                        receivedAtEpochSecond = Instant.now().epochSecond,
                    ),
                )

                testApplication {
                    application { installBrowserApi(harness.deps) }
                    val response = client.get("/api/dm")
                    response.status shouldBe HttpStatusCode.OK
                    val conversations = json.decodeFromString<List<DmConversationSummary>>(response.bodyAsText())
                    conversations.size shouldBe 1
                    conversations.single().peerPublicKeyHex shouldBe hexOf(peer)
                    conversations.single().lastMessage.body shouldBe "hello there"
                    conversations.single().lastMessage.quarantined shouldBe true
                    conversations.single().accepted shouldBe false
                }
            } finally {
                harness.stop()
            }
        }

        test("GET /api/dm/{peerHex} returns full history in order, including attachment metadata") {
            val harness = DmTestHarness()
            val peer = DualKeyIdentity.generate().secp256k1KeyPair.publicKey
            try {
                val attachment = harness.putEncryptedAttachment("attachment bytes".toByteArray())
                harness.dmStore.recordInbound(
                    DmInboundMessage(
                        sender = peer,
                        plaintext = ByteArray(0),
                        content = DmContent("first"),
                        quarantined = false,
                        dedupKey = ByteArray(1),
                        receivedAtEpochSecond = Instant.now().epochSecond,
                    ),
                )
                harness.dmStore.recordOutbound(peer, DmContent("second", listOf(attachment)), DmDeliveryState.SENT)

                testApplication {
                    application { installBrowserApi(harness.deps) }
                    val response = client.get("/api/dm/${hexOf(peer)}")
                    response.status shouldBe HttpStatusCode.OK
                    val history = json.decodeFromString<List<DmMessageResponse>>(response.bodyAsText())
                    history.size shouldBe 2
                    history[0].direction shouldBe "inbound"
                    history[0].body shouldBe "first"
                    history[1].direction shouldBe "outbound"
                    history[1].body shouldBe "second"
                    history[1].deliveryState shouldBe "SENT"
                    history[1].attachments.size shouldBe 1
                    history[1].attachments.single().name shouldBe "note.txt"
                }
            } finally {
                harness.stop()
            }
        }

        test("GET /api/dm/{peerHex} with a malformed hex returns 400") {
            val harness = DmTestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }
                    val response = client.get("/api/dm/not-hex")
                    response.status shouldBe HttpStatusCode.BadRequest
                }
            } finally {
                harness.stop()
            }
        }

        test("POST /api/dm/{peerHex}/accept marks a peer accepted") {
            val harness = DmTestHarness()
            val peer = DualKeyIdentity.generate().secp256k1KeyPair.publicKey
            try {
                harness.dmAcceptedContacts.isAccepted(peer) shouldBe false
                testApplication {
                    application { installBrowserApi(harness.deps) }
                    // See DmAcceptRequest's own doc comment - a JSON body is required, even though
                    // it carries no information itself, so this route is not a CSRF-exploitable
                    // "no body" POST like a plain cross-origin <form> could otherwise reach.
                    val response =
                        client.post("/api/dm/${hexOf(peer)}/accept") {
                            contentType(ContentType.Application.Json)
                            setBody("{}")
                        }
                    response.status shouldBe HttpStatusCode.OK
                }
                harness.dmAcceptedContacts.isAccepted(peer) shouldBe true
            } finally {
                harness.stop()
            }
        }

        test("GET /api/dm/attachment/{peerHex}/{cid} decrypts and returns a locally-stored attachment") {
            val harness = DmTestHarness()
            val peer = DualKeyIdentity.generate().secp256k1KeyPair.publicKey
            try {
                val attachment = harness.putEncryptedAttachment("secret bytes".toByteArray())
                harness.dmStore.recordOutbound(
                    peer,
                    DmContent("with attachment", listOf(attachment)),
                    DmDeliveryState.SENT,
                )

                testApplication {
                    application { installBrowserApi(harness.deps) }
                    val response = client.get("/api/dm/attachment/${hexOf(peer)}/${attachment.cid}")
                    response.status shouldBe HttpStatusCode.OK
                    response.bodyAsText() shouldBe "secret bytes"
                }
            } finally {
                harness.stop()
            }
        }

        test("POST /api/dm/{peerHex} to an unknown recipient fails cleanly with 502, no history recorded") {
            val harness = DmTestHarness()
            val peer = DualKeyIdentity.generate().secp256k1KeyPair.publicKey
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }
                    val response =
                        client.post("/api/dm/${hexOf(peer)}") {
                            contentType(ContentType.Application.Json)
                            setBody(json.encodeToString(NewDmRequest(body = "hi")))
                        }
                    response.status shouldBe HttpStatusCode.BadGateway
                }
                harness.dmStore.historyFor(peer).size shouldBe 0
            } finally {
                harness.stop()
            }
        }

        test(
            "POST /api/dm/{peerHex}/accept without a JSON body is rejected (CSRF hardening regression)",
        ) {
            // V0.8.6b hardening-pass finding: this route used to accept a plain, body-less POST -
            // exactly the shape a cross-origin <form method="POST"> can send without triggering a
            // CORS preflight (see DmAcceptRequest's own doc comment). Asserting this is no longer
            // 200 is the regression test for that fix.
            val harness = DmTestHarness()
            val peer = DualKeyIdentity.generate().secp256k1KeyPair.publicKey
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }
                    val response = client.post("/api/dm/${hexOf(peer)}/accept")
                    response.status shouldNotBe HttpStatusCode.OK
                }
                harness.dmAcceptedContacts.isAccepted(peer) shouldBe false
            } finally {
                harness.stop()
            }
        }

        test("POST /api/dm/{peerHex} rejects an oversized body with 400") {
            val harness = DmTestHarness()
            val peer = DualKeyIdentity.generate().secp256k1KeyPair.publicKey
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }
                    val response =
                        client.post("/api/dm/${hexOf(peer)}") {
                            contentType(ContentType.Application.Json)
                            val oversizedBody = "x".repeat(DmContentCodec.MAX_DM_BODY_BYTES + 1)
                            setBody(json.encodeToString(NewDmRequest(body = oversizedBody)))
                        }
                    response.status shouldBe HttpStatusCode.BadRequest
                }
                harness.dmStore.historyFor(peer).size shouldBe 0
            } finally {
                harness.stop()
            }
        }

        test("POST /api/dm/{peerHex} rejects more than MAX_DM_ATTACHMENTS attachments with 400") {
            val harness = DmTestHarness()
            val peer = DualKeyIdentity.generate().secp256k1KeyPair.publicKey
            try {
                val tooMany =
                    (0..DmContentCodec.MAX_DM_ATTACHMENTS).map {
                        NewDmAttachmentRequest(name = "a$it.txt", mime = "text/plain", contentBase64 = "AAAA")
                    }
                testApplication {
                    application { installBrowserApi(harness.deps) }
                    val response =
                        client.post("/api/dm/${hexOf(peer)}") {
                            contentType(ContentType.Application.Json)
                            setBody(json.encodeToString(NewDmRequest(body = "hi", attachments = tooMany)))
                        }
                    response.status shouldBe HttpStatusCode.BadRequest
                }
                harness.dmStore.historyFor(peer).size shouldBe 0
            } finally {
                harness.stop()
            }
        }

        test("POST /api/dm/{peerHex} rejects malformed base64 attachment content with 400") {
            val harness = DmTestHarness()
            val peer = DualKeyIdentity.generate().secp256k1KeyPair.publicKey
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }
                    val response =
                        client.post("/api/dm/${hexOf(peer)}") {
                            contentType(ContentType.Application.Json)
                            setBody(
                                json.encodeToString(
                                    NewDmRequest(
                                        body = "hi",
                                        attachments =
                                            listOf(
                                                NewDmAttachmentRequest(
                                                    name = "a.txt",
                                                    mime = "text/plain",
                                                    contentBase64 = "not-valid-base64!!!",
                                                ),
                                            ),
                                    ),
                                ),
                            )
                        }
                    response.status shouldBe HttpStatusCode.BadRequest
                }
                harness.dmStore.historyFor(peer).size shouldBe 0
            } finally {
                harness.stop()
            }
        }

        test("POST /api/dm/{peerHex} rejects an oversized attachment name with 400") {
            val harness = DmTestHarness()
            val peer = DualKeyIdentity.generate().secp256k1KeyPair.publicKey
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }
                    val response =
                        client.post("/api/dm/${hexOf(peer)}") {
                            contentType(ContentType.Application.Json)
                            setBody(
                                json.encodeToString(
                                    NewDmRequest(
                                        body = "hi",
                                        attachments =
                                            listOf(
                                                NewDmAttachmentRequest(
                                                    name = "a".repeat(DmContentCodec.MAX_ATTACHMENT_NAME_BYTES + 1),
                                                    mime = "text/plain",
                                                    contentBase64 = "AAAA",
                                                ),
                                            ),
                                    ),
                                ),
                            )
                        }
                    response.status shouldBe HttpStatusCode.BadRequest
                }
                harness.dmStore.historyFor(peer).size shouldBe 0
            } finally {
                harness.stop()
            }
        }

        test("POST /api/dm/{peerHex} rejects an oversized attachment mime with 400") {
            val harness = DmTestHarness()
            val peer = DualKeyIdentity.generate().secp256k1KeyPair.publicKey
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }
                    val response =
                        client.post("/api/dm/${hexOf(peer)}") {
                            contentType(ContentType.Application.Json)
                            setBody(
                                json.encodeToString(
                                    NewDmRequest(
                                        body = "hi",
                                        attachments =
                                            listOf(
                                                NewDmAttachmentRequest(
                                                    name = "a.txt",
                                                    mime = "x".repeat(DmContentCodec.MAX_ATTACHMENT_MIME_BYTES + 1),
                                                    contentBase64 = "AAAA",
                                                ),
                                            ),
                                    ),
                                ),
                            )
                        }
                    response.status shouldBe HttpStatusCode.BadRequest
                }
                harness.dmStore.historyFor(peer).size shouldBe 0
            } finally {
                harness.stop()
            }
        }

        test("POST /api/dm/{peerHex} rejects an attachment exceeding the upload cap with 400 and no orphaned blob") {
            val harness = DmTestHarness()
            val peer = DualKeyIdentity.generate().secp256k1KeyPair.publicKey
            try {
                val oversized = ByteArray((MAX_DM_ATTACHMENT_UPLOAD_BYTES + 1).toInt())
                val oversizedBase64 = Base64.getEncoder().encodeToString(oversized)
                testApplication {
                    application { installBrowserApi(harness.deps) }
                    val response =
                        client.post("/api/dm/${hexOf(peer)}") {
                            contentType(ContentType.Application.Json)
                            setBody(
                                json.encodeToString(
                                    NewDmRequest(
                                        body = "hi",
                                        attachments =
                                            listOf(
                                                NewDmAttachmentRequest(
                                                    name = "big.bin",
                                                    mime = "application/octet-stream",
                                                    contentBase64 = oversizedBase64,
                                                ),
                                            ),
                                    ),
                                ),
                            )
                        }
                    response.status shouldBe HttpStatusCode.BadRequest
                }
                harness.dmStore.historyFor(peer).size shouldBe 0
            } finally {
                harness.stop()
            }
        }

        test("a BrowserApiDependencies with dm = null installs no /api/dm routes") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            val storage = NabuStorage.attach(node, Files.createTempDirectory("dm-api-routing-test-no-dm"))
            val pubsub = GossipPubSub.attach(node)
            val veritas = VeritasGossip.attach(pubsub, storage)
            val virtus = LtrGossip.attach(pubsub, storage)
            val karma = KarmaGossip.attach(pubsub, storage)
            val posts = PostAnnouncementGossip.attach(pubsub, storage)
            val karmaAnchorCache = KarmaAnchorCache(DmTestNoAnchorSource)
            val mailInbox = InboxGossip.attach(pubsub, storage, identity.secp256k1KeyPair.publicKey)
            val mailSender = MailSender(pubsub, storage)
            val sentFolder = SentFolder()
            val deps =
                BrowserApiDependencies(
                    identity,
                    node,
                    storage,
                    veritas,
                    virtus,
                    karma,
                    posts,
                    karmaAnchorCache,
                    mailInbox,
                    mailSender,
                    sentFolder,
                )
            try {
                testApplication {
                    application { installBrowserApi(deps) }
                    val response = client.get("/api/dm")
                    response.status shouldBe HttpStatusCode.NotFound
                }
            } finally {
                mailInbox.stop()
                posts.stop()
                karma.stop()
                virtus.stop()
                veritas.stop()
                pubsub.stop()
                storage.stop()
                runCatching { node.stop() }
            }
        }
    })
