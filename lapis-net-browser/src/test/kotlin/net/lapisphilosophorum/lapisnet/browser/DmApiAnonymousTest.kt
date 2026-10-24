package net.lapisphilosophorum.lapisnet.browser

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldNotContain
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
import net.lapisphilosophorum.lapisnet.dm.AnonymousDmTarget
import net.lapisphilosophorum.lapisnet.dm.AnonymousDmTransport
import net.lapisphilosophorum.lapisnet.dm.DmAcceptedContacts
import net.lapisphilosophorum.lapisnet.dm.DmAnonymousDeliveryException
import net.lapisphilosophorum.lapisnet.dm.DmAnonymousFailure
import net.lapisphilosophorum.lapisnet.dm.DmAttachmentCipher
import net.lapisphilosophorum.lapisnet.dm.DmAttachmentRef
import net.lapisphilosophorum.lapisnet.dm.DmContent
import net.lapisphilosophorum.lapisnet.dm.DmDeliveryState
import net.lapisphilosophorum.lapisnet.dm.DmRoute
import net.lapisphilosophorum.lapisnet.dm.DmSessionManager
import net.lapisphilosophorum.lapisnet.dm.DmStore
import net.lapisphilosophorum.lapisnet.dm.EncryptedDmAttachmentBlobCodec
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
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
import java.util.concurrent.atomic.AtomicInteger

private val anonJson = Json { ignoreUnknownKeys = true }

private object AnonNoAnchorSource : BitcoinTimeAnchorSource {
    override fun findFirstOutgoingTransaction(pubkey: Secp256k1PublicKey): TimeAnchorLookupResult =
        TimeAnchorLookupResult.NotFound

    override fun currentChainTipHeight(): Int = 0
}

/** A transport whose answers the test scripts; counts every call. */
private class ScriptedTransport(
    private val bundles: PrekeyBundleGossip,
) : AnonymousDmTransport {
    @Volatile var failure: DmAnonymousFailure? = null

    @Volatile var online = true
    val resolves = AtomicInteger()
    val deposits = AtomicInteger()

    override fun resolve(recipient: Secp256k1PublicKey): AnonymousDmTarget {
        resolves.incrementAndGet()
        failure?.let { throw DmAnonymousDeliveryException(it) }
        return AnonymousDmTarget(recipient, requireNotNull(bundles.lookup(recipient)).x25519IdentityKey, null, online)
    }

    override fun deliverOnline(
        target: AnonymousDmTarget,
        envelopeBytes: ByteArray,
        deadline: Instant,
    ): Boolean = true

    override fun depositOffline(
        target: AnonymousDmTarget,
        envelopeBytes: ByteArray,
        notValidAfterEpochSecond: Long,
    ) {
        deposits.incrementAndGet()
    }

    override fun close() = Unit
}

/** A single anonymity-mode node (no network peers) wired like [DmApiRoutingTest]'s harness. */
private class AnonHarness(
    val identity: DualKeyIdentity = DualKeyIdentity.generate(),
) {
    val node: LapisNode = LapisNode.create(identity).also { it.start(bootstrapPeers = emptyList()) }
    val storage: NabuStorage = NabuStorage.attach(node, Files.createTempDirectory("dm-api-anon"))
    val pubsub: GossipPubSub = GossipPubSub.attach(node)
    val veritas = VeritasGossip.attach(pubsub, storage)
    val virtus = LtrGossip.attach(pubsub, storage)
    val karma = KarmaGossip.attach(pubsub, storage)
    val posts = PostAnnouncementGossip.attach(pubsub, storage)
    val mailInbox = InboxGossip.attach(pubsub, storage, identity.secp256k1KeyPair.publicKey)
    val peerDirectory = PeerDirectoryGossip.attach(pubsub, storage)
    val prekeyBundleGossip = PrekeyBundleGossip.attach(pubsub, storage)
    val dmStore = DmStore()
    val sessionDir = Files.createTempDirectory("dm-api-anon-sessions")
    val dmSessionManager: DmSessionManager
    val transport: ScriptedTransport
    val deps: BrowserApiDependencies

    init {
        val prekeys =
            PrekeyStore.create(
                Files.createTempDirectory("dm-api-anon-prekeys"),
                identity,
                oneTimePrekeyCount = 2,
            )
        dmSessionManager =
            DmSessionManager.attach(
                identity,
                prekeys,
                node,
                peerDirectory,
                prekeyBundleGossip,
                null,
                storage,
                pubsub,
                sessionDir,
                "test-passphrase".toCharArray(),
                anonymous = true,
            )
        transport = ScriptedTransport(prekeyBundleGossip)
        dmSessionManager.installAnonymousTransport(transport)
        deps =
            BrowserApiDependencies(
                identity,
                node,
                storage,
                veritas,
                virtus,
                karma,
                posts,
                KarmaAnchorCache(AnonNoAnchorSource),
                mailInbox,
                MailSender(pubsub, storage),
                SentFolder(),
                dm = DmApiDependencies(peerDirectory, dmSessionManager, dmStore, DmAcceptedContacts()),
                anonymityActive = true,
            )
    }

    /** A recipient whose prekey bundle this node knows (indexed locally, as if received by gossip). */
    fun knownRecipient(): Secp256k1PublicKey {
        val recipient = DualKeyIdentity.generate()
        val store = PrekeyStore.create(Files.createTempDirectory("dm-api-anon-peer"), recipient, oneTimePrekeyCount = 2)
        runCatching { prekeyBundleGossip.announce(store.publishBundle(recipient, Instant.now().epochSecond + 3600)) }
        return recipient.secp256k1KeyPair.publicKey
    }

    fun sessionFiles(): Int =
        Files.list(sessionDir).use { s ->
            s
                .filter {
                    it.fileName.toString() != ".salt"
                }.count()
                .toInt()
        }

    fun stop() {
        runCatching { dmSessionManager.stop() }
        runCatching { prekeyBundleGossip.stop() }
        runCatching { peerDirectory.stop() }
        runCatching { mailInbox.stop() }
        runCatching { posts.stop() }
        runCatching { karma.stop() }
        runCatching { virtus.stop() }
        runCatching { veritas.stop() }
        runCatching { pubsub.stop() }
        runCatching { storage.stop() }
        runCatching { node.stop() }
    }
}

private fun hexOf(key: Secp256k1PublicKey): String = key.bytes.joinToString("") { "%02x".format(it) }

class DmApiAnonymousTest :
    FunSpec({
        fun io.ktor.client.HttpClient.unused() = Unit

        test("every refusal code has a fixed body and status; unknown, offline and blocking recipients look the same") {
            val h = AnonHarness()
            try {
                val recipients = List(3) { DualKeyIdentity.generate().secp256k1KeyPair.publicKey }
                h.transport.failure = DmAnonymousFailure.RECIPIENT_NOT_REACHABLE_ANONYMOUSLY
                testApplication {
                    application { installBrowserApi(h.deps) }
                    val bodies =
                        recipients.map { r ->
                            val response =
                                client.post("/api/dm/${hexOf(r)}") {
                                    contentType(ContentType.Application.Json)
                                    setBody(anonJson.encodeToString(NewDmRequest(body = "hi")))
                                }
                            response.status shouldBe HttpStatusCode.ServiceUnavailable
                            response.bodyAsText()
                        }
                    bodies.toSet().size shouldBe 1
                    bodies[0] shouldBe """{"error":"recipient-not-reachable-anonymously"}"""
                    for (r in recipients) bodies[0] shouldNotContain hexOf(r).take(12)

                    val peer = h.knownRecipient()
                    for (
                    (failure, status) in
                    listOf(
                        DmAnonymousFailure.ANONYMITY_NOT_READY to HttpStatusCode.ServiceUnavailable,
                        DmAnonymousFailure.RATE_LIMITED to HttpStatusCode.ServiceUnavailable,
                    )
                    ) {
                        h.transport.failure = failure
                        val response =
                            client.post("/api/dm/${hexOf(peer)}") {
                                contentType(ContentType.Application.Json)
                                setBody(anonJson.encodeToString(NewDmRequest(body = "hi")))
                            }
                        response.status shouldBe status
                        response.bodyAsText() shouldBe """{"error":"${failure.code}"}"""
                    }
                    h.transport.failure = null
                    val tooLarge =
                        client.post("/api/dm/${hexOf(peer)}") {
                            contentType(ContentType.Application.Json)
                            setBody(anonJson.encodeToString(NewDmRequest(body = "x".repeat(6_000))))
                        }
                    tooLarge.status shouldBe HttpStatusCode.PayloadTooLarge
                    tooLarge.bodyAsText() shouldBe """{"error":"message-too-large-anonymous"}"""
                }
                h.sessionFiles() shouldBe 0
                h.dmStore.peers().size shouldBe 0
            } finally {
                h.stop()
            }
        }

        test("attachments are refused with 409 before storage, cipher or session are touched") {
            val h = AnonHarness()
            try {
                val peer = h.knownRecipient()
                testApplication {
                    application { installBrowserApi(h.deps) }
                    val response =
                        client.post("/api/dm/${hexOf(peer)}") {
                            contentType(ContentType.Application.Json)
                            setBody(
                                anonJson.encodeToString(
                                    NewDmRequest(
                                        body = "hi",
                                        attachments = listOf(NewDmAttachmentRequest("a.txt", "text/plain", "AAAA")),
                                    ),
                                ),
                            )
                        }
                    response.status shouldBe HttpStatusCode.Conflict
                    response.bodyAsText() shouldBe """{"error":"attachments-unavailable-anonymous"}"""
                }
                h.transport.resolves.get() shouldBe 0
                h.sessionFiles() shouldBe 0
            } finally {
                h.stop()
            }
        }

        test("a delivered message carries route=circuit in the response and in the history") {
            val h = AnonHarness()
            try {
                val peer = h.knownRecipient()
                testApplication {
                    application { installBrowserApi(h.deps) }
                    val sent =
                        client.post("/api/dm/${hexOf(peer)}") {
                            contentType(ContentType.Application.Json)
                            setBody(anonJson.encodeToString(NewDmRequest(body = "hello")))
                        }
                    sent.status shouldBe HttpStatusCode.OK
                    val parsed = anonJson.decodeFromString<NewDmResponse>(sent.bodyAsText())
                    parsed.deliveryState shouldBe "SENT"
                    parsed.route shouldBe "circuit"
                    val history =
                        anonJson.decodeFromString<List<DmMessageResponse>>(
                            client.get("/api/dm/${hexOf(peer)}").bodyAsText(),
                        )
                    history.single().route shouldBe "circuit"

                    // queued for pickup when the online attempt is not possible
                    h.transport.online = false
                    val queued =
                        client.post("/api/dm/${hexOf(peer)}") {
                            contentType(ContentType.Application.Json)
                            setBody(anonJson.encodeToString(NewDmRequest(body = "later")))
                        }
                    anonJson.decodeFromString<NewDmResponse>(queued.bodyAsText()).deliveryState shouldBe
                        "QUEUED_FOR_PICKUP"
                    h.transport.deposits.get() shouldBe 1
                }
                h.dmSessionManager.routeMode() shouldBe DmRoute.CIRCUIT
            } finally {
                h.stop()
            }
        }

        test("an attachment that is not local is not fetched from the sender: 409; a local one is served") {
            val h = AnonHarness()
            try {
                val peer = DualKeyIdentity.generate().secp256k1KeyPair.publicKey
                val own = DmAttachmentCipher.encrypt("own bytes".toByteArray(), SecureRandom())
                val missing =
                    DmAttachmentRef(
                        h.storage.put(EncryptedDmAttachmentBlobCodec.encode(own.blob)),
                        "x.txt",
                        "text/plain",
                        9,
                        own.key,
                    )
                val foreignCid =
                    io.ipfs.cid.Cid
                        .decode("bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy")
                val remote = DmAttachmentRef(foreignCid, "remote.txt", "text/plain", 5, own.key)
                h.dmStore.recordOutbound(peer, DmContent("a", listOf(missing)), DmDeliveryState.SENT)
                h.dmStore.recordInbound(
                    net.lapisphilosophorum.lapisnet.dm.DmInboundMessage(
                        peer,
                        ByteArray(0),
                        DmContent("b", listOf(remote)),
                        false,
                        ByteArray(1),
                        Instant.now().epochSecond,
                    ),
                )
                testApplication {
                    application { installBrowserApi(h.deps) }
                    val gone = client.get("/api/dm/attachment/${hexOf(peer)}/${remote.cid}")
                    gone.status shouldBe HttpStatusCode.Conflict
                    gone.bodyAsText() shouldBe """{"error":"attachments-unavailable-anonymous"}"""
                    client.get("/api/dm/attachment/${hexOf(peer)}/${missing.cid}").status shouldBe HttpStatusCode.OK
                }
            } finally {
                h.stop()
            }
        }
    })
