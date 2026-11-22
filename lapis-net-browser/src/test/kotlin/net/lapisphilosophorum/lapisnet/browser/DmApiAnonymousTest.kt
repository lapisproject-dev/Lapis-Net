package net.lapisphilosophorum.lapisnet.browser

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldNotContain
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
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
import net.lapisphilosophorum.lapisnet.dmonion.attachment.AttachmentFetchClient
import net.lapisphilosophorum.lapisnet.dmonion.attachment.AttachmentFetchFailure
import net.lapisphilosophorum.lapisnet.dmonion.attachment.AttachmentFetchResult
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

/** Wave Q21: an attachment fetch over circuits whose answer the test scripts; records every call. */
internal class ScriptedAttachmentClient : AttachmentFetchClient {
    @Volatile var next: AttachmentFetchResult = AttachmentFetchResult.NotFound
    val calls = AtomicInteger()
    val senders = java.util.concurrent.CopyOnWriteArrayList<Secp256k1PublicKey>()
    val maxBytes = java.util.concurrent.CopyOnWriteArrayList<Int>()

    override fun fetch(
        sender: Secp256k1PublicKey,
        cid: io.ipfs.cid.Cid,
        attachmentKey: ByteArray,
        maxBytes: Int,
    ): java.util.concurrent.CompletableFuture<AttachmentFetchResult> {
        calls.incrementAndGet()
        senders += sender
        this.maxBytes += maxBytes
        return java.util.concurrent.CompletableFuture
            .completedFuture(next)
    }
}

/** The CIDv1 (raw, SHA-256) of [bytes], as the blockstore would compute it. */
internal fun rawCidOf(bytes: ByteArray): io.ipfs.cid.Cid =
    io.ipfs.cid.Cid.buildCidV1(
        io.ipfs.cid.Cid.Codec.Raw,
        io.ipfs.multihash.Multihash.Type.sha2_256,
        java.security.MessageDigest
            .getInstance("SHA-256")
            .digest(bytes),
    )

/** A single anonymity-mode node (no network peers) wired like [DmApiRoutingTest]'s harness. */
private class AnonHarness(
    val identity: DualKeyIdentity = DualKeyIdentity.generate(),
    /** Wave Q21: the scripted fetch over circuits; `null` wires no fetcher at all (anonymity not ready). */
    val client: ScriptedAttachmentClient? = ScriptedAttachmentClient(),
) {
    val node: LapisNode = LapisNode.create(identity).also { it.start(bootstrapPeers = emptyList()) }

    /** Every connection this node ever opened or accepted (a direct dial would show up here). */
    val connections = AtomicInteger().also { c -> node.addConnectionHandler { c.incrementAndGet() } }
    val blockDir: java.nio.file.Path = Files.createTempDirectory("dm-api-anon")
    val storage: NabuStorage = NabuStorage.attach(node, blockDir)

    /** Regular files under the blockstore directory (a write shows up here). */
    fun storedFiles(): Long = Files.walk(blockDir).use { w -> w.filter { Files.isRegularFile(it) }.count() }

    val pubsub: GossipPubSub = GossipPubSub.attach(node)
    val veritas = VeritasGossip.attach(pubsub, storage)
    val virtus = LtrGossip.attach(pubsub, storage)
    val karma = KarmaGossip.attach(pubsub, storage)
    val posts = PostAnnouncementGossip.attach(pubsub, storage)
    val mailInbox = InboxGossip.attach(pubsub, storage, identity.secp256k1KeyPair.publicKey)
    val peerDirectory = PeerDirectoryGossip.attach(pubsub, storage)
    val prekeyBundleGossip = PrekeyBundleGossip.attach(pubsub, storage)
    val dmStore = DmStore()
    val fetcher: AnonymousAttachmentFetcher? =
        client?.let { c -> AnonymousAttachmentFetcher(NabuAttachmentBlobStore(storage), { c }) }
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
                dm =
                    DmApiDependencies(
                        peerDirectory,
                        dmSessionManager,
                        dmStore,
                        DmAcceptedContacts(),
                        anonymousAttachments = fetcher,
                    ),
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

        // Wave Q21: attachments are no longer refused as such in anonymity mode; the limit is one fetch over circuits
        // (about 4 MiB per attachment), checked before storage, cipher or session are touched.
        test(
            "an attachment up to the anonymity limit is sent and stored unserved; limit + 1 is 413 before anything else",
        ) {
            val h = AnonHarness()
            try {
                val peer = h.knownRecipient()

                fun request(size: Int) =
                    anonJson.encodeToString(
                        NewDmRequest(
                            body = "hi",
                            attachments =
                                listOf(
                                    NewDmAttachmentRequest(
                                        "a.bin",
                                        "application/octet-stream",
                                        java.util.Base64
                                            .getEncoder()
                                            .encodeToString(ByteArray(size) { 7 }),
                                    ),
                                ),
                        ),
                    )
                testApplication {
                    application { installBrowserApi(h.deps) }
                    val small =
                        client.post("/api/dm/${hexOf(peer)}") {
                            contentType(ContentType.Application.Json)
                            setBody(request(1_000))
                        }
                    small.status shouldBe HttpStatusCode.OK
                    val sentRef = (
                        h.dmStore
                            .historyFor(peer)
                            .last()
                            .content.attachments
                            .single()
                    )
                    // stored, but in the store that is never served or announced
                    h.storage.getLocal(sentRef.cid) shouldNotBe null
                    h.storage.isServed(sentRef.cid) shouldBe false

                    val atLimit =
                        client.post("/api/dm/${hexOf(peer)}") {
                            contentType(ContentType.Application.Json)
                            setBody(request(MAX_ANONYMOUS_DM_ATTACHMENT_BYTES))
                        }
                    atLimit.status shouldBe HttpStatusCode.OK

                    val resolvesBefore = h.transport.resolves.get()
                    val historyBefore = h.dmStore.historyFor(peer).size
                    val filesBefore = h.storedFiles()
                    val sessionsBefore = h.sessionFiles()
                    val tooLarge =
                        client.post("/api/dm/${hexOf(peer)}") {
                            contentType(ContentType.Application.Json)
                            setBody(request(MAX_ANONYMOUS_DM_ATTACHMENT_BYTES + 1))
                        }
                    tooLarge.status shouldBe HttpStatusCode.PayloadTooLarge
                    tooLarge.bodyAsText() shouldBe """{"error":"attachment-too-large-anonymous"}"""
                    h.transport.resolves.get() shouldBe resolvesBefore
                    h.dmStore.historyFor(peer).size shouldBe historyBefore
                    h.storedFiles() shouldBe filesBefore
                    h.sessionFiles() shouldBe sessionsBefore
                }
                MAX_ANONYMOUS_DM_ATTACHMENT_BYTES shouldBe 4_193_946
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

        // Wave Q21: a blob that is not local is fetched from the sender's onion service (scripted here); never a
        // direct connection. Every outcome has a fixed code.
        test("a blob that is not local is fetched from the sender's service; every outcome has its fixed code") {
            val h = AnonHarness()
            try {
                val peer = DualKeyIdentity.generate().secp256k1KeyPair.publicKey
                val own = DmAttachmentCipher.encrypt("own bytes".toByteArray(), SecureRandom())
                val local =
                    DmAttachmentRef(
                        h.storage.put(EncryptedDmAttachmentBlobCodec.encode(own.blob)),
                        "x.txt",
                        "text/plain",
                        9,
                        own.key,
                    )
                val plaintext = "remote attachment".toByteArray()
                val remoteEncrypted = DmAttachmentCipher.encrypt(plaintext, SecureRandom())
                val remoteBlob = EncryptedDmAttachmentBlobCodec.encode(remoteEncrypted.blob)
                val remote =
                    DmAttachmentRef(
                        rawCidOf(remoteBlob),
                        "remote.txt",
                        "text/plain",
                        plaintext.size.toLong(),
                        remoteEncrypted.key,
                    )
                h.dmStore.recordOutbound(peer, DmContent("a", listOf(local)), DmDeliveryState.SENT)
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
                val c = checkNotNull(h.client)
                testApplication {
                    application { installBrowserApi(h.deps) }
                    val url = "/api/dm/attachment/${hexOf(peer)}/${remote.cid}"
                    // Security (Q21): a cross-site subresource (<img src>) or a foreign Origin must not trigger the
                    // onion fetch (deanonymization oracle). 403 before any lookup; the fetch client is never asked.
                    c.next = AttachmentFetchResult.Found(remoteBlob)
                    val crossSite = client.get(url) { header("Sec-Fetch-Site", "cross-site") }
                    crossSite.status shouldBe HttpStatusCode.Forbidden
                    val sameSite = client.get(url) { header("Sec-Fetch-Site", "same-site") }
                    sameSite.status shouldBe HttpStatusCode.Forbidden
                    val foreignOrigin = client.get(url) { header(HttpHeaders.Origin, "https://attacker.example") }
                    foreignOrigin.status shouldBe HttpStatusCode.Forbidden
                    c.calls.get() shouldBe 0
                    for ((result, expected) in listOf(
                        AttachmentFetchResult.NotFound to
                            (HttpStatusCode.NotFound to "attachments-unavailable-anonymous"),
                        AttachmentFetchResult.Unavailable(AttachmentFetchFailure.MANIPULATED) to
                            (HttpStatusCode.NotFound to "attachments-unavailable-anonymous"),
                        AttachmentFetchResult.Unavailable(AttachmentFetchFailure.TIMEOUT) to
                            (HttpStatusCode.GatewayTimeout to "attachment-fetch-timeout-anonymous"),
                        AttachmentFetchResult.Unavailable(AttachmentFetchFailure.RATE_LIMITED) to
                            (HttpStatusCode.ServiceUnavailable to "rate-limited"),
                        AttachmentFetchResult.Unavailable(AttachmentFetchFailure.NOT_READY) to
                            (HttpStatusCode.ServiceUnavailable to "anonymity-not-ready"),
                        AttachmentFetchResult.Unavailable(AttachmentFetchFailure.TOO_LARGE) to
                            (HttpStatusCode.PayloadTooLarge to "attachment-too-large-anonymous"),
                    )) {
                        c.next = result
                        val response = client.get(url)
                        response.status shouldBe expected.first
                        response.bodyAsText() shouldBe """{"error":"${expected.second}"}"""
                    }
                    // bytes that do not decrypt under the ref's key: 404, no plaintext
                    c.next = AttachmentFetchResult.Found(EncryptedDmAttachmentBlobCodec.encode(own.blob))
                    val wrong = client.get(url)
                    wrong.status shouldBe HttpStatusCode.NotFound
                    wrong.bodyAsText() shouldBe """{"error":"attachments-unavailable-anonymous"}"""
                    // the genuine blob: the plaintext; the request named the inbound peer as the sender
                    c.next = AttachmentFetchResult.Found(remoteBlob)
                    val ok = client.get(url)
                    ok.status shouldBe HttpStatusCode.OK
                    ok.bodyAsText() shouldBe "remote attachment"
                    c.senders.all { it == peer } shouldBe true
                    c.maxBytes.last() shouldBe plaintext.size + EncryptedDmAttachmentBlobCodec.OVERHEAD_BYTES
                    // stored unserved: the second download is local and asks nobody
                    val calls = c.calls.get()
                    client.get(url).bodyAsText() shouldBe "remote attachment"
                    c.calls.get() shouldBe calls
                    h.storage.isServed(remote.cid) shouldBe false
                    // the outbound (own) blob is local
                    client.get("/api/dm/attachment/${hexOf(peer)}/${local.cid}").status shouldBe HttpStatusCode.OK
                }
                // never a direct connection: the node dialled nobody
                h.connections.get() shouldBe 0
            } finally {
                h.stop()
            }
        }

        test("without a wired fetcher a blob that is not local is 503 anonymity-not-ready, a local one is served") {
            val h = AnonHarness(client = null)
            try {
                val peer = DualKeyIdentity.generate().secp256k1KeyPair.publicKey
                val enc = DmAttachmentCipher.encrypt("zz".toByteArray(), SecureRandom())
                val blob = EncryptedDmAttachmentBlobCodec.encode(enc.blob)
                val remote = DmAttachmentRef(rawCidOf(blob), "r.txt", "text/plain", 2, enc.key)
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
                    val response = client.get("/api/dm/attachment/${hexOf(peer)}/${remote.cid}")
                    response.status shouldBe HttpStatusCode.ServiceUnavailable
                    response.bodyAsText() shouldBe """{"error":"anonymity-not-ready"}"""
                    h.storage.putUnserved(blob)
                    client.get("/api/dm/attachment/${hexOf(peer)}/${remote.cid}").bodyAsText() shouldBe "zz"
                }
            } finally {
                h.stop()
            }
        }
    })
