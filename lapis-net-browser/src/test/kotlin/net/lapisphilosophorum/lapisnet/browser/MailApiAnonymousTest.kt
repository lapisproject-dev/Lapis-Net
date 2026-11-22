package net.lapisphilosophorum.lapisnet.browser

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
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
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.karma.BitcoinTimeAnchorSource
import net.lapisphilosophorum.lapisnet.karma.KarmaGossip
import net.lapisphilosophorum.lapisnet.karma.TimeAnchorLookupResult
import net.lapisphilosophorum.lapisnet.mail.AnonymousMailSizeClass
import net.lapisphilosophorum.lapisnet.mail.AnonymousMailSizing
import net.lapisphilosophorum.lapisnet.mail.AnonymousMailTransport
import net.lapisphilosophorum.lapisnet.mail.AttachmentRef
import net.lapisphilosophorum.lapisnet.mail.InboxGossip
import net.lapisphilosophorum.lapisnet.mail.MailAnonymousDeliveryException
import net.lapisphilosophorum.lapisnet.mail.MailAnonymousFailure
import net.lapisphilosophorum.lapisnet.mail.MailFrameCodec
import net.lapisphilosophorum.lapisnet.mail.MailSender
import net.lapisphilosophorum.lapisnet.mail.MessageBody
import net.lapisphilosophorum.lapisnet.mail.MessageBodyCodec
import net.lapisphilosophorum.lapisnet.mail.MessageEnvelope
import net.lapisphilosophorum.lapisnet.mail.MessageEnvelopeCodec
import net.lapisphilosophorum.lapisnet.mail.SentFolder
import net.lapisphilosophorum.lapisnet.mail.SentMessage
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import net.lapisphilosophorum.lapisnet.trust.VeritasGossip
import net.lapisphilosophorum.lapisnet.virtus.LtrGossip
import java.nio.file.Files
import java.util.Base64
import java.util.concurrent.atomic.AtomicInteger

private val mailJson = Json { ignoreUnknownKeys = true }

private object NoAnchors : BitcoinTimeAnchorSource {
    override fun findFirstOutgoingTransaction(pubkey: Secp256k1PublicKey): TimeAnchorLookupResult =
        TimeAnchorLookupResult.NotFound

    override fun currentChainTipHeight(): Int = 0
}

private class ScriptedMailTransport : AnonymousMailTransport {
    @Volatile var failure: MailAnonymousFailure? = null
    val preflights = AtomicInteger()
    val deliveries = AtomicInteger()

    override fun preflight(
        recipients: List<Secp256k1PublicKey>,
        frameBytes: Int,
        attachmentBlobSizes: List<Int>,
    ): AnonymousMailSizeClass {
        preflights.incrementAndGet()
        failure?.let { throw MailAnonymousDeliveryException(it) }
        return AnonymousMailSizing.classify(frameBytes, attachmentBlobSizes)
    }

    override fun deliver(
        recipients: List<Secp256k1PublicKey>,
        frameBytes: ByteArray,
        attachmentBlobs: List<ByteArray>,
        sizeClass: AnonymousMailSizeClass,
    ) {
        deliveries.incrementAndGet()
    }

    override fun close() = Unit
}

private class MailAnonHarness(
    /** Wave Q21: the scripted fetch over circuits for attachments that are not local. */
    val client: ScriptedAttachmentClient = ScriptedAttachmentClient(),
) {
    val identity = DualKeyIdentity.generate()
    val node: LapisNode = LapisNode.create(identity).also { it.start(bootstrapPeers = emptyList()) }
    val storage: NabuStorage = NabuStorage.attach(node, Files.createTempDirectory("mail-api-anon"))
    val pubsub: GossipPubSub = GossipPubSub.attach(node)
    val veritas = VeritasGossip.attach(pubsub, storage)
    val virtus = LtrGossip.attach(pubsub, storage)
    val karma = KarmaGossip.attach(pubsub, storage)
    val posts = PostAnnouncementGossip.attach(pubsub, storage)
    val mailInbox = InboxGossip.attachAnonymous(pubsub, storage, identity.secp256k1KeyPair.publicKey)
    val sentFolder = SentFolder()
    val transport = ScriptedMailTransport()
    val mailSender = MailSender(pubsub, storage, anonymous = true).also { it.installAnonymousTransport(transport) }
    val deps =
        BrowserApiDependencies(
            identity,
            node,
            storage,
            veritas,
            virtus,
            karma,
            posts,
            KarmaAnchorCache(NoAnchors),
            mailInbox,
            mailSender,
            sentFolder,
            anonymityActive = true,
            anonymousAttachments = AnonymousAttachmentFetcher(NabuAttachmentBlobStore(storage), { client }),
        )

    fun stop() {
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

class MailApiAnonymousTest :
    FunSpec({
        test("every refusal has a fixed body and status; recipients are never echoed") {
            val h = MailAnonHarness()
            try {
                val recipient = hexOf(DualKeyIdentity.generate().secp256k1KeyPair.publicKey)
                testApplication {
                    application { installBrowserApi(h.deps) }
                    for (
                    (failure, status) in
                    listOf(
                        MailAnonymousFailure.RECIPIENT_NOT_REACHABLE_ANONYMOUSLY to HttpStatusCode.ServiceUnavailable,
                        MailAnonymousFailure.ANONYMITY_NOT_READY to HttpStatusCode.ServiceUnavailable,
                        MailAnonymousFailure.MAIL_TOO_LARGE_ANONYMOUS to HttpStatusCode.PayloadTooLarge,
                        MailAnonymousFailure.ATTACHMENTS_UNAVAILABLE_ANONYMOUS to HttpStatusCode.Conflict,
                    )
                    ) {
                        h.transport.failure = failure
                        val response =
                            client.post("/api/mail") {
                                contentType(ContentType.Application.Json)
                                setBody(mailJson.encodeToString(NewMailRequest(listOf(recipient), "s", "b")))
                            }
                        response.status shouldBe status
                        val text = response.bodyAsText()
                        text shouldBe """{"error":"${failure.wire}"}"""
                        text shouldNotContain recipient.take(12)
                    }
                }
                h.transport.deliveries.get() shouldBe 0
                h.sentFolder.latest().size shouldBe 0
            } finally {
                h.stop()
            }
        }

        test("an accepted send answers the same whatever happens afterwards and lands in the sent folder") {
            val h = MailAnonHarness()
            try {
                val recipient = hexOf(DualKeyIdentity.generate().secp256k1KeyPair.publicKey)
                testApplication {
                    application { installBrowserApi(h.deps) }
                    val response =
                        client.post("/api/mail") {
                            contentType(ContentType.Application.Json)
                            setBody(
                                mailJson.encodeToString(
                                    NewMailRequest(listOf(recipient), "s", "b", encryption = "HYBRID_ECIES"),
                                ),
                            )
                        }
                    response.status shouldBe HttpStatusCode.OK
                }
                h.transport.deliveries.get() shouldBe 1
                h.sentFolder.latest().size shouldBe 1
            } finally {
                h.stop()
            }
        }

        test("an upload above 1 MiB is refused with 413 before it is decoded, stored or handed to the transport") {
            val h = MailAnonHarness()
            try {
                val recipient = hexOf(DualKeyIdentity.generate().secp256k1KeyPair.publicKey)
                val big =
                    Base64.getEncoder().encodeToString(
                        ByteArray(
                            AnonymousMailSizing.MAX_CIRCUIT_BUNDLE_BYTES + 1024,
                        ) { 1 },
                    )
                testApplication {
                    application { installBrowserApi(h.deps) }
                    val response =
                        client.post("/api/mail") {
                            contentType(ContentType.Application.Json)
                            setBody(
                                mailJson.encodeToString(
                                    NewMailRequest(
                                        listOf(recipient),
                                        "s",
                                        "b",
                                        attachments =
                                            listOf(
                                                NewMailAttachmentRequest("big.bin", "application/octet-stream", big),
                                            ),
                                    ),
                                ),
                            )
                        }
                    response.status shouldBe HttpStatusCode.PayloadTooLarge
                    response.bodyAsText() shouldBe """{"error":"mail-too-large-anonymous"}"""
                }
                h.transport.preflights.get() shouldBe 0
            } finally {
                h.stop()
            }
        }

        test("an attachment that is local is served; one that is not is 404 at once, without any network lookup") {
            val h = MailAnonHarness()
            try {
                val recipient = hexOf(DualKeyIdentity.generate().secp256k1KeyPair.publicKey)
                val content = "attachment bytes".toByteArray()
                val foreign = MessageBodyCodec.cidFor(ByteArray(64) { 42 })
                val foreignBody =
                    MessageBody("f", "b", listOf(AttachmentRef(foreign, "remote.bin", "application/octet-stream", 64)))
                val bodyBytes = MessageBodyCodec.encode(foreignBody)
                val envelope =
                    MessageEnvelope.create(
                        h.identity.secp256k1KeyPair,
                        listOf(h.identity.secp256k1KeyPair.publicKey),
                        MessageBodyCodec.cidFor(bodyBytes),
                    )
                val envelopeBytes = MessageEnvelopeCodec.encode(envelope)
                h.sentFolder.add(
                    SentMessage(
                        envelope,
                        foreignBody,
                        MessageBodyCodec.cidFor(bodyBytes),
                        null,
                        MailFrameCodec.encode(envelopeBytes, bodyBytes),
                    ),
                )
                testApplication {
                    application { installBrowserApi(h.deps) }
                    val sent =
                        client.post("/api/mail") {
                            contentType(ContentType.Application.Json)
                            setBody(
                                mailJson.encodeToString(
                                    NewMailRequest(
                                        listOf(recipient),
                                        "s",
                                        "b",
                                        attachments =
                                            listOf(
                                                NewMailAttachmentRequest(
                                                    "a.txt",
                                                    "text/plain",
                                                    Base64.getEncoder().encodeToString(content),
                                                ),
                                            ),
                                    ),
                                ),
                            )
                        }
                    sent.status shouldBe HttpStatusCode.OK
                    val localCid = MessageBodyCodec.cidFor(content).toString()
                    val served = client.get("/api/mail/attachment/$localCid")
                    served.status shouldBe HttpStatusCode.OK
                    served.bodyAsText() shouldBe "attachment bytes"

                    val started = System.nanoTime()
                    val missing = client.get("/api/mail/attachment/$foreign")
                    missing.status shouldBe HttpStatusCode.NotFound
                    missing.bodyAsText() shouldBe """{"error":"attachments-unavailable-anonymous"}"""
                    // a provider lookup / Bitswap round would take far longer than this
                    ((System.nanoTime() - started) / 1_000_000 < 3_000) shouldBe true
                }
            } finally {
                h.stop()
            }
        }

        // Wave Q21: an encrypted attachment that is not local is fetched from the mail's sender (envelope.sender) over
        // circuits. The message is put into the sent folder with a FOREIGN sender only to reach the route without a
        // network; the inbox path runs through the same code (the first message that names the CID wins).
        test("not local: the fetcher is asked with envelope.sender; without a key: 404 and no network at all") {
            val h = MailAnonHarness()
            try {
                val sender = DualKeyIdentity.generate()
                val plaintext = "mail attachment".toByteArray()
                val encrypted =
                    net.lapisphilosophorum.lapisnet.mail.MailAttachmentCipher
                        .encrypt(plaintext)
                val blob =
                    net.lapisphilosophorum.lapisnet.mail.EncryptedAttachmentBlobCodec
                        .encode(encrypted.blob)
                val encryptedRef =
                    AttachmentRef(
                        rawCidOf(blob),
                        "m.txt",
                        "text/plain",
                        plaintext.size.toLong(),
                        encryptionKey = encrypted.key,
                    )
                val plainRef = AttachmentRef(rawCidOf(ByteArray(64) { 5 }), "p.bin", "application/octet-stream", 64)
                val body = MessageBody("s", "b", listOf(encryptedRef, plainRef))
                val bodyBytes = MessageBodyCodec.encode(body)
                val envelope =
                    MessageEnvelope.create(
                        sender.secp256k1KeyPair,
                        listOf(h.identity.secp256k1KeyPair.publicKey),
                        MessageBodyCodec.cidFor(bodyBytes),
                    )
                h.sentFolder.add(
                    SentMessage(
                        envelope,
                        body,
                        MessageBodyCodec.cidFor(bodyBytes),
                        null,
                        MailFrameCodec.encode(MessageEnvelopeCodec.encode(envelope), bodyBytes),
                    ),
                )
                testApplication {
                    application { installBrowserApi(h.deps) }
                    // Security (Q21): a cross-site subresource or a foreign Origin must not trigger the onion fetch.
                    h.client.next =
                        net.lapisphilosophorum.lapisnet.dmonion.attachment.AttachmentFetchResult
                            .Found(blob)
                    val crossUrl = "/api/mail/attachment/${encryptedRef.cid}"
                    client.get(crossUrl) { header("Sec-Fetch-Site", "cross-site") }.status shouldBe
                        HttpStatusCode.Forbidden
                    client.get(crossUrl) { header(HttpHeaders.Origin, "https://attacker.example") }.status shouldBe
                        HttpStatusCode.Forbidden
                    h.client.calls.get() shouldBe 0
                    val plain = client.get("/api/mail/attachment/${plainRef.cid}")
                    plain.status shouldBe HttpStatusCode.NotFound
                    plain.bodyAsText() shouldBe """{"error":"attachments-unavailable-anonymous"}"""
                    h.client.calls.get() shouldBe 0

                    h.client.next =
                        net.lapisphilosophorum.lapisnet.dmonion.attachment.AttachmentFetchResult.Unavailable(
                            net.lapisphilosophorum.lapisnet.dmonion.attachment.AttachmentFetchFailure.TIMEOUT,
                        )
                    val slow = client.get("/api/mail/attachment/${encryptedRef.cid}")
                    slow.status shouldBe HttpStatusCode.GatewayTimeout
                    slow.bodyAsText() shouldBe """{"error":"attachment-fetch-timeout-anonymous"}"""

                    h.client.next =
                        net.lapisphilosophorum.lapisnet.dmonion.attachment.AttachmentFetchResult
                            .Found(blob)
                    val ok = client.get("/api/mail/attachment/${encryptedRef.cid}")
                    ok.status shouldBe HttpStatusCode.OK
                    ok.bodyAsText() shouldBe "mail attachment"
                    h.client.senders.toSet() shouldBe setOf(sender.secp256k1KeyPair.publicKey)
                    h.client.maxBytes.last() shouldBe
                        plaintext.size +
                        net.lapisphilosophorum.lapisnet.mail.EncryptedAttachmentBlobCodec.OVERHEAD_BYTES
                    h.storage.isServed(encryptedRef.cid) shouldBe false
                }
            } finally {
                h.stop()
            }
        }

        // Wave Q21 invariant (same as the DM send path): an attachment sent in anonymity mode is stored unserved, so it is
        // never answered over Bitswap/DHT, also not after a later restart in normal mode.
        test("outgoing mail attachments (encrypted and unencrypted) are stored unserved in anonymity mode") {
            val h = MailAnonHarness()
            try {
                val recipient = hexOf(DualKeyIdentity.generate().secp256k1KeyPair.publicKey)
                val plain = "plain attachment".toByteArray()
                val secret = "secret attachment".toByteArray()
                testApplication {
                    application { installBrowserApi(h.deps) }
                    val sent =
                        client.post("/api/mail") {
                            contentType(ContentType.Application.Json)
                            setBody(
                                mailJson.encodeToString(
                                    NewMailRequest(
                                        listOf(recipient),
                                        "s",
                                        "b",
                                        attachments =
                                            listOf(
                                                NewMailAttachmentRequest(
                                                    "p.txt",
                                                    "text/plain",
                                                    Base64.getEncoder().encodeToString(plain),
                                                ),
                                                NewMailAttachmentRequest(
                                                    "s.txt",
                                                    "text/plain",
                                                    Base64.getEncoder().encodeToString(secret),
                                                    encrypt = true,
                                                ),
                                            ),
                                    ),
                                ),
                            )
                        }
                    sent.status shouldBe HttpStatusCode.OK
                    val refs =
                        h.sentFolder
                            .latest()
                            .single()
                            .body.attachments
                    refs.size shouldBe 2
                    for (ref in refs) {
                        h.storage.isServed(ref.cid) shouldBe false
                        // still readable locally (the onion attachment server loads via getLocal)
                        val response = client.get("/api/mail/attachment/${ref.cid}")
                        response.status shouldBe HttpStatusCode.OK
                    }
                    refs.single { it.encryptionKey == null }.let {
                        client.get("/api/mail/attachment/${it.cid}").bodyAsText() shouldBe "plain attachment"
                    }
                    refs.single { it.encryptionKey != null }.let {
                        client.get("/api/mail/attachment/${it.cid}").bodyAsText() shouldBe "secret attachment"
                    }
                }
                h.client.calls.get() shouldBe 0
            } finally {
                h.stop()
            }
        }
    })
