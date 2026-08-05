package net.lapisphilosophorum.lapisnet.browser

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.ktor.client.request.get
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
import net.lapisphilosophorum.lapisnet.mail.InboxGossip
import net.lapisphilosophorum.lapisnet.mail.MailSender
import net.lapisphilosophorum.lapisnet.mail.SentFolder
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import net.lapisphilosophorum.lapisnet.trust.VeritasGossip
import net.lapisphilosophorum.lapisnet.virtus.LtrGossip
import java.nio.file.Files
import java.util.Base64

private val json = Json { ignoreUnknownKeys = true }

/** Mirrors [BrowserApiRoutingTest]'s own `TestHarness` exactly - duplicated locally (rather than
 * shared) because that class is `private` to its own file. A single, never-connected [LapisNode] is
 * enough for every test in this file: `POST /api/mail` persists+publishes locally (gossip `publish`
 * is a documented no-op with zero mesh peers), and every route this file exercises only ever reads
 * back what THIS SAME node's own [InboxGossip]/[SentFolder] instances already hold - no real network
 * exercise needed (see [TwoNodeMailBrowserIntegrationTest] for the real two-node, real-gossip
 * proof). */
private class MailTestHarness(
    val identity: DualKeyIdentity = DualKeyIdentity.generate(),
) {
    val node: LapisNode = LapisNode.create(identity)
    val storage: NabuStorage
    val pubsub: GossipPubSub
    val veritas: VeritasGossip
    val virtus: LtrGossip
    val karma: KarmaGossip
    val posts: PostAnnouncementGossip
    val karmaAnchorCache: KarmaAnchorCache
    val mailInbox: InboxGossip
    val mailSender: MailSender
    val sentFolder: SentFolder
    val deps: BrowserApiDependencies

    init {
        node.start(bootstrapPeers = emptyList())
        storage = NabuStorage.attach(node, Files.createTempDirectory("browser-api-mail-routing-test"))
        pubsub = GossipPubSub.attach(node)
        veritas = VeritasGossip.attach(pubsub, storage)
        virtus = LtrGossip.attach(pubsub, storage)
        karma = KarmaGossip.attach(pubsub, storage)
        posts = PostAnnouncementGossip.attach(pubsub, storage)
        karmaAnchorCache = KarmaAnchorCache(MailTestNoAnchorSource)
        mailInbox = InboxGossip.attach(pubsub, storage, identity.secp256k1KeyPair.publicKey)
        mailSender = MailSender(pubsub, storage)
        sentFolder = SentFolder()
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
            )
    }

    fun stop() {
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

private object MailTestNoAnchorSource : BitcoinTimeAnchorSource {
    override fun findFirstOutgoingTransaction(pubkey: Secp256k1PublicKey): TimeAnchorLookupResult =
        TimeAnchorLookupResult.NotFound

    override fun currentChainTipHeight(): Int = 0
}

private fun recipientHexFor(identity: DualKeyIdentity): String =
    identity.secp256k1KeyPair.publicKey.bytes
        .joinToString("") { "%02x".format(it) }

/** RFC 2616 §2.2 separator set that [io.ktor.http.HeaderValueWithParameters]'s private
 * `needQuotes()`/`quoteTo()` pair uses to decide whether a header parameter value must be
 * quoted-and-escaped. Reproduced here (Ktor 3.5.1's `HeaderValueWithParameters.kt`) purely to
 * compute the INDEPENDENTLY expected `Content-Disposition` header string for a crafted attachment
 * name - not to test Ktor itself, but to pin down exactly what "correctly escaped" means for the
 * assertion below, so a future Ktor upgrade that silently changed this escaping would fail this
 * test loudly instead of leaving the header-injection question unverified. */
private val HEADER_VALUE_SEPARATORS =
    setOf('(', ')', '<', '>', '@', ',', ';', ':', '\\', '"', '/', '[', ']', '?', '=', '{', '}', ' ', '\t', '\n', '\r')

private fun expectedContentDispositionFileNameParameter(rawName: String): String {
    val needsQuotes = rawName.isEmpty() || rawName.any { it in HEADER_VALUE_SEPARATORS }
    if (!needsQuotes) return "attachment; filename=$rawName"
    val escaped =
        buildString {
            append('"')
            for (ch in rawName) {
                when (ch) {
                    '\\' -> append("\\\\")
                    '\n' -> append("\\n")
                    '\r' -> append("\\r")
                    '\t' -> append("\\t")
                    '"' -> append("\\\"")
                    else -> append(ch)
                }
            }
            append('"')
        }
    return "attachment; filename=$escaped"
}

class BrowserApiMailRoutingTest :
    FunSpec({
        test("GET /api/mail is empty, POST /api/mail round-trips into GET /api/mail/sent") {
            val harness = MailTestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }

                    val emptyInbox = client.get("/api/mail")
                    json.decodeFromString<List<MailSummaryResponse>>(emptyInbox.bodyAsText()) shouldBe emptyList()
                    val emptySent = client.get("/api/mail/sent")
                    json.decodeFromString<List<MailSummaryResponse>>(emptySent.bodyAsText()) shouldBe emptyList()

                    val recipient = DualKeyIdentity.generate()
                    val response =
                        client.post("/api/mail") {
                            contentType(ContentType.Application.Json)
                            setBody(
                                json.encodeToString(
                                    NewMailRequest(
                                        recipientsHex = listOf(recipientHexFor(recipient)),
                                        subject = "hello",
                                        body = "# hi\n\nfrom the routing test",
                                    ),
                                ),
                            )
                        }
                    response.status shouldBe HttpStatusCode.OK
                    val posted = json.decodeFromString<NewMailResponse>(response.bodyAsText())
                    posted.cid.isNotBlank() shouldBe true

                    // Never appears in /api/mail (no self-delivery, no gossip round trip in this
                    // single-node harness) - only /api/mail/sent, populated synchronously by the
                    // same POST /api/mail call.
                    val inboxAfter = client.get("/api/mail")
                    json.decodeFromString<List<MailSummaryResponse>>(inboxAfter.bodyAsText()) shouldBe emptyList()

                    val sentAfter = client.get("/api/mail/sent")
                    val sentEntries = json.decodeFromString<List<MailSummaryResponse>>(sentAfter.bodyAsText())
                    sentEntries.size shouldBe 1
                    val entry = sentEntries.single()
                    entry.cid shouldBe posted.cid
                    entry.folder shouldBe "sent"
                    entry.subject shouldBe "hello"
                    entry.bodyPreview shouldBe "# hi\n\nfrom the routing test"
                    entry.decryptionFailed shouldBe false
                    entry.encryption shouldBe "NONE"
                }
            } finally {
                harness.stop()
            }
        }

        test("POST /api/mail with HYBRID_ECIES encryption round-trips a readable plaintext view in /api/mail/sent") {
            val harness = MailTestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }

                    val recipient = DualKeyIdentity.generate()
                    val response =
                        client.post("/api/mail") {
                            contentType(ContentType.Application.Json)
                            setBody(
                                json.encodeToString(
                                    NewMailRequest(
                                        recipientsHex = listOf(recipientHexFor(recipient)),
                                        subject = "secret",
                                        body = "encrypted content",
                                        encryption = "HYBRID_ECIES",
                                    ),
                                ),
                            )
                        }
                    response.status shouldBe HttpStatusCode.OK

                    val sentEntries =
                        json.decodeFromString<List<MailSummaryResponse>>(client.get("/api/mail/sent").bodyAsText())
                    sentEntries.size shouldBe 1
                    val entry = sentEntries.single()
                    entry.encryption shouldBe "HYBRID_ECIES"
                    entry.decryptionFailed shouldBe false
                    entry.subject shouldBe "secret"
                    entry.bodyPreview shouldBe "encrypted content"
                }
            } finally {
                harness.stop()
            }
        }

        test("POST /api/mail rejects an invalid recipient hex with 400") {
            val harness = MailTestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }
                    val response =
                        client.post("/api/mail") {
                            contentType(ContentType.Application.Json)
                            setBody(
                                json.encodeToString(
                                    NewMailRequest(recipientsHex = listOf("not-hex"), subject = "s", body = "b"),
                                ),
                            )
                        }
                    response.status shouldBe HttpStatusCode.BadRequest
                }
            } finally {
                harness.stop()
            }
        }

        test("POST /api/mail rejects an empty recipient list with 400") {
            val harness = MailTestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }
                    val response =
                        client.post("/api/mail") {
                            contentType(ContentType.Application.Json)
                            setBody(
                                json.encodeToString(
                                    NewMailRequest(recipientsHex = emptyList(), subject = "s", body = "b"),
                                ),
                            )
                        }
                    response.status shouldBe HttpStatusCode.BadRequest
                }
            } finally {
                harness.stop()
            }
        }

        test("POST /api/mail rejects an unknown encryption string with 400") {
            val harness = MailTestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }
                    val recipient = DualKeyIdentity.generate()
                    val response =
                        client.post("/api/mail") {
                            contentType(ContentType.Application.Json)
                            setBody(
                                json.encodeToString(
                                    NewMailRequest(
                                        recipientsHex = listOf(recipientHexFor(recipient)),
                                        subject = "s",
                                        body = "b",
                                        encryption = "ROT13",
                                    ),
                                ),
                            )
                        }
                    response.status shouldBe HttpStatusCode.BadRequest
                }
            } finally {
                harness.stop()
            }
        }

        test("POST /api/mail explicitly rejects MLS_ARCHIVE with 400") {
            val harness = MailTestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }
                    val recipient = DualKeyIdentity.generate()
                    val response =
                        client.post("/api/mail") {
                            contentType(ContentType.Application.Json)
                            setBody(
                                json.encodeToString(
                                    NewMailRequest(
                                        recipientsHex = listOf(recipientHexFor(recipient)),
                                        subject = "s",
                                        body = "b",
                                        encryption = "MLS_ARCHIVE",
                                    ),
                                ),
                            )
                        }
                    response.status shouldBe HttpStatusCode.BadRequest
                }
            } finally {
                harness.stop()
            }
        }

        test("POST /api/mail rejects an oversized subject with 400") {
            val harness = MailTestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }
                    val recipient = DualKeyIdentity.generate()
                    val response =
                        client.post("/api/mail") {
                            contentType(ContentType.Application.Json)
                            setBody(
                                json.encodeToString(
                                    NewMailRequest(
                                        recipientsHex = listOf(recipientHexFor(recipient)),
                                        subject = "x".repeat(600),
                                        body = "b",
                                    ),
                                ),
                            )
                        }
                    response.status shouldBe HttpStatusCode.BadRequest
                }
            } finally {
                harness.stop()
            }
        }

        test("POST /api/mail rejects an oversized body with 400") {
            val harness = MailTestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }
                    val recipient = DualKeyIdentity.generate()
                    val response =
                        client.post("/api/mail") {
                            contentType(ContentType.Application.Json)
                            setBody(
                                json.encodeToString(
                                    NewMailRequest(
                                        recipientsHex = listOf(recipientHexFor(recipient)),
                                        subject = "s",
                                        body = "x".repeat(40_000),
                                    ),
                                ),
                            )
                        }
                    response.status shouldBe HttpStatusCode.BadRequest
                }
            } finally {
                harness.stop()
            }
        }

        test("POST /api/mail rejects too many attachments with 400") {
            val harness = MailTestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }
                    val recipient = DualKeyIdentity.generate()
                    val tooMany =
                        (1..20).map {
                            NewMailAttachmentRequest(name = "a$it.txt", mime = "text/plain", contentBase64 = "AAAA")
                        }
                    val response =
                        client.post("/api/mail") {
                            contentType(ContentType.Application.Json)
                            setBody(
                                json.encodeToString(
                                    NewMailRequest(
                                        recipientsHex = listOf(recipientHexFor(recipient)),
                                        subject = "s",
                                        body = "b",
                                        attachments = tooMany,
                                    ),
                                ),
                            )
                        }
                    response.status shouldBe HttpStatusCode.BadRequest
                }
            } finally {
                harness.stop()
            }
        }

        test("POST /api/mail rejects an oversized attachment name with 400") {
            val harness = MailTestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }
                    val recipient = DualKeyIdentity.generate()
                    val response =
                        client.post("/api/mail") {
                            contentType(ContentType.Application.Json)
                            setBody(
                                json.encodeToString(
                                    NewMailRequest(
                                        recipientsHex = listOf(recipientHexFor(recipient)),
                                        subject = "s",
                                        body = "b",
                                        attachments =
                                            listOf(
                                                NewMailAttachmentRequest(
                                                    name = "a".repeat(200),
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
            } finally {
                harness.stop()
            }
        }

        test("POST /api/mail rejects an oversized attachment mime with 400") {
            val harness = MailTestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }
                    val recipient = DualKeyIdentity.generate()
                    val response =
                        client.post("/api/mail") {
                            contentType(ContentType.Application.Json)
                            setBody(
                                json.encodeToString(
                                    NewMailRequest(
                                        recipientsHex = listOf(recipientHexFor(recipient)),
                                        subject = "s",
                                        body = "b",
                                        attachments =
                                            listOf(
                                                NewMailAttachmentRequest(
                                                    name = "a.txt",
                                                    mime = "x".repeat(100),
                                                    contentBase64 = "AAAA",
                                                ),
                                            ),
                                    ),
                                ),
                            )
                        }
                    response.status shouldBe HttpStatusCode.BadRequest
                }
            } finally {
                harness.stop()
            }
        }

        test("POST /api/mail rejects malformed base64 attachment content with 400") {
            val harness = MailTestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }
                    val recipient = DualKeyIdentity.generate()
                    val response =
                        client.post("/api/mail") {
                            contentType(ContentType.Application.Json)
                            setBody(
                                json.encodeToString(
                                    NewMailRequest(
                                        recipientsHex = listOf(recipientHexFor(recipient)),
                                        subject = "s",
                                        body = "b",
                                        attachments =
                                            listOf(
                                                NewMailAttachmentRequest(
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
            } finally {
                harness.stop()
            }
        }

        test("POST /api/mail rejects a malformed replyToCid with 400") {
            val harness = MailTestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }
                    val recipient = DualKeyIdentity.generate()
                    val response =
                        client.post("/api/mail") {
                            contentType(ContentType.Application.Json)
                            setBody(
                                json.encodeToString(
                                    NewMailRequest(
                                        recipientsHex = listOf(recipientHexFor(recipient)),
                                        subject = "s",
                                        body = "b",
                                        replyToCid = "not-a-cid",
                                    ),
                                ),
                            )
                        }
                    response.status shouldBe HttpStatusCode.BadRequest
                }
            } finally {
                harness.stop()
            }
        }

        test("POST /api/mail rejects a malformed threadRootCid with 400") {
            val harness = MailTestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }
                    val recipient = DualKeyIdentity.generate()
                    val response =
                        client.post("/api/mail") {
                            contentType(ContentType.Application.Json)
                            setBody(
                                json.encodeToString(
                                    NewMailRequest(
                                        recipientsHex = listOf(recipientHexFor(recipient)),
                                        subject = "s",
                                        body = "b",
                                        threadRootCid = "not-a-cid",
                                    ),
                                ),
                            )
                        }
                    response.status shouldBe HttpStatusCode.BadRequest
                }
            } finally {
                harness.stop()
            }
        }

        test("GET /api/mail/thread/{cid} 404s for an unknown (but structurally valid) cid") {
            val harness = MailTestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }
                    // A real, validly-formed CID that was never referenced as any envelope's
                    // contentCid - never present in any thread, but still parses successfully, so
                    // this exercises the 404 branch specifically, not the 400/malformed-cid branch.
                    val unknownCid = harness.storage.put("never part of any thread".toByteArray())
                    val response = client.get("/api/mail/thread/$unknownCid")
                    response.status shouldBe HttpStatusCode.NotFound
                }
            } finally {
                harness.stop()
            }
        }

        test("GET /api/mail/thread/{cid} 400s for a malformed cid") {
            val harness = MailTestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }
                    val response = client.get("/api/mail/thread/not-a-cid-at-all")
                    response.status shouldBe HttpStatusCode.BadRequest
                }
            } finally {
                harness.stop()
            }
        }

        test("GET /api/mail/thread/{cid} assembles a real self-composed reply chain with correct depth/children") {
            val harness = MailTestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }
                    val recipient = DualKeyIdentity.generate()

                    val rootResponse =
                        client.post("/api/mail") {
                            contentType(ContentType.Application.Json)
                            setBody(
                                json.encodeToString(
                                    NewMailRequest(
                                        recipientsHex = listOf(recipientHexFor(recipient)),
                                        subject = "root",
                                        body = "root body",
                                    ),
                                ),
                            )
                        }
                    val rootCid = json.decodeFromString<NewMailResponse>(rootResponse.bodyAsText()).cid

                    val replyResponse =
                        client.post("/api/mail") {
                            contentType(ContentType.Application.Json)
                            setBody(
                                json.encodeToString(
                                    NewMailRequest(
                                        recipientsHex = listOf(recipientHexFor(recipient)),
                                        subject = "Re: root",
                                        body = "reply body",
                                        replyToCid = rootCid,
                                    ),
                                ),
                            )
                        }
                    replyResponse.status shouldBe HttpStatusCode.OK

                    val threadResponse = client.get("/api/mail/thread/$rootCid")
                    threadResponse.status shouldBe HttpStatusCode.OK
                    val thread = json.decodeFromString<MailThreadNodeResponse>(threadResponse.bodyAsText())
                    thread.summary.cid shouldBe rootCid
                    thread.depth shouldBe 0
                    thread.children.size shouldBe 1
                    thread.children
                        .single()
                        .summary.subject shouldBe "Re: root"
                    thread.children.single().depth shouldBe 1
                }
            } finally {
                harness.stop()
            }
        }

        test("GET /api/mail/attachment/{cid} 404s for an unknown (but structurally valid) cid") {
            val harness = MailTestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }
                    val unknownCid = harness.storage.put("never part of any attachment".toByteArray())
                    val response = client.get("/api/mail/attachment/$unknownCid")
                    response.status shouldBe HttpStatusCode.NotFound
                }
            } finally {
                harness.stop()
            }
        }

        test("GET /api/mail/attachment/{cid} round-trips a real self-composed unencrypted attachment") {
            val harness = MailTestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }
                    val recipient = DualKeyIdentity.generate()
                    val contentBase64 = Base64.getEncoder().encodeToString("hello attachment".toByteArray())

                    val sendResponse =
                        client.post("/api/mail") {
                            contentType(ContentType.Application.Json)
                            setBody(
                                json.encodeToString(
                                    NewMailRequest(
                                        recipientsHex = listOf(recipientHexFor(recipient)),
                                        subject = "with attachment",
                                        body = "see attached",
                                        attachments =
                                            listOf(
                                                NewMailAttachmentRequest(
                                                    name = "note.txt",
                                                    mime = "text/plain",
                                                    contentBase64 = contentBase64,
                                                    encrypt = false,
                                                ),
                                            ),
                                    ),
                                ),
                            )
                        }
                    sendResponse.status shouldBe HttpStatusCode.OK

                    val sentEntries =
                        json.decodeFromString<List<MailSummaryResponse>>(client.get("/api/mail/sent").bodyAsText())
                    val attachment = sentEntries.single().attachments.single()
                    attachment.encrypted shouldBe false

                    val fetchResponse = client.get("/api/mail/attachment/${attachment.cid}")
                    fetchResponse.status shouldBe HttpStatusCode.OK
                    fetchResponse.bodyAsText() shouldBe "hello attachment"
                }
            } finally {
                harness.stop()
            }
        }

        test(
            "GET /api/mail/attachment/{cid} round-trips a real self-composed ENCRYPTED attachment, correctly decrypted",
        ) {
            val harness = MailTestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }
                    val recipient = DualKeyIdentity.generate()
                    val contentBase64 = Base64.getEncoder().encodeToString("top secret attachment".toByteArray())

                    val sendResponse =
                        client.post("/api/mail") {
                            contentType(ContentType.Application.Json)
                            setBody(
                                json.encodeToString(
                                    NewMailRequest(
                                        recipientsHex = listOf(recipientHexFor(recipient)),
                                        subject = "with encrypted attachment",
                                        body = "see attached (encrypted)",
                                        attachments =
                                            listOf(
                                                NewMailAttachmentRequest(
                                                    name = "secret.txt",
                                                    mime = "text/plain",
                                                    contentBase64 = contentBase64,
                                                    encrypt = true,
                                                ),
                                            ),
                                    ),
                                ),
                            )
                        }
                    sendResponse.status shouldBe HttpStatusCode.OK

                    val sentEntries =
                        json.decodeFromString<List<MailSummaryResponse>>(client.get("/api/mail/sent").bodyAsText())
                    val attachment = sentEntries.single().attachments.single()
                    attachment.encrypted shouldBe true

                    val fetchResponse = client.get("/api/mail/attachment/${attachment.cid}")
                    fetchResponse.status shouldBe HttpStatusCode.OK
                    fetchResponse.bodyAsText() shouldBe "top secret attachment"
                }
            } finally {
                harness.stop()
            }
        }

        test(
            "GET /api/mail/attachment/{cid} escapes a crafted attachment name in Content-Disposition " +
                "instead of allowing header injection",
        ) {
            val harness = MailTestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }
                    val recipient = DualKeyIdentity.generate()
                    val contentBase64 = Base64.getEncoder().encodeToString("attacker-controlled name".toByteArray())

                    // Contains every character MailApi.kt's own doc comment flags as unvalidated
                    // (name is byte-length-checked only, never character-restricted): a double
                    // quote and a backslash (both would let a naively-concatenated header value
                    // "escape" the filename="..." parameter), and a CRLF pair immediately followed
                    // by a syntactically valid extra header line and a Set-Cookie line - the classic
                    // HTTP response-splitting/header-injection shape. Comfortably under
                    // MessageBodyCodec.MAX_ATTACHMENT_NAME_BYTES (128 UTF-8 bytes).
                    val craftedName =
                        "evil\".txt\\backslash\r\nX-Injected-Header: hacked\r\nSet-Cookie: sess=hijacked\r\n"

                    val sendResponse =
                        client.post("/api/mail") {
                            contentType(ContentType.Application.Json)
                            setBody(
                                json.encodeToString(
                                    NewMailRequest(
                                        recipientsHex = listOf(recipientHexFor(recipient)),
                                        subject = "attachment header-injection regression",
                                        body = "see attached",
                                        attachments =
                                            listOf(
                                                NewMailAttachmentRequest(
                                                    name = craftedName,
                                                    mime = "text/plain",
                                                    contentBase64 = contentBase64,
                                                ),
                                            ),
                                    ),
                                ),
                            )
                        }
                    sendResponse.status shouldBe HttpStatusCode.OK

                    val sentEntries =
                        json.decodeFromString<List<MailSummaryResponse>>(client.get("/api/mail/sent").bodyAsText())
                    val attachment = sentEntries.single().attachments.single()
                    attachment.name shouldBe craftedName

                    val fetchResponse = client.get("/api/mail/attachment/${attachment.cid}")
                    fetchResponse.status shouldBe HttpStatusCode.OK

                    // 1. Exactly one Content-Disposition header - if the CRLF pairs above had
                    // survived into the raw response unescaped, this would instead have produced
                    // either a malformed/split response or additional (possibly duplicated) headers.
                    val contentDispositionValues = fetchResponse.headers.getAll(HttpHeaders.ContentDisposition)
                    contentDispositionValues?.size shouldBe 1
                    val contentDispositionValue = contentDispositionValues!!.single()

                    // 2. The header value contains no raw CR or LF byte at all - the crafted CRLFs
                    // were consumed into escape sequences, not carried through verbatim. This is the
                    // actual injection-blocking property: a raw CR/LF here is what would let an
                    // attacker start a new header (or a new response) inside this single header write.
                    contentDispositionValue.contains('\r') shouldBe false
                    contentDispositionValue.contains('\n') shouldBe false

                    // 3. The injected header/cookie lines never became real, separate response
                    // headers.
                    fetchResponse.headers["X-Injected-Header"].shouldBeNull()
                    fetchResponse.headers["Set-Cookie"].shouldBeNull()

                    // 4. The header is exactly what Ktor's own quoting discipline is documented to
                    // produce for this input (see expectedContentDispositionFileNameParameter's doc
                    // comment) - not merely "harmless", but byte-for-byte the correctly escaped form:
                    // the quote and backslash are backslash-escaped in place, and both CRLF pairs are
                    // rewritten to the literal two-character `\r\n` mnemonic sequences rather than
                    // surviving as raw bytes.
                    contentDispositionValue shouldBe expectedContentDispositionFileNameParameter(craftedName)
                }
            } finally {
                harness.stop()
            }
        }
    })
