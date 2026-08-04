package net.lapisphilosophorum.lapisnet.browser

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
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
import net.lapisphilosophorum.lapisnet.trust.VeritasGrant
import net.lapisphilosophorum.lapisnet.trust.VeritasGrantCodec
import net.lapisphilosophorum.lapisnet.virtus.LtrGossip
import java.nio.file.Files

private val json = Json { ignoreUnknownKeys = true }

/**
 * Sets up one real, never-connected [LapisNode] + [NabuStorage] + [GossipPubSub] +
 * [VeritasGossip]/[LtrGossip]/[PostAnnouncementGossip] - mirrors
 * [net.lapisphilosophorum.lapisnet.virtus.LtrGossipOnGossipMessageTest]'s established "a single,
 * never-connected node is enough" test seam (see that class's doc comment). No real network
 * exercise here at all - `announce()` calls just persist+index locally, gossip `publish()` is a
 * documented no-op with zero mesh peers (see [GossipPubSub.publish]'s doc comment), which is
 * exactly what "seed test data directly, no real network" means for this integration-shaped test.
 */
private class TestHarness(
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
        storage = NabuStorage.attach(node, Files.createTempDirectory("browser-api-routing-test"))
        pubsub = GossipPubSub.attach(node)
        veritas = VeritasGossip.attach(pubsub, storage)
        virtus = LtrGossip.attach(pubsub, storage)
        karma = KarmaGossip.attach(pubsub, storage)
        posts = PostAnnouncementGossip.attach(pubsub, storage)
        // NoAnchorSource: no real network I/O, always resolves NotFound - exactly what a fresh
        // test identity with no real Bitcoin history should resolve to (NoAnchorClaim), mirroring
        // KarmaAnchorCache's own doc comment on that being the correct, non-error outcome.
        karmaAnchorCache = KarmaAnchorCache(NoAnchorSource)
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

/** A [BitcoinTimeAnchorSource] that always reports "not found", with zero real network I/O - the
 * test-harness default for every test in this file that doesn't specifically exercise Karma
 * anchor-resolution failure handling. */
private object NoAnchorSource : BitcoinTimeAnchorSource {
    override fun findFirstOutgoingTransaction(pubkey: Secp256k1PublicKey): TimeAnchorLookupResult =
        TimeAnchorLookupResult.NotFound

    override fun currentChainTipHeight(): Int = 0
}

/** A [BitcoinTimeAnchorSource] that always reports [TimeAnchorLookupResult.LookupFailed] - used to
 * exercise `POST /api/karma`'s graceful-failure path (a 502, never an uncaught exception) without
 * any real network I/O. */
private object FailingAnchorSource : BitcoinTimeAnchorSource {
    override fun findFirstOutgoingTransaction(pubkey: Secp256k1PublicKey): TimeAnchorLookupResult =
        TimeAnchorLookupResult.LookupFailed("simulated Electrum failure")

    override fun currentChainTipHeight(): Int = throw IllegalStateException("simulated Electrum failure")
}

class BrowserApiRoutingTest :
    FunSpec({
        test("GET /api/identity returns the real identity fingerprint and peer id") {
            val harness = TestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }
                    val response = client.get("/api/identity")
                    response.status shouldBe HttpStatusCode.OK
                    val body = json.decodeFromString<IdentityResponse>(response.bodyAsText())
                    body.fingerprint shouldBe
                        harness.identity.secp256k1KeyPair.publicKey
                            .fingerprint()
                    body.peerId shouldBe harness.node.peerId.toBase58()
                }
            } finally {
                harness.stop()
            }
        }

        test("GET /api/timeline is empty before any post, and POST /api/posts then GET round-trips it") {
            val harness = TestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }

                    val empty = client.get("/api/timeline")
                    json.decodeFromString<List<TimelinePostResponse>>(empty.bodyAsText()) shouldBe emptyList()

                    val postResponse =
                        client.post("/api/posts") {
                            contentType(ContentType.Application.Json)
                            setBody(json.encodeToString(NewPostRequest("hello from the routing test")))
                        }
                    postResponse.status shouldBe HttpStatusCode.OK
                    val posted = json.decodeFromString<NewPostResponse>(postResponse.bodyAsText())
                    posted.cid.isNotBlank() shouldBe true

                    val timeline = client.get("/api/timeline")
                    val entries = json.decodeFromString<List<TimelinePostResponse>>(timeline.bodyAsText())
                    entries.size shouldBe 1
                    entries.single().text shouldBe "hello from the routing test"
                    entries.single().cid shouldBe posted.cid
                    // The local identity's own post is self-authored - always RESOLVED at full
                    // self-trust (see CredibilityCalculatorTest's identical assertion), never
                    // filtered by the default threshold.
                    entries.single().credibilityLevel shouldBe CredibilityLevel.RESOLVED.name
                }
            } finally {
                harness.stop()
            }
        }

        test("POST /api/trust then a follow-up GET /api/timeline reflects the resolved credibility") {
            val harness = TestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }

                    val otherAuthorIdentity = DualKeyIdentity.generate()
                    // Seed a post authored by someone other than the local identity directly
                    // through the real gossip/index path (no network involved - see TestHarness's
                    // doc comment), so /api/timeline has a non-self-authored entry to resolve.
                    val announcement =
                        PostAnnouncement.create(
                            otherAuthorIdentity.secp256k1KeyPair,
                            "post from someone else".toByteArray(),
                        )
                    harness.posts.announce(announcement)

                    val targetHex =
                        otherAuthorIdentity.secp256k1KeyPair.publicKey.bytes.joinToString(
                            "",
                        ) { "%02x".format(it) }
                    val trustResponse =
                        client.post("/api/trust") {
                            contentType(ContentType.Application.Json)
                            setBody(
                                json.encodeToString(
                                    TrustRequest(targetHex, trustMicros = 900_000, comment = "trusted"),
                                ),
                            )
                        }
                    trustResponse.status shouldBe HttpStatusCode.OK

                    val timeline = client.get("/api/timeline")
                    val entries = json.decodeFromString<List<TimelinePostResponse>>(timeline.bodyAsText())
                    val entry = entries.single { it.text == "post from someone else" }
                    entry.credibilityLevel shouldBe CredibilityLevel.RESOLVED.name
                    entry.credibilityScoreMicros shouldBe 900_000
                }
            } finally {
                harness.stop()
            }
        }

        test(
            "the real end-to-end authorPublicKeyHex path: reading it from a live /api/timeline entry and " +
                "feeding it straight into POST /api/trust is accepted and moves that author's credibility",
        ) {
            // Every OTHER test in this file that exercises /api/trust manually recomputes the
            // target hex from a known keypair - `otherAuthorIdentity.secp256k1KeyPair.publicKey.bytes
            // .joinToString(...)`. That never exercises the real client flow (app.js reads
            // `post.authorPublicKeyHex` straight off a `/api/timeline` response entry and feeds that
            // exact string into `/api/trust`, never recomputing it locally) - this test does the
            // real round trip instead.
            val harness = TestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }

                    val otherAuthorIdentity = DualKeyIdentity.generate()
                    val announcement =
                        PostAnnouncement.create(
                            otherAuthorIdentity.secp256k1KeyPair,
                            "post whose authorPublicKeyHex is read from a real response".toByteArray(),
                        )
                    harness.posts.announce(announcement)

                    // Before any trust grant this author is NO_PATH (not RESOLVED-low) - per
                    // TimelineBuilder.build's filtering rule, NO_PATH entries are NEVER filtered
                    // out (only a genuinely low RESOLVED score is), so this entry is already
                    // visible in the default (non-includeFiltered) view.
                    val beforeTrust = client.get("/api/timeline")
                    val beforeEntries = json.decodeFromString<List<TimelinePostResponse>>(beforeTrust.bodyAsText())
                    val entryBeforeTrust =
                        beforeEntries.single {
                            it.text == "post whose authorPublicKeyHex is read from a real response"
                        }
                    val expectedHex =
                        otherAuthorIdentity.secp256k1KeyPair.publicKey.bytes.joinToString(
                            "",
                        ) { "%02x".format(it) }
                    // Sanity check that the real response's hex actually matches the known keypair
                    // before using it - if this ever drifts, the test below would still "pass" for
                    // the wrong reason (submitting garbage that happens to be accepted).
                    entryBeforeTrust.authorPublicKeyHex shouldBe expectedHex

                    // The real client flow: feed the exact string read off the response straight
                    // into POST /api/trust, no local recomputation.
                    val trustResponse =
                        client.post("/api/trust") {
                            contentType(ContentType.Application.Json)
                            setBody(
                                json.encodeToString(
                                    TrustRequest(
                                        entryBeforeTrust.authorPublicKeyHex,
                                        trustMicros = 700_000,
                                        comment = "trusting via the real timeline-read hex",
                                    ),
                                ),
                            )
                        }
                    trustResponse.status shouldBe HttpStatusCode.OK

                    val afterTrust = client.get("/api/timeline")
                    val afterEntries = json.decodeFromString<List<TimelinePostResponse>>(afterTrust.bodyAsText())
                    val entryAfterTrust =
                        afterEntries.single {
                            it.text == "post whose authorPublicKeyHex is read from a real response"
                        }
                    entryAfterTrust.credibilityLevel shouldBe CredibilityLevel.RESOLVED.name
                    entryAfterTrust.credibilityScoreMicros shouldBe 700_000
                }
            } finally {
                harness.stop()
            }
        }

        test("POST /api/posts with text exceeding MAX_POST_BODY_BYTES returns 400, not a crash") {
            val harness = TestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }

                    val tooLong = "a".repeat(MAX_POST_BODY_BYTES + 1)
                    val response =
                        client.post("/api/posts") {
                            contentType(ContentType.Application.Json)
                            setBody(json.encodeToString(NewPostRequest(tooLong)))
                        }

                    response.status shouldBe HttpStatusCode.BadRequest
                    val body = json.decodeFromString<ErrorResponse>(response.bodyAsText())
                    body.error.isNotBlank() shouldBe true
                }
            } finally {
                harness.stop()
            }
        }

        test("POST /api/karma on a real post succeeds and is reflected in /api/timeline's karmaVoteCount") {
            val harness = TestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }

                    val postResponse =
                        client.post("/api/posts") {
                            contentType(ContentType.Application.Json)
                            setBody(json.encodeToString(NewPostRequest("a post to like")))
                        }
                    val posted = json.decodeFromString<NewPostResponse>(postResponse.bodyAsText())

                    val karmaResponse =
                        client.post("/api/karma") {
                            contentType(ContentType.Application.Json)
                            setBody(json.encodeToString(NewKarmaVoteRequest(posted.cid)))
                        }
                    karmaResponse.status shouldBe HttpStatusCode.OK
                    val karmaBody = json.decodeFromString<NewKarmaVoteResponse>(karmaResponse.bodyAsText())
                    karmaBody.targetCid shouldBe posted.cid
                    karmaBody.karmaVoteCount shouldBe 1

                    val timeline = client.get("/api/timeline")
                    val entries = json.decodeFromString<List<TimelinePostResponse>>(timeline.bodyAsText())
                    val entry = entries.single { it.cid == posted.cid }
                    entry.karmaVoteCount shouldBe 1
                    // NoAnchorSource (this harness's fake BitcoinTimeAnchorSource) always resolves
                    // NoAnchorClaim, which KarmaWeightCalculator always scores as exactly 0.0 - see
                    // that object's doc comment. This assertion is the structural proof the vote
                    // round-tripped through real signing/gossip/indexing, not a claim about a
                    // nonzero score (which would require a real ChainAnchorClaim).
                    entry.karmaScore shouldBe 0.0
                }
            } finally {
                harness.stop()
            }
        }

        test("POST /api/karma with a malformed targetCid returns 400, not a crash") {
            val harness = TestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }

                    val response =
                        client.post("/api/karma") {
                            contentType(ContentType.Application.Json)
                            setBody(json.encodeToString(NewKarmaVoteRequest("not-a-real-cid")))
                        }

                    response.status shouldBe HttpStatusCode.BadRequest
                    val body = json.decodeFromString<ErrorResponse>(response.bodyAsText())
                    body.error.isNotBlank() shouldBe true
                }
            } finally {
                harness.stop()
            }
        }

        test("POST /api/karma returns 502, not a crash, when the identity's time anchor cannot be resolved") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            val storage = NabuStorage.attach(node, Files.createTempDirectory("browser-api-routing-test-failing"))
            val pubsub = GossipPubSub.attach(node)
            val veritas = VeritasGossip.attach(pubsub, storage)
            val virtus = LtrGossip.attach(pubsub, storage)
            val karma = KarmaGossip.attach(pubsub, storage)
            val posts = PostAnnouncementGossip.attach(pubsub, storage)
            val karmaAnchorCache = KarmaAnchorCache(FailingAnchorSource)
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

                    val postResponse =
                        client.post("/api/posts") {
                            contentType(ContentType.Application.Json)
                            setBody(json.encodeToString(NewPostRequest("a post that cannot be liked")))
                        }
                    val posted = json.decodeFromString<NewPostResponse>(postResponse.bodyAsText())

                    val response =
                        client.post("/api/karma") {
                            contentType(ContentType.Application.Json)
                            setBody(json.encodeToString(NewKarmaVoteRequest(posted.cid)))
                        }

                    response.status shouldBe HttpStatusCode.BadGateway
                    val body = json.decodeFromString<ErrorResponse>(response.bodyAsText())
                    body.error.isNotBlank() shouldBe true
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

        test("POST /api/trust with a malformed hex public key returns 400, not a crash") {
            val harness = TestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }

                    val response =
                        client.post("/api/trust") {
                            contentType(ContentType.Application.Json)
                            setBody(json.encodeToString(TrustRequest("not-hex-at-all", trustMicros = 500_000)))
                        }

                    response.status shouldBe HttpStatusCode.BadRequest
                }
            } finally {
                harness.stop()
            }
        }

        test("POST /api/peers/connect with a malformed multiaddr returns 400, not a crash") {
            val harness = TestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }

                    val response =
                        client.post("/api/peers/connect") {
                            contentType(ContentType.Application.Json)
                            setBody(json.encodeToString(ConnectPeerRequest("not a real multiaddr")))
                        }

                    response.status shouldBe HttpStatusCode.BadRequest
                    val body = json.decodeFromString<ErrorResponse>(response.bodyAsText())
                    body.error.isNotBlank() shouldBe true
                }
            } finally {
                harness.stop()
            }
        }

        test("GET /api/peers returns an empty list for a never-connected node") {
            val harness = TestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }

                    val response = client.get("/api/peers")
                    response.status shouldBe HttpStatusCode.OK
                    val body = json.decodeFromString<PeersResponse>(response.bodyAsText())
                    body.peers shouldBe emptyList()
                }
            } finally {
                harness.stop()
            }
        }

        test("GET /api/connect/info returns a lapisnet:// URI containing the identity's public key hex") {
            val harness = TestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }

                    val response = client.get("/api/connect/info")
                    response.status shouldBe HttpStatusCode.OK
                    val body = json.decodeFromString<ConnectInfoResponse>(response.bodyAsText())
                    val expectedHex =
                        harness.identity.secp256k1KeyPair.publicKey.bytes
                            .joinToString("") { "%02x".format(it) }
                    body.publicKeyHex shouldBe expectedHex
                    body.uri.isNotBlank() shouldBe true
                    body.uri.startsWith("${ConnectUri.SCHEME}://${ConnectUri.HOST}?") shouldBe true
                    body.uri.contains(expectedHex) shouldBe true
                }
            } finally {
                harness.stop()
            }
        }

        test("GET /api/connect/qr.svg returns image/svg+xml content type") {
            val harness = TestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }

                    val response = client.get("/api/connect/qr.svg")
                    response.status shouldBe HttpStatusCode.OK
                    response.contentType()?.withoutParameters() shouldBe ContentType.Image.SVG
                    response.bodyAsText().startsWith("<svg") shouldBe true
                }
            } finally {
                harness.stop()
            }
        }

        test("POST /api/connect/uri with a malformed URI returns 400") {
            val harness = TestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }

                    val response =
                        client.post("/api/connect/uri") {
                            contentType(ContentType.Application.Json)
                            setBody(json.encodeToString(ConnectUriRequest("not a lapisnet uri at all")))
                        }

                    response.status shouldBe HttpStatusCode.BadRequest
                    val body = json.decodeFromString<ErrorResponse>(response.bodyAsText())
                    body.error.isNotBlank() shouldBe true
                }
            } finally {
                harness.stop()
            }
        }

        test("POST /api/self-link issues a max-trust grant to the target and it resolves as fully trusted") {
            val harness = TestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }

                    val otherDeviceIdentity = DualKeyIdentity.generate()
                    val announcement =
                        PostAnnouncement.create(
                            otherDeviceIdentity.secp256k1KeyPair,
                            "post from my other device".toByteArray(),
                        )
                    harness.posts.announce(announcement)

                    val targetHex =
                        otherDeviceIdentity.secp256k1KeyPair.publicKey.bytes
                            .joinToString("") { "%02x".format(it) }
                    val response =
                        client.post("/api/self-link") {
                            contentType(ContentType.Application.Json)
                            setBody(json.encodeToString(SelfLinkRequest(targetHex, label = "phone")))
                        }
                    response.status shouldBe HttpStatusCode.OK
                    val body = json.decodeFromString<SelfLinkResponse>(response.bodyAsText())
                    body.trustMicros shouldBe 1_000_000

                    val timeline = client.get("/api/timeline")
                    val entries = json.decodeFromString<List<TimelinePostResponse>>(timeline.bodyAsText())
                    val entry = entries.single { it.text == "post from my other device" }
                    entry.credibilityLevel shouldBe CredibilityLevel.RESOLVED.name
                    entry.credibilityScoreMicros shouldBe 1_000_000
                }
            } finally {
                harness.stop()
            }
        }

        test("POST /api/self-link to your own identity returns 400") {
            val harness = TestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }

                    val ownHex =
                        harness.identity.secp256k1KeyPair.publicKey.bytes
                            .joinToString("") { "%02x".format(it) }
                    val response =
                        client.post("/api/self-link") {
                            contentType(ContentType.Application.Json)
                            setBody(json.encodeToString(SelfLinkRequest(ownHex)))
                        }

                    response.status shouldBe HttpStatusCode.BadRequest
                }
            } finally {
                harness.stop()
            }
        }

        test("POST /api/self-link with malformed hex returns 400") {
            val harness = TestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }

                    val response =
                        client.post("/api/self-link") {
                            contentType(ContentType.Application.Json)
                            setBody(json.encodeToString(SelfLinkRequest("not-hex-at-all")))
                        }

                    response.status shouldBe HttpStatusCode.BadRequest
                }
            } finally {
                harness.stop()
            }
        }

        test("POST /api/self-link with an over-long label returns 400, not a 500") {
            val harness = TestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }

                    val otherDeviceIdentity = DualKeyIdentity.generate()
                    val targetHex =
                        otherDeviceIdentity.secp256k1KeyPair.publicKey.bytes
                            .joinToString("") { "%02x".format(it) }
                    val tooLongLabel = "a".repeat(VeritasGrantCodec.MAX_COMMENT_BYTES + 1)

                    val response =
                        client.post("/api/self-link") {
                            contentType(ContentType.Application.Json)
                            setBody(json.encodeToString(SelfLinkRequest(targetHex, label = tooLongLabel)))
                        }

                    response.status shouldBe HttpStatusCode.BadRequest
                    val body = json.decodeFromString<ErrorResponse>(response.bodyAsText())
                    body.error.isNotBlank() shouldBe true
                }
            } finally {
                harness.stop()
            }
        }

        // Security-critical regression test: proves a self-link from an identity the LOCAL VIEWER
        // has no trust path to grants the self-linked-to identity NOTHING from the viewer's own
        // point of view. This is the central Sybil-resistance claim of Part C (see
        // architecture.adoc "Self-trust linking (V0.4)"): an A->B self-link only extends A's
        // PRE-EXISTING standing one hop further - it can never manufacture trust a third party
        // (here, the harness's own local identity) didn't already have a path to.
        test("a self-link from an untrusted identity grants no credibility to the local viewer") {
            val harness = TestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }

                    // X and Y are both strangers to the local harness identity - nobody has ever
                    // granted either of them any trust from the local viewer's point of view.
                    val identityX = DualKeyIdentity.generate()
                    val identityY = DualKeyIdentity.generate()

                    // X self-links to Y directly through the real gossip/index path (simulating an
                    // attacker announcing a self-link, exactly as POST /api/self-link would) -
                    // never via the local harness identity, and never through the HTTP route
                    // (which can only ever self-link on behalf of the LOCAL identity).
                    val attackerSelfLink =
                        VeritasGrant.create(
                            truster = identityX.secp256k1KeyPair,
                            target = identityY.secp256k1KeyPair.publicKey,
                            trustMicros = 1_000_000,
                            comment = "self-link: attacker-controlled",
                        )
                    harness.veritas.announce(attackerSelfLink)

                    val announcement =
                        PostAnnouncement.create(identityY.secp256k1KeyPair, "post from Y".toByteArray())
                    harness.posts.announce(announcement)

                    val timeline = client.get("/api/timeline")
                    val entries = json.decodeFromString<List<TimelinePostResponse>>(timeline.bodyAsText())
                    val entry = entries.single { it.text == "post from Y" }
                    entry.credibilityLevel shouldBe CredibilityLevel.NO_PATH.name
                }
            } finally {
                harness.stop()
            }
        }

        // Ktor's testApplication test host never opens a real socket at all (see its doc comment:
        // it runs the application in-process against an in-memory client), so there is no
        // "resolved connector" to introspect for the 127.0.0.1-only requirement here. The real
        // enforcement point is BrowserServer.start()'s own require() guard - exercised directly
        // below, which is the strongest testable proxy for "this server can never bind a
        // non-loopback address" without actually opening a real socket in a unit test.
        test("BrowserServer.start refuses to bind any host other than 127.0.0.1") {
            val identity = DualKeyIdentity.generate()
            val dataDirectory = Files.createTempDirectory("browser-server-bind-guard-test")

            shouldThrow<IllegalArgumentException> {
                BrowserServer.start(
                    identity = identity,
                    httpHost = "0.0.0.0",
                    httpPort = 0,
                    dataDirectory = dataDirectory,
                )
            }
        }
    })
