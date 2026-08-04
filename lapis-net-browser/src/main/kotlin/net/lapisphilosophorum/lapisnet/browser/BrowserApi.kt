package net.lapisphilosophorum.lapisnet.browser

import io.github.oshai.kotlinlogging.KotlinLogging
import io.ipfs.cid.Cid
import io.ipfs.multibase.Base58
import io.ipfs.multibase.Multibase
import io.ipfs.multihash.Multihash
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.http.content.staticResources
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.plugins.statuspages.StatusPages
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.libp2p.core.PeerInfo
import io.libp2p.core.multiformats.Multiaddr
import kotlinx.serialization.Serializable
import net.lapisphilosophorum.lapisnet.core.cid.CidBytesValidation
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.karma.KarmaGossip
import net.lapisphilosophorum.lapisnet.karma.KarmaVote
import net.lapisphilosophorum.lapisnet.karma.KarmaVoteCodec
import net.lapisphilosophorum.lapisnet.mail.InboxGossip
import net.lapisphilosophorum.lapisnet.mail.MailSender
import net.lapisphilosophorum.lapisnet.mail.SentFolder
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import net.lapisphilosophorum.lapisnet.trust.MAX_TRUST_MICROS
import net.lapisphilosophorum.lapisnet.trust.MIN_TRUST_MICROS
import net.lapisphilosophorum.lapisnet.trust.TrustGraph
import net.lapisphilosophorum.lapisnet.trust.VeritasGossip
import net.lapisphilosophorum.lapisnet.trust.VeritasGrant
import net.lapisphilosophorum.lapisnet.trust.VeritasGrantCodec
import net.lapisphilosophorum.lapisnet.virtus.LightningProof
import net.lapisphilosophorum.lapisnet.virtus.LightningProofVerifier
import net.lapisphilosophorum.lapisnet.virtus.LtrGossip
import net.lapisphilosophorum.lapisnet.virtus.LtrRecord
import java.security.MessageDigest

private val logger = KotlinLogging.logger {}

@Serializable
data class IdentityResponse(
    val fingerprint: String,
    val peerId: String,
)

@Serializable
data class TimelinePostResponse(
    val cid: String,
    val author: String,
    /** The author's full 33-byte compressed secp256k1 public key, hex-encoded - unlike [author]
     * (a short, one-way [Secp256k1PublicKey.fingerprint], display-only), this is what the client
     * must send back as `targetPublicKeyHex` in a `POST /api/trust` call to rate this author -
     * a fingerprint alone cannot be reversed back into a usable public key. */
    val authorPublicKeyHex: String,
    val text: String,
    val publishedAtEpochSeconds: Long,
    val credibilityLevel: String,
    val credibilityScoreMicros: Int,
    val ltrWeightMsat: Double,
    val ltrRecordCount: Int,
    val karmaScore: Double,
    val karmaVoteCount: Int,
)

@Serializable
data class NewPostRequest(
    val text: String,
)

@Serializable
data class NewPostResponse(
    val cid: String,
)

@Serializable
data class NewKarmaVoteRequest(
    val targetCid: String,
)

@Serializable
data class NewKarmaVoteResponse(
    val targetCid: String,
    val karmaVoteCount: Int,
)

/** Request body for `POST /api/ltr/lightning` - an *externally-obtained* `(preimage, signedInvoice)`
 * pair, e.g. the author paid a real BOLT-11 invoice with their own Lightning wallet out-of-band and
 * is now submitting proof of that payment. Deliberately carries no amount field - see that route's
 * doc comment on why the amount is always derived server-side from [signedInvoice] itself, never
 * trusted from the client. */
@Serializable
data class NewLightningLtrRequest(
    val cid: String,
    val viewIdHex: String,
    val preimageHex: String,
    val signedInvoice: String,
)

@Serializable
data class NewLightningLtrResponse(
    val cid: String,
    val initialValueMsat: Long,
    val ltrRecordCount: Int,
)

@Serializable
data class TrustRequest(
    val targetPublicKeyHex: String,
    val trustMicros: Int,
    val comment: String = "",
)

@Serializable
data class TrustResponse(
    val target: String,
    val trustMicros: Int,
)

@Serializable
data class PeerSummary(
    val peerId: String,
    val remoteAddress: String,
)

@Serializable
data class PeersResponse(
    val peers: List<PeerSummary>,
)

@Serializable
data class ConnectPeerRequest(
    val multiaddr: String,
)

@Serializable
data class ConnectPeerResponse(
    val peerId: String,
)

@Serializable
data class ErrorResponse(
    val error: String,
)

@Serializable
data class ConnectInfoResponse(
    val multiaddr: String,
    val publicKeyHex: String,
    val uri: String,
)

@Serializable
data class ConnectUriRequest(
    val uri: String,
)

@Serializable
data class ConnectUriResponse(
    val peerId: String,
    val publicKeyHex: String,
)

@Serializable
data class SelfLinkRequest(
    val targetPublicKeyHex: String,
    val label: String = "",
)

@Serializable
data class SelfLinkResponse(
    val target: String,
    val trustMicros: Int,
)

/** Marker text returned by `GET /api/timeline` in place of a post's real text when the local
 * [NabuStorage.get] lookup misses - see that route's doc comment for why this happens (a
 * gossip-received post whose body bytes this node never durably stored, e.g. past the persistence
 * cap) and why it must never crash or silently return `null`/omit the entry instead. */
const val CONTENT_UNAVAILABLE_MARKER = "<content unavailable>"

/**
 * Everything [installBrowserApi] needs to serve the browser MVP's JSON routes - a plain data
 * holder, not a lifecycle owner (see [BrowserServer], which owns and stops each of these).
 */
class BrowserApiDependencies(
    val identity: DualKeyIdentity,
    val node: LapisNode,
    val storage: NabuStorage,
    val veritas: VeritasGossip,
    val virtus: LtrGossip,
    val karma: KarmaGossip,
    val posts: PostAnnouncementGossip,
    val karmaAnchorCache: KarmaAnchorCache,
    /** V0.9.3 - see `MailApi.kt`'s `installMailRoutes` for the routes wired against these three. */
    val mailInbox: InboxGossip,
    val mailSender: MailSender,
    val sentFolder: SentFolder,
)

/**
 * Installs the browser MVP's JSON API routes plus the static UI (see
 * `src/main/resources/static/`) onto [this] [Application]. Called both by [BrowserServer.start]
 * (a real embedded server) and by tests via Ktor's `testApplication { application { ... } }` test
 * host - kept as a standalone `Application.()` extension specifically so both call sites share the
 * exact same route wiring instead of it living only inside [BrowserServer]'s `embeddedServer { }`
 * lambda.
 */
fun Application.installBrowserApi(deps: BrowserApiDependencies) {
    // No CORS plugin is installed here - Ktor never emits Access-Control-Allow-Origin without
    // one, which incidentally blocks browser-originated cross-origin requests today on top of
    // the 127.0.0.1-only bind (see BrowserServer's doc comment). Confirmed safe as of the V0.2.2
    // review; revisit with a real CORS policy if this ever needs to serve a UI hosted elsewhere.
    install(ContentNegotiation) { json() }
    // Defense-in-depth: catches any exception a route handler doesn't explicitly handle (e.g. an
    // unanticipated NabuStorageException from a future route) so it can never reach the client as
    // Ktor's default response, which echoes the raw exception message - including local
    // filesystem paths, as NabuStorageException's messages routinely do (see NabuStorage's doc
    // comments). The real exception is logged server-side; the client only ever sees a generic,
    // sanitized message.
    install(StatusPages) {
        exception<Throwable> { call, cause ->
            logger.error(cause) { "unhandled exception in a browser API route" }
            call.respond(HttpStatusCode.InternalServerError, ErrorResponse("internal server error"))
        }
    }
    routing {
        get("/api/identity") {
            call.respond(
                IdentityResponse(
                    fingerprint =
                        deps.identity.secp256k1KeyPair.publicKey
                            .fingerprint(),
                    peerId = deps.node.peerId.toBase58(),
                ),
            )
        }

        get("/api/timeline") {
            val includeFiltered = call.request.queryParameters["includeFiltered"]?.toBooleanStrictOrNull() ?: false

            val graph = TrustGraph.fromGrants(deps.veritas.currentGrants())
            val tracked = deps.posts.currentPosts()
            val candidates =
                tracked.map { indexed ->
                    TimelineCandidate(
                        cid = indexed.cid,
                        author = indexed.announcement.author,
                        publishedAtEpochSeconds = indexed.announcement.timestampSeconds,
                    )
                }
            // Single-view pilot stage - every lookup is scoped to PLACEHOLDER_VIEW_ID, see that
            // constant's doc comment.
            val ltrRecordsByCid =
                tracked.associate { indexed ->
                    indexed.cid to deps.virtus.currentRecords(indexed.cid, PLACEHOLDER_VIEW_ID)
                }
            val karmaVotesByCid =
                tracked.associate { indexed ->
                    indexed.cid to deps.karma.currentVotesForTarget(indexed.cid)
                }

            val entries =
                TimelineBuilder.build(
                    graph = graph,
                    localIdentity = deps.identity.secp256k1KeyPair.publicKey,
                    candidates = candidates,
                    ltrRecordsByCid = ltrRecordsByCid,
                    karmaVotesByCid = karmaVotesByCid,
                    karmaVotesByVoter = deps.karma::currentVotesByVoter,
                )
            val visible = TimelineBuilder.visible(entries, includeFilteredContent = includeFiltered)

            val response =
                visible.map { entry ->
                    // A gossip-received post's body bytes might not be durably stored locally -
                    // e.g. past PostAnnouncementIndex's body- or wrapper-persistence caps, or a
                    // genuine local storage fault. NabuStorage.get() documents that a real fault
                    // (as opposed to a plain not-found) THROWS NabuStorageException rather than
                    // returning null - runCatching here ensures one corrupted/faulty local block
                    // degrades to the placeholder for that entry only, never fails the whole
                    // response (and never leaks the raw exception message, which can include
                    // local filesystem paths - see NabuStorage's doc comments).
                    val text =
                        runCatching { deps.storage.get(entry.cid) }
                            .getOrNull()
                            ?.toString(Charsets.UTF_8)
                            ?: CONTENT_UNAVAILABLE_MARKER
                    TimelinePostResponse(
                        cid = entry.cid.toString(),
                        author = entry.author.fingerprint(),
                        authorPublicKeyHex = entry.author.bytes.toHexString(),
                        text = text,
                        publishedAtEpochSeconds = entry.publishedAtEpochSeconds,
                        credibilityLevel = entry.credibility.level.name,
                        credibilityScoreMicros = entry.credibility.scoreMicros,
                        ltrWeightMsat = entry.ltrWeightMsat,
                        ltrRecordCount = entry.ltrRecordCount,
                        karmaScore = entry.karmaScore,
                        karmaVoteCount = entry.karmaVoteCount,
                    )
                }
            call.respond(response)
        }

        post("/api/posts") {
            val request = call.receive<NewPostRequest>()
            val bytes = request.text.toByteArray(Charsets.UTF_8)
            if (bytes.size !in 1..MAX_POST_BODY_BYTES) {
                call.respond(
                    HttpStatusCode.BadRequest,
                    ErrorResponse("text must be 1..$MAX_POST_BODY_BYTES UTF-8 bytes, was ${bytes.size}"),
                )
                return@post
            }
            val announcement = PostAnnouncement.create(deps.identity.secp256k1KeyPair, bytes)
            val cid = deps.posts.announce(announcement)
            call.respond(NewPostResponse(cid.toString()))
        }

        post("/api/karma") {
            val request = call.receive<NewKarmaVoteRequest>()
            val targetCid = parseCidOrNull(request.targetCid)
            if (targetCid == null) {
                call.respond(HttpStatusCode.BadRequest, ErrorResponse("targetCid is not a valid CID"))
                return@post
            }
            // Resolves (or lazily populates, on this identity's first-ever vote) this node's own
            // Bitcoin time anchor - a real, client-side Electrum lookup, never a chain call in the
            // gossip path (see KarmaGossip's doc comment). KarmaAnchorResolutionException covers
            // every real failure mode (LookupFailed, a chain-tip query failure, an inconsistent
            // cached genesis/tip pair) - caught here so a transient Electrum outage degrades to a
            // clean 502 response, never an uncaught exception (the installed StatusPages handler
            // would also catch it, but a dedicated response here gives the caller a clearer,
            // Karma-specific error message than the generic "internal server error" fallback).
            val timeAnchor =
                try {
                    deps.karmaAnchorCache.currentClaimFor(deps.identity.secp256k1KeyPair)
                } catch (e: KarmaAnchorResolutionException) {
                    logger.warn(e) { "failed to resolve time anchor for a Karma vote" }
                    call.respond(
                        HttpStatusCode.BadGateway,
                        ErrorResponse("failed to resolve this identity's Bitcoin time anchor: ${e.message}"),
                    )
                    return@post
                }
            val vote = KarmaVote.create(deps.identity.secp256k1KeyPair, targetCid, timeAnchor)
            deps.karma.announce(vote)
            val karmaVoteCount = deps.karma.currentVotesForTarget(targetCid).size
            call.respond(NewKarmaVoteResponse(targetCid = targetCid.toString(), karmaVoteCount = karmaVoteCount))
        }

        // V0.6: the first LTR/Virtus record *authoring* endpoint - V0.2.2's known gap ("no LTR
        // record authoring in this MVP") closed for the Lightning payment path specifically.
        // Accepts a (preimage, signedInvoice) pair the caller obtained by paying a real BOLT-11
        // invoice with their own Lightning wallet OUT-OF-BAND - this route never sends a Lightning
        // payment itself (no embedded node/wallet exists in this codebase, see
        // lapis-net-virtus/build.gradle.kts's header comment on that scope cut). It only verifies
        // the resulting proof and, if valid, authors and announces the LtrRecord.
        post("/api/ltr/lightning") {
            val request = call.receive<NewLightningLtrRequest>()

            val cid = parseCidOrNull(request.cid)
            if (cid == null) {
                call.respond(HttpStatusCode.BadRequest, ErrorResponse("cid is not a valid CID"))
                return@post
            }
            val viewId = parseHexPublicKeyOrNull(request.viewIdHex)
            if (viewId == null) {
                call.respond(
                    HttpStatusCode.BadRequest,
                    ErrorResponse("viewIdHex must be a 33-byte compressed secp256k1 public key in hex"),
                )
                return@post
            }
            val preimage = parseHexBytesOrNull(request.preimageHex, expectedLength = 32)
            if (preimage == null) {
                call.respond(HttpStatusCode.BadRequest, ErrorResponse("preimageHex must be exactly 32 bytes in hex"))
                return@post
            }

            // The amount is ALWAYS derived from the invoice itself, server-side - never trusted
            // from a client-supplied field (there is no such field on NewLightningLtrRequest at
            // all - see that class's doc comment). This is the anti-amount-spoofing discipline
            // LightningProofVerifier.verify itself also enforces at gossip-validation time; doing
            // it here too means a bad request fails fast with a clean 400 rather than only being
            // caught much later at the verify-before-announce step below.
            val initialValueMsat = LightningProofVerifier.invoiceAmountMsatOrNull(request.signedInvoice)
            if (initialValueMsat == null) {
                call.respond(
                    HttpStatusCode.BadRequest,
                    ErrorResponse("signedInvoice is not a parseable BOLT-11 invoice with a non-null amount"),
                )
                return@post
            }

            // Derived server-side, never trusted from a client-supplied hash - mirrors the amount
            // discipline immediately above.
            val paymentHash = MessageDigest.getInstance("SHA-256").digest(preimage)
            val proof =
                runCatching { LightningProof(preimage, paymentHash, request.signedInvoice) }.getOrElse {
                    call.respond(HttpStatusCode.BadRequest, ErrorResponse("invalid Lightning proof fields"))
                    return@post
                }

            // initialValueMsat is derived server-side from the invoice's own amount above and is
            // never client-supplied, but a real BOLT-11 invoice's amount decoder has no upper
            // bound - an invoice can legally encode a value larger than LtrRecord's own
            // MIN_INITIAL_VALUE_MSAT..MAX_INITIAL_VALUE_MSAT range (the 21M-BTC-in-msat supply
            // cap, see that constant's doc comment). LtrRecord.create's init block enforces that
            // range and throws IllegalArgumentException outside it - wrapped here (mirroring the
            // LightningProof(...) construction immediately above) so an oversized invoice amount
            // fails with a clean 400, consistent with this route's other validation-failure
            // branches, instead of an unsanitized 500 from the global StatusPages handler.
            val record =
                runCatching {
                    LtrRecord.create(
                        payer = deps.identity.secp256k1KeyPair,
                        cid = cid,
                        viewId = viewId,
                        initialValueMsat = initialValueMsat,
                        proof = proof,
                    )
                }.getOrElse {
                    call.respond(
                        HttpStatusCode.BadRequest,
                        ErrorResponse("invoice amount is outside the supported LTR record range"),
                    )
                    return@post
                }

            // Verify BEFORE announcing - a locally-authored record still goes through the exact
            // same cryptographic checks LtrGossip.onGossipMessage applies to a gossip-received one
            // (see that function's doc comment on why this is safe to do synchronously here: pure,
            // bounded, local computation, no liveness dependency). Never leak raw ACINQ exception
            // detail into the HTTP response - LightningProofVerifier.verify already never throws,
            // so a generic message here is the full, deliberate error surface, mirroring the
            // existing Karma electrum-error sanitization pattern (full detail is not even
            // available here to log, since verify() itself never exposes the specific failure
            // reason - see that function's doc comment).
            if (!LightningProofVerifier.verify(record, proof)) {
                logger.warn { "rejected a self-authored Lightning-proof LTR record that failed verification" }
                call.respond(HttpStatusCode.BadRequest, ErrorResponse("Lightning proof failed verification"))
                return@post
            }

            // C1 fix: deps.virtus.announce now checks LtrRecordIndex.hasLightningPaymentBeenUsed
            // BEFORE persisting/indexing/publishing a genuinely new record - false here means this
            // exact (cid, viewId, paymentHash) triple already backs another tracked record (this
            // payment was already used, whether via an earlier call to this same endpoint or via
            // gossip), so a repeat POST of the identical (preimage, signedInvoice) pair must not
            // mint additional LTR weight from the one real payment - see
            // LtrRecordIndex.hasLightningPaymentBeenUsed's doc comment for the full "spent
            // payment-hash" reasoning and its documented residual gap.
            if (!deps.virtus.announce(record)) {
                logger.warn {
                    "rejected a self-authored Lightning-proof LTR record - its payment hash was already used " +
                        "for this cid/view"
                }
                call.respond(
                    HttpStatusCode.BadRequest,
                    ErrorResponse(
                        "this Lightning payment has already been used to back an LTR record for this cid/view",
                    ),
                )
                return@post
            }
            val ltrRecordCount = deps.virtus.currentRecords(cid, viewId).size
            call.respond(
                NewLightningLtrResponse(
                    cid = cid.toString(),
                    initialValueMsat = initialValueMsat,
                    ltrRecordCount = ltrRecordCount,
                ),
            )
        }

        post("/api/trust") {
            val request = call.receive<TrustRequest>()
            val target = parseHexPublicKeyOrNull(request.targetPublicKeyHex)
            if (target == null) {
                call.respond(
                    HttpStatusCode.BadRequest,
                    ErrorResponse("targetPublicKeyHex must be a 33-byte compressed secp256k1 public key in hex"),
                )
                return@post
            }
            if (request.trustMicros !in MIN_TRUST_MICROS..MAX_TRUST_MICROS) {
                call.respond(
                    HttpStatusCode.BadRequest,
                    ErrorResponse("trustMicros must be in $MIN_TRUST_MICROS..$MAX_TRUST_MICROS"),
                )
                return@post
            }
            val grant =
                VeritasGrant.create(
                    truster = deps.identity.secp256k1KeyPair,
                    target = target,
                    trustMicros = request.trustMicros,
                    comment = request.comment,
                )
            deps.veritas.announce(grant)
            call.respond(TrustResponse(target = target.fingerprint(), trustMicros = request.trustMicros))
        }

        get("/api/peers") {
            val peers =
                deps.node.host.network.connections.map { connection ->
                    PeerSummary(
                        peerId = connection.secureSession().remoteId.toBase58(),
                        remoteAddress = connection.remoteAddress().toString(),
                    )
                }
            call.respond(PeersResponse(peers))
        }

        post("/api/peers/connect") {
            val request = call.receive<ConnectPeerRequest>()
            val multiaddr = runCatching { Multiaddr(request.multiaddr) }.getOrNull()
            val peerId = multiaddr?.getPeerId()
            if (multiaddr == null || peerId == null) {
                call.respond(
                    HttpStatusCode.BadRequest,
                    ErrorResponse(
                        "multiaddr must be a valid libp2p multiaddr including a /p2p/<peerId> component",
                    ),
                )
                return@post
            }
            runCatching { deps.node.connect(PeerInfo(peerId, listOf(multiaddr))) }
                .onSuccess { call.respond(ConnectPeerResponse(peerId.toBase58())) }
                .onFailure { error ->
                    call.respond(HttpStatusCode.BadRequest, ErrorResponse("failed to connect: ${error.message}"))
                }
        }

        // --- V0.4: QR-code / deep-link key exchange (Part B) + self-trust-linking (Part C) ---

        get("/api/connect/info") {
            val maddr = deps.node.bestDialableMultiaddr()
            val pkHex =
                deps.identity.secp256k1KeyPair.publicKey.bytes
                    .toHexString()
            if (maddr == null) {
                call.respond(ConnectInfoResponse(multiaddr = "", publicKeyHex = pkHex, uri = ""))
                return@get
            }
            val uri = ConnectUri.of(maddr, deps.identity.secp256k1KeyPair.publicKey).toUriString()
            call.respond(ConnectInfoResponse(multiaddr = maddr.toString(), publicKeyHex = pkHex, uri = uri))
        }

        get("/api/connect/qr.svg") {
            val maddr = deps.node.bestDialableMultiaddr()
            if (maddr == null) {
                call.respond(HttpStatusCode.ServiceUnavailable, ErrorResponse("no dialable listen address yet"))
                return@get
            }
            val uri = ConnectUri.of(maddr, deps.identity.secp256k1KeyPair.publicKey).toUriString()
            val svg = QrCodeSvg.render(uri)
            call.respondText(svg, ContentType.Image.SVG)
        }

        post("/api/connect/uri") {
            val request = call.receive<ConnectUriRequest>()
            val parsed = ConnectUri.parseOrNull(request.uri)
            if (parsed == null) {
                call.respond(HttpStatusCode.BadRequest, ErrorResponse("not a valid lapisnet://connect URI"))
                return@post
            }
            val peerId = parsed.multiaddr.getPeerId()!!
            runCatching { deps.node.connect(PeerInfo(peerId, listOf(parsed.multiaddr))) }
                .onSuccess {
                    call.respond(
                        ConnectUriResponse(
                            peerId = peerId.toBase58(),
                            publicKeyHex = parsed.publicKey.bytes.toHexString(),
                        ),
                    )
                }.onFailure { error ->
                    call.respond(HttpStatusCode.BadRequest, ErrorResponse("failed to connect: ${error.message}"))
                }
        }

        // Reuses the EXISTING VeritasGrant model verbatim at MAX_TRUST_MICROS - no schema change,
        // no new signature domain tag, no special gossip-path validation (see architecture.adoc
        // "Self-trust linking (V0.4)"). This creates NO new Sybil attack surface: an A->B self-link
        // only propagates A's pre-existing standing one hop further; it cannot manufacture trust a
        // third party didn't already have a path to, and TrustPathFinder's shortest-path rule makes
        // the near (already-known) edge decisive over any far self-linked sock-puppet edge.
        post("/api/self-link") {
            val request = call.receive<SelfLinkRequest>()
            val target = parseHexPublicKeyOrNull(request.targetPublicKeyHex)
            if (target == null) {
                call.respond(
                    HttpStatusCode.BadRequest,
                    ErrorResponse("targetPublicKeyHex must be a 33-byte compressed secp256k1 public key in hex"),
                )
                return@post
            }
            if (target == deps.identity.secp256k1KeyPair.publicKey) {
                call.respond(HttpStatusCode.BadRequest, ErrorResponse("cannot self-link to your own identity"))
                return@post
            }
            val comment = if (request.label.isBlank()) "self-link" else "self-link: ${request.label}"
            // Validate the resulting comment fits VeritasGrantCodec's byte limit BEFORE calling
            // VeritasGrant.create, so an over-long label returns a clean 400 instead of an
            // uncaught IllegalArgumentException from VeritasGrant's init block (mirrors the
            // /api/posts byte-count 400 pattern for MAX_POST_BODY_BYTES). Never silently truncate
            // a user-supplied label.
            if (comment.toByteArray(Charsets.UTF_8).size > VeritasGrantCodec.MAX_COMMENT_BYTES) {
                call.respond(HttpStatusCode.BadRequest, ErrorResponse("label is too long"))
                return@post
            }
            val grant =
                VeritasGrant.create(
                    truster = deps.identity.secp256k1KeyPair,
                    target = target,
                    trustMicros = MAX_TRUST_MICROS,
                    comment = comment,
                )
            deps.veritas.announce(grant)
            call.respond(SelfLinkResponse(target = target.fingerprint(), trustMicros = MAX_TRUST_MICROS))
        }

        // V0.9.3 mail routes - kept in their own file (MailApi.kt) for readability given their
        // size, with installBrowserApi calling this thin extension so BrowserApi.kt itself stays a
        // dispatcher. installMailRoutes is a Route.() extension, called from inside this same
        // `routing { }` block so it shares the exact route tree the routes above are installed
        // into.
        installMailRoutes(deps)

        // Serves src/main/resources/static/ (index.html, style.css, app.js) at the site root -
        // e.g. /index.html, /style.css, /app.js. Mapped LAST relative to the /api/* routes above
        // only for readability; Ktor's routing tree dispatches by exact path match, so ordering
        // among these routes has no behavioral effect.
        staticResources("/", "static")
    }
}

/** Parses [hex] as a 33-byte compressed secp256k1 public key, or `null` for any malformed input
 * (wrong length, non-hex characters, or bytes that don't represent a valid curve point) - never
 * throws, so route handlers can turn this straight into a 400 response instead of crashing. */
internal fun parseHexPublicKeyOrNull(hex: String): Secp256k1PublicKey? {
    if (hex.length != 66 || hex.any { it !in HEX_CHARS }) return null
    val bytes = ByteArray(33) { i -> hex.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
    return runCatching { Secp256k1PublicKey(bytes) }.getOrNull()
}

/** Parses [hex] as exactly [expectedLength] raw bytes, or `null` for any malformed input (wrong
 * length or non-hex characters) - never throws, mirrors [parseHexPublicKeyOrNull]'s established
 * pattern for this file. Used by `POST /api/ltr/lightning` for `preimageHex` (unlike
 * [parseHexPublicKeyOrNull], the result is not curve-point-validated - a preimage is an arbitrary
 * 32-byte value, not a public key). */
private fun parseHexBytesOrNull(
    hex: String,
    expectedLength: Int,
): ByteArray? {
    if (hex.length != expectedLength * 2 || hex.any { it !in HEX_CHARS }) return null
    return runCatching {
        ByteArray(expectedLength) { i -> hex.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
    }.getOrNull()
}

private val HEX_CHARS = "0123456789abcdefABCDEF"

internal fun ByteArray.toHexString(): String = joinToString("") { "%02x".format(it) }

/** Cheap upper bound on an incoming CID string's length, checked BEFORE it ever reaches
 * [Cid.decode] - mirrors [parseHexPublicKeyOrNull]'s exact-length precondition check, just looser
 * since a base-encoded (base32/base58/etc.) CID string has no single exact length the way a fixed
 * 33-byte hex public key does. Derived from
 * [net.lapisphilosophorum.lapisnet.karma.KarmaVoteCodec.MAX_CID_BYTES] (128 raw bytes) with a
 * generous 4x multiplier to cover multibase encoding expansion (base32 ~1.6x, base58btc ~1.37x,
 * plus a multibase prefix character) - not a tight bound, just enough headroom to reject an
 * obviously-oversized string before wasting decode work on it. */
private val MAX_CID_STRING_LENGTH = KarmaVoteCodec.MAX_CID_BYTES * 4

/** Parses [value] as a [Cid], or `null` for any malformed input - never throws, so route handlers
 * can turn this straight into a 400 response instead of crashing, mirroring
 * [parseHexPublicKeyOrNull]'s established pattern for this file.
 *
 * **Deliberately does NOT call `io.ipfs.cid.Cid.decode(String)` directly.** That method has two
 * separate byte-parsing paths - both funnel attacker-controlled bytes into
 * `Multihash.deserialize`'s `byte[] hash = new byte[len]` allocation BEFORE its own constructor's
 * `hash.length > 127` bound check ever runs, exactly the CID multihash length overflow OOM-DoS this
 * project's other four CID-decoding call sites (`MessageEnvelopeCodec`, `MessageBodyCodec`,
 * `LtrRecordCodec`, `KarmaVoteCodec`, `VeritasGrantCodec`) were fixed to guard against with
 * [CidBytesValidation] - see that object's class doc comment for the full mechanism:
 * - The common path: `Multibase.decode(v)` then `Cid.cast(data)` - guarded here by decoding the
 *   multibase bytes ourselves and checking [CidBytesValidation.isSafeToCast] before ever calling
 *   [Cid.cast].
 * - The legacy CIDv0 shortcut (`v.length() == 46 && v.startsWith("Qm")`): `Multihash.fromBase58(v)`,
 *   which never goes through [Cid.cast] at all and is NOT covered by `isSafeToCast` - guarded here
 *   by decoding the base58 bytes ourselves and checking
 *   [CidBytesValidation.isSafeToDeserializeMultihash] first. This mirrors `Cid.decode`'s own
 *   branch selection exactly, so behavior for well-formed input is unchanged. */
internal fun parseCidOrNull(value: String): Cid? {
    if (value.length > MAX_CID_STRING_LENGTH) return null

    if (value.length == 46 && value.startsWith("Qm")) {
        val multihashBytes = runCatching { Base58.decode(value) }.getOrNull() ?: return null
        if (!CidBytesValidation.isSafeToDeserializeMultihash(multihashBytes)) return null
        return runCatching { Cid.buildV0(Multihash.deserialize(multihashBytes)) }.getOrNull()
    }

    val cidBytes = runCatching { Multibase.decode(value) }.getOrNull() ?: return null
    if (!CidBytesValidation.isSafeToCast(cidBytes)) return null
    return runCatching { Cid.cast(cidBytes) }.getOrNull()
}

/** Picks the "best" dialable multiaddr for this node to advertise (V0.4 QR/deep-link connect,
 * see [ConnectUri]): prefers a non-loopback listen address over a `127.0.0.1`/`::1` one, and
 * always appends `/p2p/<peerId>` so the result is directly usable by [LapisNode.connect]/
 * [PeerInfo] on the receiving side. Returns `null` only if this node has no listen address at all
 * (should not happen for a started [LapisNode], but this file never assumes that at a route
 * boundary - see this function's callers' own null-handling). */
private fun LapisNode.bestDialableMultiaddr(): Multiaddr? {
    val addrs = listenAddresses()
    if (addrs.isEmpty()) return null
    val nonLoopback = addrs.firstOrNull { !it.toString().contains("/127.0.0.1/") && !it.toString().contains("/::1/") }
    return (nonLoopback ?: addrs.first()).withP2P(peerId)
}
