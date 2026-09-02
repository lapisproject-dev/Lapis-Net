package net.lapisphilosophorum.lapisnet.browser

import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.http.ContentDisposition
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.request.receive
import io.ktor.server.response.header
import io.ktor.server.response.respond
import io.ktor.server.response.respondBytes
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import kotlinx.serialization.Serializable
import net.lapisphilosophorum.lapisnet.directory.PeerDirectoryGossip
import net.lapisphilosophorum.lapisnet.dm.DmAcceptedContacts
import net.lapisphilosophorum.lapisnet.dm.DmAttachmentCipher
import net.lapisphilosophorum.lapisnet.dm.DmAttachmentFetcher
import net.lapisphilosophorum.lapisnet.dm.DmAttachmentRef
import net.lapisphilosophorum.lapisnet.dm.DmContent
import net.lapisphilosophorum.lapisnet.dm.DmContentCodec
import net.lapisphilosophorum.lapisnet.dm.DmDeliveryState
import net.lapisphilosophorum.lapisnet.dm.DmHistoryEntry
import net.lapisphilosophorum.lapisnet.dm.DmSendOutcome
import net.lapisphilosophorum.lapisnet.dm.DmSessionException
import net.lapisphilosophorum.lapisnet.dm.DmSessionManager
import net.lapisphilosophorum.lapisnet.dm.DmStore
import net.lapisphilosophorum.lapisnet.dm.EncryptedDmAttachmentBlobCodec
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.util.Base64

private val logger = KotlinLogging.logger {}

/**
 * V0.8.6b DM browser routes: `GET /api/dm`, `GET /api/dm/{peerHex}`, `POST /api/dm/{peerHex}`,
 * `POST /api/dm/{peerHex}/accept`, `GET /api/dm/attachment/{peerHex}/{cid}`. Kept in this dedicated
 * file for the exact same readability reason `MailApi.kt` gives for its own routes - see that
 * file's class doc comment, which applies verbatim here.
 *
 * **Wiring, not new capability.** Every byte this file moves already exists in `lapis-net-dm`
 * (`DmSessionManager.sendAuto`, `DmStore`, `DmAcceptedContacts`, `DmAttachmentCipher`,
 * `DmAttachmentFetcher`) - this file is the first caller that reaches any of it from outside a
 * test, exposing it as the `lapis-net-browser` JSON API the hand-written `dm.js` client renders.
 *
 * **CRITICAL SECURITY NOTE, identical in substance to `MailApi.kt`'s own:** [DmMessageResponse.body],
 * attachment names, and every peer-derived display string here are ENTIRELY sender-controlled
 * content that this node never sanitizes or interprets. The hand-written, framework-free `dm.js`
 * client MUST render every one of these fields via `textContent` - see `dm.js`'s own file-header
 * policy.
 *
 * **Explicit, deliberate scope cut for this wave (stated here, not silently omitted, mirroring
 * this module's established practice - see e.g. `MailApi.kt`'s `MAIL_BODY_PREVIEW_CHARS` doc
 * comment): no thread/reply UI.** [DmContent] carries no reply/thread reference at all (unlike
 * mail's `MessageEnvelope.replyTo`/`threadRoot`) - a flat, one-conversation-per-peer view is the
 * whole of the DM data model this wave, so there is nothing to build a thread view over.
 *
 * **Second explicit, deliberate scope cut: no [net.lapisphilosophorum.lapisnet.dm.DmAcceptanceCheck]
 * (gate-based) policy is configured anywhere `BrowserServer` wires this up.** `BrowserServer.start`
 * passes `acceptance = null` to both `DmSessionManager.attach` and (transitively, via
 * `mailboxGossip`) `MailboxGossip.attach` - the SAME state `lapis-net-mail`'s own
 * `MailAcceptanceCheck` is in (zero production callers anywhere in this codebase, only exercised by
 * its own unit tests). Consequences, so they are discovered by reading this comment rather than by
 * surprise:
 *   - [DmMessageResponse.quarantined] is unconditionally `false` in [toResponse] below - there is no
 *     `DmAcceptanceCheck` for [net.lapisphilosophorum.lapisnet.dm.DmSessionManager] to ever classify
 *     an inbound message as [net.lapisphilosophorum.lapisnet.dm.DmAcceptanceDecision.Quarantine], so
 *     `dm.js`'s quarantine badge can never render in this wave's real wiring.
 *   - `POST /api/dm/{peerHex}/accept` still functions - it flips [DmAcceptedContacts.isAccepted] for
 *     display purposes ([DmConversationSummary.accepted]) and would take effect immediately the day
 *     an `acceptance` gate policy IS wired (since `DmAcceptancePolicy.decide` checks
 *     `isAcceptedContact` unconditionally, independent of which gates are configured) - but until
 *     then it accepts a contact that was never actually gated in the first place.
 *   - [DmAcceptedContacts] itself IS wired into `DmSessionManager.attach`'s `acceptedContacts`
 *     parameter (unlike `acceptance`) - so an outbound send still correctly marks its recipient
 *     accepted (see [DmAcceptedContacts]'s own "this node itself sent that peer a message" doc
 *     comment half). Only the gate-evaluation half of V0.8.6's acceptance feature is unwired here.
 *
 * Wiring a real `acceptance` gate policy needs a live `TrustGraph` snapshot and a
 * `KarmaScoreLookup` sourced from this node's own veritas/karma gossip state - a genuine product
 * decision (which gates, which thresholds) intentionally left to a dedicated future wave rather
 * than invented as a side effect of a review pass.
 */

@Serializable
data class DmAttachmentSummary(
    val cid: String,
    val name: String,
    val mime: String,
    val size: Long,
)

@Serializable
data class DmMessageResponse(
    val direction: String,
    val body: String,
    val attachments: List<DmAttachmentSummary>,
    val epochSecond: Long,
    /** `true` only for an [DmHistoryEntry.Inbound] entry [net.lapisphilosophorum.lapisnet.dm.DmAcceptancePolicy]
     * quarantined - always `false` for [DmHistoryEntry.Outbound]. */
    val quarantined: Boolean,
    /** `null` for [DmHistoryEntry.Inbound] - mirrors [DmDeliveryState]'s own enum name for
     * `Outbound`. */
    val deliveryState: String?,
)

@Serializable
data class DmConversationSummary(
    val peerPublicKeyHex: String,
    val peerFingerprint: String,
    val lastMessage: DmMessageResponse,
    val accepted: Boolean,
)

@Serializable
data class NewDmAttachmentRequest(
    val name: String,
    val mime: String,
    /** Base64-encoded raw attachment bytes. */
    val contentBase64: String,
)

@Serializable
data class NewDmRequest(
    val body: String,
    val attachments: List<NewDmAttachmentRequest> = emptyList(),
)

@Serializable
data class NewDmResponse(
    val deliveryState: String,
)

@Serializable
data class DmAcceptResponse(
    val peerPublicKeyHex: String,
    val accepted: Boolean,
)

/**
 * Empty-but-present request body for `POST /api/dm/{peerHex}/accept` - V0.8.6b hardening-pass
 * finding. Every OTHER state-changing POST route in this module and `BrowserApi.kt`/`MailApi.kt`
 * calls `call.receive<...>()` on a real JSON body, which (per `installBrowserApi`'s own "no CORS
 * plugin installed" comment) incidentally requires a `Content-Type: application/json` request - a
 * type that forces the browser to run a CORS preflight before sending the real request, which then
 * fails (no `Access-Control-Allow-Origin` is ever emitted). A route with NO body requirement is
 * exempt from that incidental protection: a plain cross-origin `<form method="POST">` needs no
 * preflight at all and would silently reach this route from any web page the operator's own browser
 * visits while a `BrowserServer` is running locally (loopback-only bind does not help here - the
 * request originates from the victim's own browser, not a remote attacker). Requiring THIS body
 * (accepting any JSON object, even `{}`) closes that gap the same way every sibling route already
 * closes it, without adding a bespoke CSRF-token mechanism this single-user, loopback-only admin
 * API does not otherwise need.
 */
@Serializable
class DmAcceptRequest

/** **Deliberately NOT [MAX_MAIL_ATTACHMENT_UPLOAD_BYTES]'s value (25 MiB), unlike an earlier version
 * of this route.** Mail's 25 MiB route cap is STRICTER than mail's own wire-format ceiling
 * (`MessageBodyCodec.MAX_ATTACHMENT_SIZE_BYTES` = 1 GiB), so mail's cap rejects oversized uploads
 * cheaply, before any encryption or storage write. DM's wire-format ceiling is
 * [DmContentCodec.MAX_DM_ATTACHMENT_BYTES] (16 MiB) - reusing mail's 25 MiB value here would be
 * LOOSER than that, letting an oversized upload pass this route-level pre-check, get fully
 * encrypted, and get durably written to Nabu via `storage.put`, only to be rejected afterward by
 * [DmAttachmentRef]'s own `size in 1..MAX_DM_ATTACHMENT_BYTES` check - after the storage write
 * already happened, leaving an orphaned, never-referenced blob behind (worse: a fresh one on every
 * retry, since each encryption run mints a new key and thus a new CID). This constant is therefore
 * pinned to [DmContentCodec.MAX_DM_ATTACHMENT_BYTES] instead, so the cheap route-level check is
 * always at least as strict as the wire-format ceiling it exists to pre-empt. */
const val MAX_DM_ATTACHMENT_UPLOAD_BYTES = DmContentCodec.MAX_DM_ATTACHMENT_BYTES

/**
 * Everything [installDmRoutes] needs beyond [BrowserApiDependencies]' own `identity`/`storage` -
 * kept as its own bundle, rather than folded directly into [BrowserApiDependencies], so a caller
 * that does not want DM wired at all (e.g. an existing test fixture built before this wave) can
 * simply omit it: [BrowserApiDependencies.dm] defaults to `null`, and [installDmRoutes] is only
 * ever called when it is non-null (see `BrowserApi.kt`'s `installBrowserApi`).
 */
class DmApiDependencies(
    val peerDirectory: PeerDirectoryGossip,
    val dmSessionManager: DmSessionManager,
    val dmStore: DmStore,
    val dmAcceptedContacts: DmAcceptedContacts,
)

private fun DmHistoryEntry.toResponse(): DmMessageResponse =
    when (this) {
        is DmHistoryEntry.Inbound ->
            DmMessageResponse(
                direction = "inbound",
                body = content.body,
                attachments = content.attachments.map { it.toSummary() },
                epochSecond = epochSecond,
                quarantined = quarantined,
                deliveryState = null,
            )
        is DmHistoryEntry.Outbound ->
            DmMessageResponse(
                direction = "outbound",
                body = content.body,
                attachments = content.attachments.map { it.toSummary() },
                epochSecond = epochSecond,
                quarantined = false,
                deliveryState = deliveryState.name,
            )
    }

private fun DmAttachmentRef.toSummary(): DmAttachmentSummary =
    DmAttachmentSummary(cid = cid.toString(), name = name, mime = mime, size = size)

@Suppress("LongMethod", "CyclomaticComplexMethod")
internal fun Route.installDmRoutes(
    deps: DmApiDependencies,
    storage: NabuStorage,
    localPublicKey: Secp256k1PublicKey,
) {
    get("/api/dm") {
        val conversations =
            deps.dmStore.peers().mapNotNull { peer ->
                val last = deps.dmStore.lastEntryFor(peer) ?: return@mapNotNull null
                DmConversationSummary(
                    peerPublicKeyHex = peer.bytes.toHexString(),
                    peerFingerprint = peer.fingerprint(),
                    lastMessage = last.toResponse(),
                    accepted = deps.dmAcceptedContacts.isAccepted(peer),
                )
            }
        call.respond(conversations)
    }

    get("/api/dm/{peerHex}") {
        val peer = parseHexPublicKeyOrNull(call.parameters["peerHex"] ?: "")
        if (peer == null) {
            call.respond(HttpStatusCode.BadRequest, ErrorResponse("peerHex must be a valid secp256k1 public key hex"))
            return@get
        }
        call.respond(deps.dmStore.historyFor(peer).map { it.toResponse() })
    }

    post("/api/dm/{peerHex}") {
        val peer = parseHexPublicKeyOrNull(call.parameters["peerHex"] ?: "")
        if (peer == null) {
            call.respond(HttpStatusCode.BadRequest, ErrorResponse("peerHex must be a valid secp256k1 public key hex"))
            return@post
        }
        val request = call.receive<NewDmRequest>()

        val bodyBytes = request.body.toByteArray(Charsets.UTF_8)
        if (bodyBytes.size > DmContentCodec.MAX_DM_BODY_BYTES) {
            call.respond(
                HttpStatusCode.BadRequest,
                ErrorResponse("body must be at most ${DmContentCodec.MAX_DM_BODY_BYTES} UTF-8 bytes"),
            )
            return@post
        }
        if (request.attachments.size > DmContentCodec.MAX_DM_ATTACHMENTS) {
            call.respond(
                HttpStatusCode.BadRequest,
                ErrorResponse("at most ${DmContentCodec.MAX_DM_ATTACHMENTS} attachments allowed"),
            )
            return@post
        }
        for (attachment in request.attachments) {
            val nameBytes = attachment.name.toByteArray(Charsets.UTF_8)
            if (nameBytes.size !in 1..DmContentCodec.MAX_ATTACHMENT_NAME_BYTES) {
                call.respond(
                    HttpStatusCode.BadRequest,
                    ErrorResponse(
                        "attachment name must be 1..${DmContentCodec.MAX_ATTACHMENT_NAME_BYTES} UTF-8 bytes",
                    ),
                )
                return@post
            }
            val mimeBytes = attachment.mime.toByteArray(Charsets.UTF_8)
            if (mimeBytes.size !in 1..DmContentCodec.MAX_ATTACHMENT_MIME_BYTES) {
                call.respond(
                    HttpStatusCode.BadRequest,
                    ErrorResponse(
                        "attachment mime must be 1..${DmContentCodec.MAX_ATTACHMENT_MIME_BYTES} UTF-8 bytes",
                    ),
                )
                return@post
            }
            // Cheap upper bound BEFORE any Base64 decoding - mirrors MailApi.kt's identical
            // pre-check ordering for MAX_MAIL_ATTACHMENT_UPLOAD_BYTES.
            val approxDecodedSize = (attachment.contentBase64.length.toLong() * 3) / 4
            if (approxDecodedSize > MAX_DM_ATTACHMENT_UPLOAD_BYTES) {
                call.respond(
                    HttpStatusCode.BadRequest,
                    ErrorResponse(
                        "attachment '${attachment.name}' content exceeds the " +
                            "$MAX_DM_ATTACHMENT_UPLOAD_BYTES-byte upload limit",
                    ),
                )
                return@post
            }
        }

        val decodedAttachments =
            request.attachments.map { attachment ->
                val rawBytes =
                    runCatching { Base64.getDecoder().decode(attachment.contentBase64) }.getOrElse {
                        call.respond(
                            HttpStatusCode.BadRequest,
                            ErrorResponse("attachment '${attachment.name}' has malformed base64 content"),
                        )
                        return@post
                    }
                if (rawBytes.isEmpty()) {
                    call.respond(
                        HttpStatusCode.BadRequest,
                        ErrorResponse("attachment '${attachment.name}' content must not be empty"),
                    )
                    return@post
                }
                if (rawBytes.size.toLong() > MAX_DM_ATTACHMENT_UPLOAD_BYTES) {
                    call.respond(
                        HttpStatusCode.BadRequest,
                        ErrorResponse(
                            "attachment '${attachment.name}' content exceeds the " +
                                "$MAX_DM_ATTACHMENT_UPLOAD_BYTES-byte upload limit",
                        ),
                    )
                    return@post
                }
                attachment to rawBytes
            }

        // Total-size check BEFORE any encrypt/storage.put below - mirrors DmContent's own
        // MAX_DM_ATTACHMENT_TOTAL_BYTES require(), but run here so a request whose individual
        // attachments each pass MAX_DM_ATTACHMENT_UPLOAD_BYTES but whose SUM does not never reaches
        // DmAttachmentCipher.encrypt/storage.put in the first place - encrypting and durably writing
        // every attachment to Nabu only to have DmContent's constructor reject the total afterward
        // would leave every one of those blobs orphaned in the blockstore (same failure shape
        // MAX_DM_ATTACHMENT_UPLOAD_BYTES's own doc comment describes for a single oversized
        // attachment, generalized to the sum).
        val totalDecodedBytes = decodedAttachments.sumOf { (_, rawBytes) -> rawBytes.size.toLong() }
        if (totalDecodedBytes > DmContentCodec.MAX_DM_ATTACHMENT_TOTAL_BYTES) {
            call.respond(
                HttpStatusCode.BadRequest,
                ErrorResponse(
                    "total attachment size must be at most " +
                        "${DmContentCodec.MAX_DM_ATTACHMENT_TOTAL_BYTES} bytes",
                ),
            )
            return@post
        }

        // Every DM attachment is always encrypted - DmAttachmentRef.encryptionKey is non-nullable,
        // see that class's own doc comment (no "encrypt: Boolean" toggle, unlike mail's).
        val builtAttachments =
            try {
                decodedAttachments.map { (attachment, rawBytes) ->
                    val encrypted = DmAttachmentCipher.encrypt(rawBytes)
                    val cid = storage.put(EncryptedDmAttachmentBlobCodec.encode(encrypted.blob))
                    DmAttachmentRef(cid, attachment.name, attachment.mime, rawBytes.size.toLong(), encrypted.key)
                }
            } catch (e: IllegalArgumentException) {
                call.respond(HttpStatusCode.BadRequest, ErrorResponse("invalid attachment: ${e.message}"))
                return@post
            }

        val content =
            try {
                DmContent(request.body, builtAttachments)
            } catch (e: IllegalArgumentException) {
                call.respond(HttpStatusCode.BadRequest, ErrorResponse("invalid DM request: ${e.message}"))
                return@post
            }

        val outcome =
            try {
                deps.dmSessionManager.sendAuto(peer, content)
            } catch (e: DmSessionException) {
                logger.debug(e) { "DM send to ${peer.fingerprint()} failed" }
                call.respond(HttpStatusCode.BadGateway, ErrorResponse("DM send failed: ${e.message}"))
                return@post
            }

        val deliveryState =
            when (outcome) {
                DmSendOutcome.SENT_ONLINE -> DmDeliveryState.SENT
                DmSendOutcome.QUEUED_FOR_PICKUP -> DmDeliveryState.QUEUED_FOR_PICKUP
            }
        deps.dmStore.recordOutbound(peer, content, deliveryState)
        call.respond(NewDmResponse(deliveryState.name))
    }

    post("/api/dm/{peerHex}/accept") {
        val peer = parseHexPublicKeyOrNull(call.parameters["peerHex"] ?: "")
        if (peer == null) {
            call.respond(HttpStatusCode.BadRequest, ErrorResponse("peerHex must be a valid secp256k1 public key hex"))
            return@post
        }
        // See DmAcceptRequest's own doc comment - the body itself carries no information, it exists
        // solely to force a Content-Type: application/json request (and thus a CORS preflight this
        // loopback server never satisfies) before this state-changing action can run.
        call.receive<DmAcceptRequest>()
        deps.dmAcceptedContacts.accept(peer)
        call.respond(DmAcceptResponse(peerPublicKeyHex = peer.bytes.toHexString(), accepted = true))
    }

    // O(known-history) linear scan across both directions of the given peer's conversation,
    // mirroring MailApi.kt's `/api/mail/attachment/{cid}` route's identical "acceptable at this
    // codebase's established personal-node-scale tolerance" reasoning.
    get("/api/dm/attachment/{peerHex}/{cid}") {
        val peer = parseHexPublicKeyOrNull(call.parameters["peerHex"] ?: "")
        if (peer == null) {
            call.respond(HttpStatusCode.BadRequest, ErrorResponse("peerHex must be a valid secp256k1 public key hex"))
            return@get
        }
        val target = parseCidOrNull(call.parameters["cid"] ?: "")
        if (target == null) {
            call.respond(HttpStatusCode.BadRequest, ErrorResponse("cid is not a valid CID"))
            return@get
        }

        var foundRef: DmAttachmentRef? = null
        var foundSender: Secp256k1PublicKey? = null
        for (entry in deps.dmStore.historyFor(peer)) {
            val ref = entry.content.attachments.find { it.cid == target } ?: continue
            foundRef = ref
            // An Inbound entry's blob was fetched/dialed from the PEER; an Outbound entry's blob
            // was `storage.put` by this node itself and is always already local - either way,
            // DmAttachmentFetcher.fetchAndDecrypt tries the local blockstore first (see its own doc
            // comment), so passing the wrong "sender" for an Outbound entry never matters in
            // practice, but `peer` is the only externally-dialable identity a browser client can
            // supply here, so it is used uniformly for both directions.
            foundSender = if (entry is DmHistoryEntry.Inbound) entry.peer else localPublicKey
            break
        }
        if (foundRef == null || foundSender == null) {
            call.respond(HttpStatusCode.NotFound, ErrorResponse("attachment not found in this conversation"))
            return@get
        }

        val plaintext =
            DmAttachmentFetcher.fetchAndDecrypt(foundRef, foundSender, deps.peerDirectory, storage)
        if (plaintext == null) {
            call.respond(
                HttpStatusCode.NotFound,
                ErrorResponse("attachment blob is not available (unreachable sender, or decryption failed)"),
            )
            return@get
        }

        call.response.header(
            HttpHeaders.ContentDisposition,
            ContentDisposition.Attachment
                .withParameter(
                    ContentDisposition.Parameters.FileName,
                    foundRef.name,
                ).toString(),
        )
        val contentType =
            runCatching {
                ContentType.parse(
                    foundRef.mime,
                )
            }.getOrDefault(ContentType.Application.OctetStream)
        call.respondBytes(plaintext, contentType)
    }
}
