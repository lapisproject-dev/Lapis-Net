package net.lapisphilosophorum.lapisnet.browser

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
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.mail.AttachmentRef
import net.lapisphilosophorum.lapisnet.mail.EncryptedAttachmentBlobCodec
import net.lapisphilosophorum.lapisnet.mail.EncryptionMode
import net.lapisphilosophorum.lapisnet.mail.HybridEcies
import net.lapisphilosophorum.lapisnet.mail.InboxMessage
import net.lapisphilosophorum.lapisnet.mail.InboxPayload
import net.lapisphilosophorum.lapisnet.mail.MailAttachmentCipher
import net.lapisphilosophorum.lapisnet.mail.MessageBodyCodec
import net.lapisphilosophorum.lapisnet.mail.ThreadBuilder
import net.lapisphilosophorum.lapisnet.mail.ThreadNode
import net.lapisphilosophorum.lapisnet.mail.toInboxMessage
import java.util.Base64

/**
 * V0.9.3 mail browser routes: `GET /api/mail`, `GET /api/mail/sent`, `GET /api/mail/thread/{cid}`,
 * `POST /api/mail`, `GET /api/mail/attachment/{cid}`. Kept in this dedicated file rather than
 * inline in `BrowserApi.kt` purely for readability given the routes' combined size -
 * [installMailRoutes] is a plain `Route.()` extension called from inside `BrowserApi.kt`'s single
 * `routing { }` block, so it shares the exact same route tree every other route in this module is
 * installed into (no separate sub-routing, no separate plugin installation).
 *
 * **CRITICAL SECURITY NOTE for whoever renders these responses (`mail.html`/`mail.js`):** [subject],
 * [MailSummaryResponse.bodyPreview], attachment names, and every sender/recipient display string
 * here are ENTIRELY user-controlled content, carried verbatim from a signed [MessageBody] that this
 * node's own validator never sanitizes or interprets (see that class's doc comment: the Markdown
 * body is stored and returned VERBATIM, never rendered to HTML). The hand-written, framework-free
 * `mail.js` client MUST render every one of these fields via `textContent`/the shared `setText`
 * helper - see `mail.js`'s own file-header policy and `MailXssRenderingTest.kt`, which proves this
 * against the real rendering function, not just a description of intent.
 */

@Serializable
data class MailAttachmentSummary(
    val cid: String,
    val name: String,
    val mime: String,
    val size: Long,
    /** Whether this attachment carries its own [AttachmentRef.encryptionKey] - the key ITSELF is
     * never serialized into any HTTP response, only this boolean. */
    val encrypted: Boolean,
)

@Serializable
data class MailSummaryResponse(
    /** [net.lapisphilosophorum.lapisnet.mail.MessageEnvelope.contentCid], stringified - the stable
     * identifier used everywhere in this API (matches [NewMailRequest.replyToCid]'s own reference
     * type, see [ThreadBuilder]'s class doc comment for why `contentCid`, not `contentId()`, is the
     * correct id to expose here). */
    val cid: String,
    /** `"inbox"` or `"sent"`. */
    val folder: String,
    val sender: String,
    val senderPublicKeyHex: String,
    val recipients: List<String>,
    val sentAtEpochSeconds: Long,
    val encryption: String,
    val subject: String,
    /** First [MAIL_BODY_PREVIEW_CHARS] characters of the plaintext body, verbatim Markdown source -
     * NOT rendered to HTML anywhere on the server. See this file's class doc comment on the client's
     * matching escaping obligation. */
    val bodyPreview: String,
    val replyToCid: String?,
    val threadRootCid: String?,
    val attachments: List<MailAttachmentSummary>,
    /** `true` only for an inbox [EncryptionMode.HYBRID_ECIES] entry whose [HybridEcies.open] threw
     * - [subject]/[bodyPreview] are [MAIL_DECRYPTION_FAILED_MARKER] placeholders in that case and
     * [attachments] is always empty (never invent attachment data from a body that failed to
     * decrypt). Always `false` for `folder = "sent"` - the local sender always already holds the
     * plaintext (see `SentMessage`'s own doc comment). */
    val decryptionFailed: Boolean,
)

@Serializable
data class MailThreadNodeResponse(
    val summary: MailSummaryResponse,
    val depth: Int,
    val children: List<MailThreadNodeResponse>,
)

@Serializable
data class NewMailAttachmentRequest(
    val name: String,
    val mime: String,
    /** Base64-encoded raw attachment bytes. */
    val contentBase64: String,
    /** If `true`, this attachment is independently encrypted via [MailAttachmentCipher] before
     * storage - see that object's class doc comment for the always-fresh-key design decision. */
    val encrypt: Boolean = false,
)

@Serializable
data class NewMailRequest(
    val recipientsHex: List<String>,
    val subject: String,
    val body: String,
    val attachments: List<NewMailAttachmentRequest> = emptyList(),
    val headers: Map<String, String> = emptyMap(),
    val replyToCid: String? = null,
    val threadRootCid: String? = null,
    /** String, not the raw [EncryptionMode] enum - an unrecognized value 400s cleanly here instead
     * of failing with a generic deserialization 400 from `ContentNegotiation` with no field-level
     * error message. */
    val encryption: String = "NONE",
)

@Serializable
data class NewMailResponse(
    val cid: String,
)

/** Mirrors [CONTENT_UNAVAILABLE_MARKER]'s established naming/placement convention for this
 * module. */
const val MAIL_DECRYPTION_FAILED_MARKER = "<unable to decrypt>"

/** How many characters of a message's plaintext body [MailSummaryResponse.bodyPreview] carries -
 * a listing view, not the full message; `mail.js` never needs more than a preview for the
 * inbox/sent list (a full-message view is out of scope for this wave's UI). */
const val MAIL_BODY_PREVIEW_CHARS = 280

/** Route-level cap on `POST /api/mail`'s total per-attachment upload size, deliberately much
 * stricter than [MessageBodyCodec.MAX_ATTACHMENT_SIZE_BYTES]'s 1 GiB wire-format ceiling - this
 * route buffers the whole base64 JSON request body in memory via `call.receive<NewMailRequest>()`
 * before any of the wire-format's own checks ever run, so a much tighter practical bound is applied
 * here first. Checked against `contentBase64.length` (cheap, ~4/3 of the decoded size) BEFORE
 * calling [Base64.getDecoder]`.decode(...)`, never only after. */
const val MAX_MAIL_ATTACHMENT_UPLOAD_BYTES = 25L * 1024 * 1024

private fun InboxMessage.toSummary(
    folder: String,
    identity: Secp256k1KeyPair,
): MailSummaryResponse {
    val plaintextBody =
        when (val currentPayload = payload) {
            is InboxPayload.Plaintext -> currentPayload.body
            is InboxPayload.Sealed ->
                runCatching { HybridEcies.open(envelope, currentPayload.sealedBody, identity) }.getOrNull()
        }
    val decryptionFailed = plaintextBody == null
    val attachments =
        plaintextBody?.attachments.orEmpty().map { attachment ->
            MailAttachmentSummary(
                cid = attachment.cid.toString(),
                name = attachment.name,
                mime = attachment.mime,
                size = attachment.size,
                encrypted = attachment.encryptionKey != null,
            )
        }
    return MailSummaryResponse(
        cid = envelope.contentCid.toString(),
        folder = folder,
        sender = envelope.sender.fingerprint(),
        senderPublicKeyHex = envelope.sender.bytes.toHexString(),
        recipients = envelope.recipients.map { it.bytes.toHexString() },
        sentAtEpochSeconds = envelope.sentAtEpochSecond,
        encryption = envelope.encryption.name,
        subject = plaintextBody?.subject ?: MAIL_DECRYPTION_FAILED_MARKER,
        bodyPreview = plaintextBody?.body?.take(MAIL_BODY_PREVIEW_CHARS) ?: MAIL_DECRYPTION_FAILED_MARKER,
        replyToCid = envelope.replyTo?.toString(),
        threadRootCid = envelope.threadRoot?.toString(),
        attachments = attachments,
        decryptionFailed = decryptionFailed,
    )
}

/** [folderByContentId] is keyed by the hex-encoded [net.lapisphilosophorum.lapisnet.mail.MessageEnvelope.contentId]
 * (the envelope's own SHA-256 fingerprint, NOT [ThreadNode.contentCid]/`contentCid` - see
 * [ThreadBuilder]'s class doc comment on why those two are different, unrelated identifiers) -
 * built once by the route handler across both the inbox and sent sets, since [ThreadNode] itself
 * carries no folder information. */
private fun ThreadNode.toResponse(
    folderByContentId: Map<String, String>,
    identity: Secp256k1KeyPair,
): MailThreadNodeResponse {
    val folder = folderByContentId[message.envelope.contentId().toHexString()] ?: "inbox"
    return MailThreadNodeResponse(
        summary = message.toSummary(folder, identity),
        depth = depth,
        children = children.map { it.toResponse(folderByContentId, identity) },
    )
}

@Suppress("LongMethod", "CyclomaticComplexMethod")
internal fun Route.installMailRoutes(deps: BrowserApiDependencies) {
    get("/api/mail") {
        call.respond(deps.mailInbox.messages().map { it.toSummary("inbox", deps.identity.secp256k1KeyPair) })
    }

    get("/api/mail/sent") {
        call.respond(
            deps.sentFolder.latest().map { it.toInboxMessage().toSummary("sent", deps.identity.secp256k1KeyPair) },
        )
    }

    post("/api/mail") {
        val request = call.receive<NewMailRequest>()

        if (request.recipientsHex.isEmpty()) {
            call.respond(HttpStatusCode.BadRequest, ErrorResponse("recipientsHex must not be empty"))
            return@post
        }
        val parsedRecipients = mutableListOf<Secp256k1PublicKey>()
        for (hex in request.recipientsHex) {
            val recipient = parseHexPublicKeyOrNull(hex)
            if (recipient == null) {
                call.respond(
                    HttpStatusCode.BadRequest,
                    ErrorResponse("recipientsHex contains an invalid public key: $hex"),
                )
                return@post
            }
            parsedRecipients += recipient
        }

        val encryptionMode =
            when (request.encryption) {
                "NONE" -> EncryptionMode.NONE
                "HYBRID_ECIES" -> EncryptionMode.HYBRID_ECIES
                "MLS_ARCHIVE" -> {
                    call.respond(
                        HttpStatusCode.BadRequest,
                        ErrorResponse("encryption mode MLS_ARCHIVE is reserved and not implemented"),
                    )
                    return@post
                }
                else -> {
                    call.respond(
                        HttpStatusCode.BadRequest,
                        ErrorResponse("unknown encryption mode: ${request.encryption}"),
                    )
                    return@post
                }
            }

        val replyTo =
            request.replyToCid?.let {
                parseCidOrNull(it) ?: run {
                    call.respond(HttpStatusCode.BadRequest, ErrorResponse("replyToCid is not a valid CID"))
                    return@post
                }
            }
        val threadRoot =
            request.threadRootCid?.let {
                parseCidOrNull(it) ?: run {
                    call.respond(HttpStatusCode.BadRequest, ErrorResponse("threadRootCid is not a valid CID"))
                    return@post
                }
            }

        val subjectBytes = request.subject.toByteArray(Charsets.UTF_8)
        if (subjectBytes.size > MessageBodyCodec.MAX_SUBJECT_BYTES) {
            call.respond(
                HttpStatusCode.BadRequest,
                ErrorResponse("subject must be at most ${MessageBodyCodec.MAX_SUBJECT_BYTES} UTF-8 bytes"),
            )
            return@post
        }
        val bodyBytes = request.body.toByteArray(Charsets.UTF_8)
        if (bodyBytes.size > MessageBodyCodec.MAX_MARKDOWN_BYTES) {
            call.respond(
                HttpStatusCode.BadRequest,
                ErrorResponse("body must be at most ${MessageBodyCodec.MAX_MARKDOWN_BYTES} UTF-8 bytes"),
            )
            return@post
        }

        if (request.attachments.size > MessageBodyCodec.MAX_ATTACHMENTS) {
            call.respond(
                HttpStatusCode.BadRequest,
                ErrorResponse("at most ${MessageBodyCodec.MAX_ATTACHMENTS} attachments allowed"),
            )
            return@post
        }
        for (attachment in request.attachments) {
            val nameBytes = attachment.name.toByteArray(Charsets.UTF_8)
            if (nameBytes.size !in 1..MessageBodyCodec.MAX_ATTACHMENT_NAME_BYTES) {
                call.respond(
                    HttpStatusCode.BadRequest,
                    ErrorResponse(
                        "attachment name must be 1..${MessageBodyCodec.MAX_ATTACHMENT_NAME_BYTES} UTF-8 bytes",
                    ),
                )
                return@post
            }
            val mimeBytes = attachment.mime.toByteArray(Charsets.UTF_8)
            if (mimeBytes.size !in 1..MessageBodyCodec.MAX_ATTACHMENT_MIME_BYTES) {
                call.respond(
                    HttpStatusCode.BadRequest,
                    ErrorResponse(
                        "attachment mime must be 1..${MessageBodyCodec.MAX_ATTACHMENT_MIME_BYTES} UTF-8 bytes",
                    ),
                )
                return@post
            }
            // Cheap upper bound on the DECODED size (~3/4 of the base64 string length) checked
            // BEFORE any Base64 decoding happens below - see MAX_MAIL_ATTACHMENT_UPLOAD_BYTES's
            // doc comment for why this order matters.
            val approxDecodedSize = (attachment.contentBase64.length.toLong() * 3) / 4
            if (approxDecodedSize > MAX_MAIL_ATTACHMENT_UPLOAD_BYTES) {
                call.respond(
                    HttpStatusCode.BadRequest,
                    ErrorResponse(
                        "attachment '${attachment.name}' content exceeds the " +
                            "$MAX_MAIL_ATTACHMENT_UPLOAD_BYTES-byte upload limit",
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
                if (rawBytes.size.toLong() > MAX_MAIL_ATTACHMENT_UPLOAD_BYTES) {
                    call.respond(
                        HttpStatusCode.BadRequest,
                        ErrorResponse(
                            "attachment '${attachment.name}' content exceeds the " +
                                "$MAX_MAIL_ATTACHMENT_UPLOAD_BYTES-byte upload limit",
                        ),
                    )
                    return@post
                }
                attachment to rawBytes
            }

        val builtAttachments =
            decodedAttachments.map { (attachment, rawBytes) ->
                if (attachment.encrypt) {
                    val encrypted = MailAttachmentCipher.encrypt(rawBytes)
                    val cid = deps.storage.put(EncryptedAttachmentBlobCodec.encode(encrypted.blob))
                    AttachmentRef(
                        cid,
                        attachment.name,
                        attachment.mime,
                        rawBytes.size.toLong(),
                        encryptionKey = encrypted.key,
                    )
                } else {
                    AttachmentRef(deps.storage.put(rawBytes), attachment.name, attachment.mime, rawBytes.size.toLong())
                }
            }

        // Any residual IllegalArgumentException from MessageBody's own init block (e.g. an
        // over-long header key/value, or too many headers - not pre-validated above since
        // headers are a lower-traffic field) is caught here so it 400s cleanly instead of falling
        // through to the generic StatusPages 500 handler.
        val sent =
            try {
                deps.mailSender.send(
                    localIdentity = deps.identity.secp256k1KeyPair,
                    recipients = parsedRecipients,
                    subject = request.subject,
                    body = request.body,
                    attachments = builtAttachments,
                    headers = request.headers,
                    replyTo = replyTo,
                    threadRoot = threadRoot,
                    encryption = encryptionMode,
                )
            } catch (e: IllegalArgumentException) {
                call.respond(HttpStatusCode.BadRequest, ErrorResponse("invalid mail request: ${e.message}"))
                return@post
            }
        deps.sentFolder.add(sent)
        call.respond(NewMailResponse(sent.bodyCid.toString()))
    }

    get("/api/mail/thread/{cid}") {
        val target = parseCidOrNull(call.parameters["cid"] ?: "")
        if (target == null) {
            call.respond(HttpStatusCode.BadRequest, ErrorResponse("cid is not a valid CID"))
            return@get
        }

        val inboxMessages = deps.mailInbox.messages()
        val sentMessages = deps.sentFolder.latest().map { it.toInboxMessage() }
        val folderByContentId = HashMap<String, String>()
        inboxMessages.forEach { folderByContentId[it.envelope.contentId().toHexString()] = "inbox" }
        sentMessages.forEach { folderByContentId[it.envelope.contentId().toHexString()] = "sent" }

        val forest = ThreadBuilder.build(inboxMessages + sentMessages)
        val root = forest.threadContaining(target)
        if (root == null) {
            call.respond(HttpStatusCode.NotFound, ErrorResponse("no known thread contains this cid"))
            return@get
        }
        call.respond(root.toResponse(folderByContentId, deps.identity.secp256k1KeyPair))
    }

    // O(known-set) linear scan, decrypting on demand per call - acceptable at this codebase's
    // established "personal-node scale" tolerance (see e.g. InboxIndex's own "provisional, should
    // be revisited against real usage" doc comment); the same caveat applies here.
    get("/api/mail/attachment/{cid}") {
        val target = parseCidOrNull(call.parameters["cid"] ?: "")
        if (target == null) {
            call.respond(HttpStatusCode.BadRequest, ErrorResponse("cid is not a valid CID"))
            return@get
        }

        val known = deps.mailInbox.messages() + deps.sentFolder.latest().map { it.toInboxMessage() }
        val found =
            known.firstNotNullOfOrNull { msg ->
                val body =
                    when (val payload = msg.payload) {
                        is InboxPayload.Plaintext -> payload.body
                        is InboxPayload.Sealed ->
                            runCatching {
                                HybridEcies.open(msg.envelope, payload.sealedBody, deps.identity.secp256k1KeyPair)
                            }.getOrNull()
                    }
                body?.attachments?.find { it.cid == target }
            }
        if (found == null) {
            call.respond(HttpStatusCode.NotFound, ErrorResponse("attachment not found"))
            return@get
        }

        // Inherited NabuStorage/Kademlia cross-node fetch limitation - a node can only reliably
        // retrieve an attachment blob it already has locally (the sender's own node, or a node
        // that fetched it some other way). Documented here, not silently swallowed - see
        // NabuStorage.get's doc comment for the underlying provider-discovery gap.
        val blobBytes = runCatching { deps.storage.get(found.cid) }.getOrNull()
        if (blobBytes == null) {
            call.respond(
                HttpStatusCode.NotFound,
                ErrorResponse(
                    "attachment blob is not locally available (cross-node fetch is a known limitation - " +
                        "see NabuStorage.get's doc comment)",
                ),
            )
            return@get
        }

        val encryptionKey = found.encryptionKey
        val plaintext =
            if (encryptionKey != null) {
                val blob =
                    runCatching { EncryptedAttachmentBlobCodec.decode(blobBytes) }.getOrElse {
                        call.respond(HttpStatusCode.BadGateway, ErrorResponse("stored attachment blob is corrupt"))
                        return@get
                    }
                runCatching { MailAttachmentCipher.decrypt(blob, encryptionKey) }.getOrElse {
                    call.respond(HttpStatusCode.BadGateway, ErrorResponse("attachment decryption failed"))
                    return@get
                }
            } else {
                blobBytes
            }

        call.response.header(
            HttpHeaders.ContentDisposition,
            ContentDisposition.Attachment.withParameter(ContentDisposition.Parameters.FileName, found.name).toString(),
        )
        val contentType =
            runCatching {
                ContentType.parse(
                    found.mime,
                )
            }.getOrDefault(ContentType.Application.OctetStream)
        call.respondBytes(plaintext, contentType)
    }
}
