@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.lapisphilosophorum.lapisnet.browser

import io.ktor.http.ContentType
import io.ktor.http.Cookie
import io.ktor.http.HttpStatusCode
import io.ktor.server.plugins.BadRequestException
import io.ktor.server.plugins.ContentTransformationException
import io.ktor.server.request.receive
import io.ktor.server.response.header
import io.ktor.server.response.respond
import io.ktor.server.response.respondBytesWriter
import io.ktor.server.routing.Route
import io.ktor.server.routing.RoutingContext
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.route
import io.ktor.utils.io.writeStringUtf8
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.ChannelResult
import kotlinx.coroutines.selects.onTimeout
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import net.lapisphilosophorum.lapisnet.call.CallId
import net.lapisphilosophorum.lapisnet.core.ratelimit.FixedWindowRateLimiter
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.time.Duration
import kotlin.time.Duration.Companion.seconds

/** Maximum number of history rows `/api/call/status` returns. */
internal const val CALL_STATUS_HISTORY_LIMIT = 50

@Serializable
data class CallSessionRequest(
    val token: String,
)

/** Response of `POST /api/call/session`: the secret path segment all other call routes live under. */
@Serializable
data class CallSessionResponse(
    val scope: String,
)

@Serializable
data class CallPlaceRequest(
    val peer: String,
)

/** Empty-but-present body of accept/reject/hangup - requiring a JSON body (together with the guard's
 * `Content-Type`/`Origin` checks) keeps these routes out of reach of plain cross-site form posts. */
@Serializable
class CallActionRequest

@Serializable
data class CallPlaceResponse(
    val callId: String,
)

@Serializable
data class CallSnapshotDto(
    val callId: String,
    val peer: String,
    val peerFingerprint: String,
    val state: String,
)

@Serializable
data class CallHistoryDto(
    val callId: String,
    val peer: String,
    val peerFingerprint: String,
    val outcome: String,
    val atEpochSecond: Long,
    val blocked: Boolean,
    /** [CallBlockReason] name for a blocked entry, else `null`. Local display only, never sent to the peer. */
    val blockReason: String? = null,
)

@Serializable
data class CallStatusResponse(
    val available: Boolean,
    val active: List<CallSnapshotDto>,
    val history: List<CallHistoryDto>,
)

/** One SSE message. [type] is `incoming|ringing|connecting|active|ended|blocked`; every string is
 * rendered by `call.js` via `textContent` only. */
@Serializable
data class CallUiEvent(
    val type: String,
    val callId: String,
    val peer: String,
    val peerFingerprint: String,
    val reason: String? = null,
    val unaccepted: Boolean = false,
    /** [CallBlockReason] name, set only for `blocked`. Local display only, never sent to the peer. */
    val blockReason: String? = null,
)

/**
 * Everything [installCallRoutes] needs. [remote]/[hub] are `null` when this node has no usable media
 * engine - `/status` then reports `available = false` and every mutating route answers `503`.
 */
class CallApiDependencies(
    val remote: CallRemote?,
    val hub: CallEventHub?,
    val ownPublicKey: Secp256k1PublicKey,
    val sessionToken: CallSessionToken,
    /** The port the HTTP engine really bound; `0` until known (the guard then answers `503`). */
    val expectedPort: () -> Int,
    val heartbeatInterval: kotlin.time.Duration = 15.seconds,
)

private val sseJson = Json { encodeDefaults = true }

private val sessionAttemptWindow = Duration.ofSeconds(60)
private const val SESSION_ATTEMPTS_PER_WINDOW = 10

private fun parseCallIdOrNull(hex: String): CallId? {
    if (hex.length != CallId.SIZE * 2) return null
    val bytes = ByteArray(CallId.SIZE)
    for (i in bytes.indices) {
        val hi = Character.digit(hex[i * 2], 16)
        val lo = Character.digit(hex[i * 2 + 1], 16)
        if (hi < 0 || lo < 0) return null
        bytes[i] = ((hi shl 4) or lo).toByte()
    }
    return try {
        CallId.of(bytes)
    } catch (_: IllegalArgumentException) {
        null
    }
}

/** Receives a JSON body; any parse problem becomes a `400` here, because the global `StatusPages`
 * handler would otherwise turn it into a `500`. */
private suspend inline fun <reified T : Any> RoutingContext.receiveOrBadRequest(): T? =
    try {
        call.receive<T>()
    } catch (_: ContentTransformationException) {
        call.respond(HttpStatusCode.BadRequest, ErrorResponse("malformed request body"))
        null
    } catch (_: BadRequestException) {
        call.respond(HttpStatusCode.BadRequest, ErrorResponse("malformed request body"))
        null
    } catch (_: SerializationException) {
        call.respond(HttpStatusCode.BadRequest, ErrorResponse("malformed request body"))
        null
    }

internal fun Route.installCallRoutes(deps: CallApiDependencies) {
    val sessionLimiter = FixedWindowRateLimiter(SESSION_ATTEMPTS_PER_WINDOW, sessionAttemptWindow)
    route(CALL_BASE_PATH) {
        installCallApiGuard(deps)

        post("/session") {
            val request = receiveOrBadRequest<CallSessionRequest>() ?: return@post
            // Only FAILED attempts count against the limiter and a correct token is never throttled:
            // otherwise any local process could lock the legitimate user out with wrong guesses.
            if (!deps.sessionToken.matches(request.token)) {
                if (!sessionLimiter.tryAcquire()) {
                    call.respond(HttpStatusCode.TooManyRequests, ErrorResponse("too many attempts"))
                } else {
                    call.respond(HttpStatusCode.Forbidden, ErrorResponse("invalid token"))
                }
                return@post
            }
            // No `Secure` flag: the connection is plain HTTP over loopback (a Secure cookie would
            // never be sent back). Cookies are not separated by port, so the cookie Path is the secret
            // /api/call/<scope> prefix: servers on other loopback ports cannot name a URL it is sent to.
            call.response.cookies.append(
                Cookie(
                    name = CALL_COOKIE_NAME,
                    value = deps.sessionToken.hex,
                    httpOnly = true,
                    path = "$CALL_BASE_PATH/${deps.sessionToken.scope}",
                    extensions = mapOf("SameSite" to "Strict"),
                ),
            )
            call.respond(CallSessionResponse(deps.sessionToken.scope))
        }

        route("/{scope}") {
            get("/status") {
                val remote = deps.remote
                if (remote == null) {
                    call.respond(CallStatusResponse(available = false, active = emptyList(), history = emptyList()))
                    return@get
                }
                val active =
                    withContext(Dispatchers.IO) { remote.activeCalls() }.map {
                        CallSnapshotDto(
                            it.callId.bytes.toHexString(),
                            it.peer.bytes.toHexString(),
                            it.peer.fingerprint(),
                            it.state.name,
                        )
                    }
                val ended =
                    remote.callHistory().map {
                        CallHistoryDto(
                            it.callId.bytes.toHexString(),
                            it.peer.bytes.toHexString(),
                            it.peer.fingerprint(),
                            it.reason.name,
                            it.endedAtEpochSecond,
                            blocked = false,
                        )
                    }
                val blocked =
                    deps.hub?.blockedAttempts().orEmpty().map {
                        CallHistoryDto(
                            it.callId.bytes.toHexString(),
                            it.peer.bytes.toHexString(),
                            it.peer.fingerprint(),
                            "BLOCKED",
                            it.atEpochSecond,
                            blocked = true,
                            blockReason = it.reason.name,
                        )
                    }
                val history =
                    (ended + blocked)
                        .sortedByDescending { it.atEpochSecond }
                        .take(CALL_STATUS_HISTORY_LIMIT)
                call.respond(CallStatusResponse(available = true, active = active, history = history))
            }

            post("/place") {
                val remote = deps.remote ?: return@post call.respondUnavailable()
                val request = receiveOrBadRequest<CallPlaceRequest>() ?: return@post
                val peer = parseHexPublicKeyOrNull(request.peer)
                if (peer == null || peer.bytes.contentEquals(deps.ownPublicKey.bytes)) {
                    call.respond(HttpStatusCode.BadRequest, ErrorResponse("invalid peer"))
                    return@post
                }
                val callId = remote.placeCall(peer)
                call.respond(HttpStatusCode.Accepted, CallPlaceResponse(callId.bytes.toHexString()))
            }

            post("/{callId}/accept") { handleAction(deps) { remote, id -> remote.acceptCall(id) } }
            post("/{callId}/reject") { handleAction(deps) { remote, id -> remote.rejectCall(id) } }
            post("/{callId}/hangup") { handleAction(deps) { remote, id -> remote.hangUp(id) } }

            get("/events") {
                val hub = deps.hub
                if (hub == null) {
                    call.respondUnavailable()
                    return@get
                }
                // Slot BEFORE any header is sent (hence respondBytesWriter instead of the SSE plugin,
                // which commits headers first): a refused subscriber gets a clean 429.
                val subscription = hub.trySubscribe()
                if (subscription == null) {
                    call.respond(HttpStatusCode.TooManyRequests, ErrorResponse("too many event streams"))
                    return@get
                }
                try {
                    call.response.header("X-Accel-Buffering", "no")
                    call.respondBytesWriter(contentType = ContentType.Text.EventStream) {
                        try {
                            writeStringUtf8("retry: 3000\n\n")
                            flush()
                            while (true) {
                                // select (not a timeout-wrapped receive): a cancelled receive can take an
                                // element off the channel and still throw, silently losing the event.
                                val result =
                                    select<ChannelResult<CallUiEvent>?> {
                                        subscription.events.onReceiveCatching { it }
                                        onTimeout(deps.heartbeatInterval) { null }
                                    }
                                if (result == null) {
                                    writeStringUtf8(": ping\n\n")
                                } else if (result.isClosed) {
                                    break
                                } else {
                                    val event = result.getOrThrow()
                                    writeStringUtf8(
                                        "event: ${event.type}\ndata: ${sseJson.encodeToString(
                                            CallUiEvent.serializer(),
                                            event,
                                        )}\n\n",
                                    )
                                }
                                flush()
                            }
                        } finally {
                            subscription.close()
                        }
                    }
                } finally {
                    subscription.close()
                }
            }
        }
    }
}

private suspend fun io.ktor.server.application.ApplicationCall.respondUnavailable() {
    respond(HttpStatusCode.ServiceUnavailable, ErrorResponse("calls are not available on this node"))
}

private suspend fun RoutingContext.handleAction(
    deps: CallApiDependencies,
    action: (CallRemote, CallId) -> Unit,
) {
    val remote = deps.remote
    if (remote == null) {
        call.respondUnavailable()
        return
    }
    receiveOrBadRequest<CallActionRequest>() ?: return
    val id = call.parameters["callId"]?.let(::parseCallIdOrNull)
    if (id == null) {
        call.respond(HttpStatusCode.BadRequest, ErrorResponse("invalid call id"))
        return
    }
    // A blocked (silently dropped) INVITE must never reach the manager, not even as a no-op.
    if (deps.hub?.isBlocked(id) == true) {
        call.respond(HttpStatusCode.NotFound, ErrorResponse("unknown call"))
        return
    }
    val known = withContext(Dispatchers.IO) { remote.activeCalls() }.any { it.callId == id }
    if (!known) {
        call.respond(HttpStatusCode.NotFound, ErrorResponse("unknown call"))
        return
    }
    // A race between the check above and this call is harmless: CallManager treats it as a no-op.
    action(remote, id)
    call.respond(HttpStatusCode.Accepted)
}
