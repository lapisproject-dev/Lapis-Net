package net.lapisphilosophorum.lapisnet.browser

import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCallPipeline
import io.ktor.server.application.call
import io.ktor.server.request.header
import io.ktor.server.request.httpMethod
import io.ktor.server.request.path
import io.ktor.server.response.header
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.intercept

/** Name of the HttpOnly cookie that carries the [CallSessionToken] after the `/session` exchange. */
internal const val CALL_COOKIE_NAME = "lapis_call"

/** Upper bound for a `/api/call` POST body - every legitimate body is a few dozen bytes. */
internal const val CALL_MAX_BODY_BYTES = 4096L

internal const val CALL_BASE_PATH = "/api/call"

private const val CALL_SESSION_PATH = "$CALL_BASE_PATH/session"

private val MISDIRECTED_REQUEST = HttpStatusCode(421, "Misdirected Request")

private val LOOPBACK_HOST_NAMES = listOf("127.0.0.1", "localhost", "[::1]")

private class Rejection(
    val status: HttpStatusCode,
    val message: String,
)

/**
 * V0.8.7b - the gatekeeper in front of every `/api/call` route (NOT of the static pages or the older
 * `/api` routes). Checks run in this order, each one a hard rejection:
 *
 *  1. the server must already know its bound port (`503` before that);
 *  2. `Host` must be exactly `127.0.0.1:P`, `localhost:P` or `[::1]:P` (`421`) - defeats DNS rebinding,
 *     where an attacker's hostname resolves to 127.0.0.1;
 *  3. `Sec-Fetch-Site`, if present, must be `same-origin` or `none` (`403`);
 *  4. `Origin`, if present, must be one of the three loopback origins with port P (`403`), and is
 *     MANDATORY on POST. `SameSite=Strict` does not help here: cookies are scoped by site, not by port,
 *     so another page on `http://localhost:8080` is "same-site" with this one - `Origin` and
 *     `Sec-Fetch-Site` are the actual defence. This runs BEFORE a SSE slot is handed out, so foreign
 *     pages cannot exhaust the subscriber limit;
 *  5. POST bodies must be `application/json` (`415`), declare a length (`411`) of at most
 *     [CALL_MAX_BODY_BYTES] (`413`);
 *  6. except for `POST /api/call/session`, the path must be `/api/call/<scope>/...` (see
 *     [CallSessionToken.scope]) and the `lapis_call` cookie must match the token (`401`).
 *
 * No CORS header is ever emitted; every response carries `Cache-Control: no-store` and
 * `Referrer-Policy: no-referrer`.
 */
internal fun Route.installCallApiGuard(deps: CallApiDependencies) {
    intercept(ApplicationCallPipeline.Plugins) {
        call.response.header(HttpHeaders.CacheControl, "no-store")
        call.response.header("Referrer-Policy", "no-referrer")
        val rejection = evaluateCallGuard(call, deps)
        if (rejection != null) {
            call.respond(rejection.status, ErrorResponse(rejection.message))
            finish()
        }
    }
}

private fun evaluateCallGuard(
    call: io.ktor.server.application.ApplicationCall,
    deps: CallApiDependencies,
): Rejection? {
    val port = deps.expectedPort()
    if (port == 0) return Rejection(HttpStatusCode.ServiceUnavailable, "server not ready")

    val host = call.request.header(HttpHeaders.Host)?.lowercase()
    if (host == null || LOOPBACK_HOST_NAMES.none { host == "$it:$port" }) {
        return Rejection(MISDIRECTED_REQUEST, "unexpected host")
    }

    val fetchSite = call.request.header("Sec-Fetch-Site")
    if (fetchSite != null && fetchSite != "same-origin" && fetchSite != "none") {
        return Rejection(HttpStatusCode.Forbidden, "cross-site request refused")
    }

    val isPost = call.request.httpMethod == HttpMethod.Post
    val origin = call.request.header(HttpHeaders.Origin)
    if (origin == null) {
        if (isPost) return Rejection(HttpStatusCode.Forbidden, "origin required")
    } else if (LOOPBACK_HOST_NAMES.none { origin.lowercase() == "http://$it:$port" }) {
        return Rejection(HttpStatusCode.Forbidden, "origin not allowed")
    }

    if (isPost) {
        val contentType =
            call.request
                .header(HttpHeaders.ContentType)
                ?.substringBefore(';')
                ?.trim()
                ?.lowercase()
        if (contentType != "application/json") {
            return Rejection(HttpStatusCode.UnsupportedMediaType, "application/json required")
        }
        val length = call.request.header(HttpHeaders.ContentLength)?.toLongOrNull()
        if (length == null) return Rejection(HttpStatusCode.LengthRequired, "content-length required")
        if (length > CALL_MAX_BODY_BYTES) return Rejection(HttpStatusCode.PayloadTooLarge, "body too large")
    }

    val path = call.request.path()
    val isSessionExchange = isPost && path == CALL_SESSION_PATH
    if (!isSessionExchange) {
        // The cookie is only ever sent to /api/call/<scope>/..., see CallSessionToken.scope.
        if (!path.startsWith("$CALL_BASE_PATH/${deps.sessionToken.scope}/") ||
            !deps.sessionToken.matches(call.request.cookies[CALL_COOKIE_NAME])
        ) {
            return Rejection(HttpStatusCode.Unauthorized, "call session required")
        }
    }
    return null
}
