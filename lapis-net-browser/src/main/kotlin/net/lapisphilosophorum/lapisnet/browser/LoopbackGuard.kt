package net.lapisphilosophorum.lapisnet.browser

import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.header
import io.ktor.server.response.respond

private val LOOPBACK_NAMES = listOf("127.0.0.1", "localhost", "[::1]")

/**
 * V0.9.15 - the minimal request guard for routes that do not live under the call API's own guard but must not be
 * reachable through DNS rebinding or a cross-site request: `Host` must be a loopback name with the port this server is
 * actually bound to (when sent), `Sec-Fetch-Site` (if sent) must be same-origin/none, and `Origin` (if sent) must be a loopback
 * origin with that port. Responds and returns `false` when the request is refused.
 *
 * Browsers always send `Origin` on a cross-origin POST and on any `fetch` POST, so a page the operator visits cannot
 * reach a state-changing route unnoticed; a missing `Origin` can only come from a non-browser client on this machine.
 */
internal suspend fun ApplicationCall.requireLoopbackRequest(): Boolean {
    if (!requireLoopbackHost()) return false
    val port = request.local.localPort
    val fetchSite = request.header("Sec-Fetch-Site")
    if (fetchSite != null && fetchSite != "same-origin" && fetchSite != "none") {
        respond(HttpStatusCode.Forbidden, ErrorResponse("cross-site request refused"))
        return false
    }
    val origin = request.header(HttpHeaders.Origin)
    if (origin != null &&
        LOOPBACK_NAMES.none {
            origin.lowercase() == "http://$it:$port" ||
                (port == 80 && origin.lowercase() == "http://$it")
        }
    ) {
        respond(HttpStatusCode.Forbidden, ErrorResponse("origin not allowed"))
        return false
    }
    return true
}

/**
 * Host-only part of [requireLoopbackRequest], safe for read routes too: a DNS-rebinding page is same-origin from the
 * browser's view (so CORS and Origin/Sec-Fetch-Site do not stop it) but always carries its own attacker-controlled
 * `Host`. Installed globally for every `/api/` route in [installBrowserApi]. Responds 421 and returns `false` on mismatch.
 */
internal suspend fun ApplicationCall.requireLoopbackHost(): Boolean {
    val port = request.local.localPort
    val host = request.header(HttpHeaders.Host)?.lowercase()
    // A browser (and so a DNS-rebinding page) always sends Host; only a non-browser client on this machine can omit it.
    // A Host header omits the port when it is the HTTP default (80).
    if (host != null && LOOPBACK_NAMES.none { host == "$it:$port" || (port == 80 && host == it) }) {
        respond(HttpStatusCode(421, "Misdirected Request"), ErrorResponse("unexpected host"))
        return false
    }
    return true
}
