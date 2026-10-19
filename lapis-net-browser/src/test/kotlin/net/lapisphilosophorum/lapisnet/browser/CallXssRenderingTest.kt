package net.lapisphilosophorum.lapisnet.browser

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldNotContain
import org.htmlunit.BrowserVersion
import org.htmlunit.ScriptResult
import org.htmlunit.WebClient
import org.htmlunit.html.DomNode
import org.htmlunit.html.HtmlPage
import java.time.Instant
import kotlin.time.Duration.Companion.seconds

private const val PAYLOAD = "<img src=x onerror=\"window.__callXssFired=true\">"

/**
 * Drives the REAL `call.js` in a REAL JS/DOM-executing headless browser against a REAL
 * [BrowserServer] (fake call remote). Events are injected through call.js's global
 * `handleCallEvent` - the exact function the EventSource handlers call - so the reducer and the
 * renderer under test are the production code, while HtmlUnit's limited `EventSource` support is
 * not on the critical path (HtmlUnit's EventSource connects but does not stream; the SSE transport
 * itself is covered by CallSseTest and CallManagerBrowserIntegrationTest).
 */
class CallXssRenderingTest :
    FunSpec({
        fun withPage(
            block: (page: HtmlPage, webClient: WebClient, remote: FakeCallRemote, server: BrowserServer) -> Unit,
        ) {
            val remote = FakeCallRemote()
            val server = startCallTestServer(remote = remote)
            val webClient = WebClient(BrowserVersion.CHROME)
            try {
                webClient.options.isThrowExceptionOnScriptError = true
                webClient.options.isThrowExceptionOnFailingStatusCode = false
                webClient.options.isCssEnabled = false
                webClient.options.isFetchPolyfillEnabled = true
                val page =
                    webClient.getPage<HtmlPage>(
                        "http://127.0.0.1:${server.boundPort}/call.html#t=${server.callTokenForTesting.hex}",
                    )
                waitFor(webClient, "status loaded") {
                    ScriptResult.isUndefined(page.executeJavaScript("state.available")).not() &&
                        page.executeJavaScript("state.available").javaScriptResult == true
                }
                block(page, webClient, remote, server)
            } finally {
                webClient.close()
                runCatching { server.stop() }
            }
        }

        test(
            "the token fragment is removed from the address bar and exchanged for a session",
        ).config(timeout = 60.seconds) {
            withPage { page, _, _, server ->
                val href = page.executeJavaScript("location.href").javaScriptResult.toString()
                href shouldNotContain "#t="
                href shouldNotContain server.callTokenForTesting.hex
                page.executeJavaScript("state.available").javaScriptResult shouldBe true
            }
        }

        test(
            "hostile strings in events and history render as inert text and never execute",
        ).config(timeout = 60.seconds) {
            withPage { page, _, _, _ ->
                page.executeJavaScript(
                    """handleCallEvent({type: "ended", callId: "ab", peer: "p",
                        peerFingerprint: ${jsString(PAYLOAD)}, reason: ${jsString(PAYLOAD)}})""",
                )
                ScriptResult.isUndefined(page.executeJavaScript("window.__callXssFired")) shouldBe true
                page.getElementsByTagName("img").size shouldBe 0
                // the peer column shows the (truncated) fingerprint, still as inert text
                page.querySelector<DomNode>("#call-history .call-history-peer")!!.textContent shouldBe
                    PAYLOAD.take(8) + "\u2026" + PAYLOAD.takeLast(6)
                page.querySelector<DomNode>("#call-history .call-history-outcome")!!.textContent shouldBe PAYLOAD
                page.asXml().contains("&lt;img src=x onerror=") shouldBe true
            }
        }

        test("a ringing call shows Decline before Accept, retitles the page and Accept fires exactly once").config(
            timeout = 60.seconds,
        ) {
            withPage { page, webClient, remote, _ ->
                val peer = randomPeer()
                val id = randomCallId()
                val idHex = id.bytes.joinToString("") { "%02x".format(it) }
                remote.active = listOf(remote.snapshot(id, peer))
                page.executeJavaScript(
                    """handleCallEvent({type: "incoming", callId: "$idHex", peer: "p", peerFingerprint: "abcdef0123456789"})""",
                )
                page.getElementById("call-ringing").isDisplayed shouldBe true
                val buttons = page.querySelectorAll("#call-ringing-list .call-card-actions button")
                buttons.size shouldBe 2
                buttons[0].textContent shouldBe "Ablehnen"
                buttons[1].textContent shouldBe "Annehmen"
                page.titleText shouldBe "Eingehender Anruf · Lapis Net"

                val accept = page.querySelector<org.htmlunit.html.HtmlButton>(".call-accept")!!
                accept.click<HtmlPage>()
                runCatching { accept.click<HtmlPage>() }
                waitFor(webClient, "accept POST") { remote.accepted.size >= 1 }
                Thread.sleep(500)
                remote.accepted.size shouldBe 1
                page.querySelector<org.htmlunit.html.HtmlButton>(".call-accept")!!.isDisabled shouldBe true

                page.executeJavaScript(
                    """handleCallEvent({type: "ended", callId: "$idHex", peer: "p", peerFingerprint: "abcdef0123456789", reason: "LOCAL_HANGUP"})""",
                )
                page.titleText shouldBe "Lapis Net - Anrufe"
            }
        }

        test("Enter accepts only when exactly one call rings and no input has focus").config(timeout = 60.seconds) {
            withPage { page, webClient, remote, _ ->
                val one = randomCallId().bytes.joinToString("") { "%02x".format(it) }
                val two = randomCallId().bytes.joinToString("") { "%02x".format(it) }
                remote.active =
                    listOf(
                        remote.snapshot(
                            net.lapisphilosophorum.lapisnet.call.CallId
                                .of(hexBytes(one)),
                            randomPeer(),
                        ),
                        remote.snapshot(
                            net.lapisphilosophorum.lapisnet.call.CallId
                                .of(hexBytes(two)),
                            randomPeer(),
                        ),
                    )

                fun ring(id: String) =
                    page.executeJavaScript(
                        """handleCallEvent({type: "incoming", callId: "$id", peer: "p", peerFingerprint: "ff"})""",
                    )

                fun pressEnter() =
                    page.executeJavaScript(
                        """document.dispatchEvent(new KeyboardEvent("keydown", {key: "Enter", bubbles: true}))""",
                    )

                // two ringing -> nothing happens
                ring(one)
                ring(two)
                pressEnter()
                Thread.sleep(500)
                remote.accepted.size shouldBe 0

                // back to one ringing, but with an input focused -> nothing happens
                page.executeJavaScript(
                    """handleCallEvent({type: "ended", callId: "$two", peer: "p", peerFingerprint: "ff", reason: "DECLINED"})""",
                )
                page.executeJavaScript("""document.getElementById("call-place-peer").focus()""")
                pressEnter()
                Thread.sleep(500)
                remote.accepted.size shouldBe 0

                // one ringing, focus on the body -> accepts
                page.executeJavaScript("""document.getElementById("call-place-peer").blur()""")
                pressEnter()
                waitFor(webClient, "enter accept") { remote.accepted.size == 1 }
            }
        }

        test("a blocked attempt is a muted history row without any button").config(timeout = 60.seconds) {
            withPage { page, _, _, _ ->
                page.executeJavaScript(
                    """handleCallEvent({type: "blocked", callId: "cd", peer: "p", peerFingerprint: "badbadbadbadbad0"})""",
                )
                val row = page.querySelector<DomNode>("#call-history .call-history-item")!!
                row
                    .getAttributes()
                    .getNamedItem("class")
                    .nodeValue
                    .contains("call-history--blocked") shouldBe true
                row.querySelectorAll("button").size shouldBe 0
                page.getElementById("call-ringing").isDisplayed shouldBe false
            }
        }

        test("call.html forbids framing").config(timeout = 60.seconds) {
            withPage { page, _, _, _ ->
                page.webResponse.getResponseHeaderValue("X-Frame-Options") shouldBe "DENY"
                page.webResponse.getResponseHeaderValue("Content-Security-Policy") shouldBe "frame-ancestors 'none'"
            }
        }
    })

private fun jsString(value: String): String = "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"

private fun hexBytes(hex: String): ByteArray =
    ByteArray(hex.length / 2) {
        hex.substring(it * 2, it * 2 + 2).toInt(16).toByte()
    }

private fun waitFor(
    webClient: WebClient,
    what: String,
    condition: () -> Boolean,
) {
    val deadline = Instant.now().plusSeconds(20)
    while (Instant.now().isBefore(deadline)) {
        webClient.waitForBackgroundJavaScript(300)
        if (condition()) return
    }
    error("timed out waiting for: $what")
}
