package net.lapisphilosophorum.lapisnet.browser

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldNotContain
import org.htmlunit.BrowserVersion
import org.htmlunit.ScriptResult
import org.htmlunit.WebClient
import org.htmlunit.html.DomNode
import org.htmlunit.html.HtmlButton
import org.htmlunit.html.HtmlPage
import java.time.Instant
import kotlin.time.Duration.Companion.seconds

private const val HOSTILE = "<img src=x onerror=\"window.__callXssFired=true\">"

private fun waitUntil(
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

/**
 * V0.10.0-G: the call page in anonymity mode, driven through the real `call.js` in HtmlUnit. The page's own node is a
 * normal-mode test server, so the media policy is injected through `applyStatus` - the exact function the status
 * response goes through.
 */
class CallAnonymityWarningUiTest :
    FunSpec({
        fun withPage(block: (page: HtmlPage, webClient: WebClient, remote: FakeCallRemote) -> Unit) {
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
                waitUntil(webClient, "status loaded") {
                    page.executeJavaScript("state.available").javaScriptResult == true
                }
                block(page, webClient, remote)
            } finally {
                webClient.close()
                runCatching { server.stop() }
            }
        }

        fun setMedia(
            page: HtmlPage,
            media: String?,
        ) {
            val field = if (media == null) "" else "callMedia: \"$media\", anonymity: \"on\","
            page.executeJavaScript("applyStatus({available: true, $field active: [], history: []}); render();")
        }

        fun submitPlace(
            page: HtmlPage,
            peer: String,
        ) {
            page.executeJavaScript(
                """document.getElementById("call-place-peer").value = "$peer";
                   document.getElementById("call-place-form").dispatchEvent(new Event("submit", {cancelable: true}));""",
            )
        }

        fun ring(
            page: HtmlPage,
            remote: FakeCallRemote,
            fingerprint: String = "abcdef0123456789",
        ): String {
            val id = randomCallId()
            val idHex = id.bytes.joinToString("") { "%02x".format(it) }
            remote.active = remote.active + remote.snapshot(id, randomPeer())
            page.executeJavaScript(
                """handleCallEvent({type: "incoming", callId: "$idHex", peer: "p", peerFingerprint: ${js(
                    fingerprint,
                )}})""",
            )
            return idHex
        }

        fun exposureBoxes(page: HtmlPage) = page.querySelectorAll(".call-exposure").size

        val peerHex = "02" + "ab".repeat(32)

        test("disabled: the form is locked, the band explains it in German and no request is ever made").config(
            timeout = 60.seconds,
        ) {
            withPage { page, _, remote ->
                setMedia(page, "disabled")
                page.getElementById("call-anonymity").isDisplayed shouldBe true
                page.getElementById("call-anonymity-title").textContent shouldBe "Anonymitätsmodus: Anrufe sind aus"
                page.getElementById("call-place-peer").getAttribute("disabled").isNotEmpty() shouldBe true
                page.getElementById("call-place-submit").getAttribute("disabled").isNotEmpty() shouldBe true
                submitPlace(page, peerHex)
                Thread.sleep(400)
                remote.totalMutatingCalls shouldBe 0
                exposureBoxes(page) shouldBe 0
            }
        }

        test(
            "exposed: place opens a confirmation, Abbrechen sends nothing, only the confirming button sends true",
        ).config(
            timeout = 90.seconds,
        ) {
            withPage { page, webClient, remote ->
                setMedia(page, "exposed")
                page.getElementById("call-anonymity").isDisplayed shouldBe true
                submitPlace(page, peerHex)
                exposureBoxes(page) shouldBe 1
                Thread.sleep(300)
                remote.totalMutatingCalls shouldBe 0
                val box = page.querySelector<DomNode>(".call-exposure")!!
                box.getAttributes().getNamedItem("role").nodeValue shouldBe "alertdialog"
                box
                    .getAttributes()
                    .getNamedItem("aria-labelledby")
                    .nodeValue
                    .isNotEmpty() shouldBe true
                // DOM order: Abbrechen first, the confirmation second; focus rests on Abbrechen
                val buttons = page.querySelectorAll(".call-exposure-actions button")
                buttons.size shouldBe 2
                buttons[0].textContent shouldBe "Abbrechen"
                buttons[1].textContent shouldBe "Anrufen – IP-Adresse wird sichtbar"
                page.executeJavaScript("document.activeElement.className").javaScriptResult.toString().contains(
                    "call-exposure-cancel",
                ) shouldBe true

                page.querySelector<HtmlButton>(".call-exposure-cancel")!!.click<HtmlPage>()
                exposureBoxes(page) shouldBe 0
                Thread.sleep(300)
                remote.totalMutatingCalls shouldBe 0

                // Escape closes an open confirmation as well, still without any request
                submitPlace(page, peerHex)
                exposureBoxes(page) shouldBe 1
                page.executeJavaScript(
                    """document.dispatchEvent(new KeyboardEvent("keydown", {key: "Escape", bubbles: true}))""",
                )
                exposureBoxes(page) shouldBe 0
                // Enter does nothing at all on an open confirmation
                submitPlace(page, peerHex)
                page.executeJavaScript(
                    """document.dispatchEvent(new KeyboardEvent("keydown", {key: "Enter", bubbles: true}))""",
                )
                exposureBoxes(page) shouldBe 1
                Thread.sleep(300)
                remote.totalMutatingCalls shouldBe 0

                page.querySelector<HtmlButton>(".call-exposure-confirm")!!.click<HtmlPage>()
                waitUntil(webClient, "place POST") { remote.placed.size == 1 }
                remote.placedConfirmed.toList() shouldBe listOf(true)

                // the next call asks again: the confirmation is never remembered
                submitPlace(page, peerHex)
                exposureBoxes(page) shouldBe 1
                Thread.sleep(300)
                remote.placed.size shouldBe 1
            }
        }

        test("exposed: Enter and Escape never act on a ringing card; Annehmen opens the confirmation first").config(
            timeout = 90.seconds,
        ) {
            withPage { page, webClient, remote ->
                setMedia(page, "exposed")
                val idHex = ring(page, remote)
                page.executeJavaScript(
                    """document.dispatchEvent(new KeyboardEvent("keydown", {key: "Enter", bubbles: true}))""",
                )
                page.executeJavaScript(
                    """document.dispatchEvent(new KeyboardEvent("keydown", {key: "Escape", bubbles: true}))""",
                )
                Thread.sleep(400)
                remote.totalMutatingCalls shouldBe 0

                page.querySelector<HtmlButton>(".call-accept")!!.click<HtmlPage>()
                exposureBoxes(page) shouldBe 1
                Thread.sleep(300)
                remote.accepted.size shouldBe 0
                // while the confirmation is open the accept button itself is locked
                page.querySelector<HtmlButton>(".call-accept")!!.isDisabled shouldBe true

                page.querySelector<HtmlButton>(".call-exposure-cancel")!!.click<HtmlPage>()
                exposureBoxes(page) shouldBe 0
                Thread.sleep(300)
                remote.accepted.size shouldBe 0

                page.querySelector<HtmlButton>(".call-accept")!!.click<HtmlPage>()
                page.querySelector<HtmlButton>(".call-exposure-confirm")!!.click<HtmlPage>()
                waitUntil(webClient, "accept POST") { remote.accepted.size == 1 }
                remote.acceptedConfirmed.toList() shouldBe listOf(true)

                // a second incoming call needs its own confirmation
                page.executeJavaScript(
                    """handleCallEvent({type: "ended", callId: "$idHex", peer: "p", peerFingerprint: "ff", reason: "LOCAL_HANGUP"})""",
                )
                ring(page, remote)
                page.querySelector<HtmlButton>(".call-accept")!!.click<HtmlPage>()
                exposureBoxes(page) shouldBe 1
                Thread.sleep(300)
                remote.accepted.size shouldBe 1
            }
        }

        test("exposed: nothing about the confirmation lands in localStorage, sessionStorage or cookies").config(
            timeout = 90.seconds,
        ) {
            withPage { page, webClient, remote ->
                setMedia(page, "exposed")
                ring(page, remote)
                page.querySelector<HtmlButton>(".call-accept")!!.click<HtmlPage>()
                page.querySelector<HtmlButton>(".call-exposure-confirm")!!.click<HtmlPage>()
                waitUntil(webClient, "accept POST") { remote.accepted.size == 1 }
                val dump =
                    page
                        .executeJavaScript(
                            """JSON.stringify([Object.keys(localStorage), Object.keys(sessionStorage), document.cookie])""",
                        ).javaScriptResult
                        .toString()
                dump shouldNotContain "onfirm"
                dump shouldNotContain "xposure"
                dump shouldNotContain "media"
            }
        }

        test(
            "a missing callMedia value is treated like exposed: the confirmation is required",
        ).config(timeout = 60.seconds) {
            withPage { page, _, remote ->
                setMedia(page, null)
                ring(page, remote)
                page.querySelector<HtmlButton>(".call-accept")!!.click<HtmlPage>()
                exposureBoxes(page) shouldBe 1
                Thread.sleep(300)
                remote.accepted.size shouldBe 0
            }
        }

        test(
            "direct: nothing changes - Annehmen accepts at once, Enter still accepts, no band",
        ).config(timeout = 60.seconds) {
            withPage { page, webClient, remote ->
                setMedia(page, "direct")
                page.getElementById("call-anonymity").isDisplayed shouldBe false
                ring(page, remote)
                page.executeJavaScript(
                    """document.dispatchEvent(new KeyboardEvent("keydown", {key: "Enter", bubbles: true}))""",
                )
                waitUntil(webClient, "enter accept") { remote.accepted.size == 1 }
                remote.acceptedConfirmed.toList() shouldBe listOf(false)
                exposureBoxes(page) shouldBe 0
            }
        }

        test("hostile fingerprints, reasons and block reasons stay inert text next to the confirmation").config(
            timeout = 60.seconds,
        ) {
            withPage { page, _, remote ->
                setMedia(page, "exposed")
                ring(page, remote, HOSTILE)
                page.querySelector<HtmlButton>(".call-accept")!!.click<HtmlPage>()
                page.executeJavaScript(
                    """handleCallEvent({type: "blocked", callId: "cd", peer: "p", peerFingerprint: ${js(HOSTILE)},
                        blockReason: ${js(HOSTILE)}})""",
                )
                ScriptResult.isUndefined(page.executeJavaScript("window.__callXssFired")) shouldBe true
                page.getElementsByTagName("img").size shouldBe 0
                page.querySelector<DomNode>("#call-history .call-history-outcome")!!.textContent shouldBe
                    "Blockiert – Annahmeregel"
            }
        }

        test("the new labels are fixed German texts: CIRCUIT_LOST, ANONYMITY_MODE and the two 409 codes").config(
            timeout = 60.seconds,
        ) {
            withPage { page, _, _ ->
                page.executeJavaScript(
                    """handleCallEvent({type: "ended", callId: "aa", peer: "p", peerFingerprint: "ff", reason: "CIRCUIT_LOST"})""",
                )
                page.querySelector<DomNode>("#call-history .call-history-outcome")!!.textContent shouldBe
                    "Verbindung abgebrochen"
                page.executeJavaScript(
                    """handleCallEvent({type: "blocked", callId: "bb", peer: "p", peerFingerprint: "ff", blockReason: "ANONYMITY_MODE"})""",
                )
                page.querySelector<DomNode>("#call-history .call-history-outcome")!!.textContent shouldBe
                    "Blockiert – Anrufe im Anonymitätsmodus aus"
                val text =
                    page
                        .executeJavaScript(
                            """errorText("Anruf fehlgeschlagen: ", {code: "CALL_MEDIA_DISABLED_IN_ANONYMITY_MODE", message: "english"})""",
                        ).javaScriptResult
                        .toString()
                text shouldNotContain "english"
                text shouldNotContain "Calls are not available"
            }
        }

        test("only the two confirmation handlers pass true: static check of call.js").config(timeout = 30.seconds) {
            val js =
                CallAnonymityWarningUiTest::class.java
                    .getResourceAsStream("/static/call.js")!!
                    .readBytes()
                    .toString(Charsets.UTF_8)
            val callsWithTrue = Regex("(postCallAction|postPlace)\\([^)]*true\\)").findAll(js).map { it.value }.toList()
            callsWithTrue.size shouldBe 2
            js
                .lines()
                .filterNot { it.trimStart().startsWith("//") }
                .joinToString("\n")
                .contains("innerHTML") shouldBe
                false
        }
    })

private fun js(value: String): String = "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"
