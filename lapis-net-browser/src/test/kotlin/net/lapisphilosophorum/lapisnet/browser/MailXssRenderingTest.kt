package net.lapisphilosophorum.lapisnet.browser

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.contentType
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.karma.BitcoinTimeAnchorSource
import net.lapisphilosophorum.lapisnet.karma.TimeAnchorLookupResult
import org.htmlunit.BrowserVersion
import org.htmlunit.ScriptResult
import org.htmlunit.WebClient
import org.htmlunit.html.DomNode
import org.htmlunit.html.HtmlPage
import java.nio.file.Files
import java.time.Duration
import java.time.Instant
import java.util.Base64
import kotlin.time.Duration.Companion.seconds

private val json = Json { ignoreUnknownKeys = true }

private object XssTestNoAnchorSource : BitcoinTimeAnchorSource {
    override fun findFirstOutgoingTransaction(pubkey: Secp256k1PublicKey): TimeAnchorLookupResult =
        TimeAnchorLookupResult.NotFound

    override fun currentChainTipHeight(): Int = 0
}

/**
 * Proves - against the REAL `mail.js` rendering code running inside a REAL, JS/DOM-executing
 * headless browser ([org.htmlunit.WebClient], not a mock or a description of intent) - that an
 * XSS payload in a message's subject/body is rendered as inert, escaped text, never as live markup
 * or an executed script. See `MailApi.kt`'s class doc comment and `mail.js`'s own file-header policy
 * for the escaping discipline this test verifies.
 *
 * **Why this targets `GET /api/mail/sent`'s rendering path (the "Sent" toggle in `mail.html`), not
 * `GET /api/mail`'s:** composing a message addresses RECIPIENTS, and GossipSub never self-delivers
 * (a documented gap since V0.9.1 - see `InboxGossip`'s class doc comment) - so exercising the
 * inbox-rendering path from a single node would require either a two-node gossip round trip (adds
 * flakiness/time to what should be a fast, deterministic security regression test) or targeting
 * `/sent`, which is populated SYNCHRONOUSLY by the same `POST /api/mail` call with zero gossip
 * involved. `mail.js`'s rendering function for an inbox item and a sent item is the exact SAME
 * function (`renderMailItem`/`fillSummaryInto`, both consuming a `MailSummaryResponse`), so this is
 * a fully faithful test of the identical rendering code path a received message would go through.
 */
class MailXssRenderingTest :
    FunSpec({
        test(
            "an XSS payload in a sent message's subject and body renders as escaped, inert text - never executes",
        ).config(
            timeout = 60.seconds,
        ) {
            val identity = DualKeyIdentity.generate()
            val server =
                BrowserServer.start(
                    identity = identity,
                    httpPort = 0,
                    dataDirectory = Files.createTempDirectory("mail-xss-rendering-test"),
                    karmaAnchorSource = XssTestNoAnchorSource,
                )
            val httpClient = HttpClient(CIO)
            val webClient = WebClient(BrowserVersion.CHROME)

            try {
                val xssSubject = "<script>window.__xssFired = true;</script>"
                val xssBody = "<img src=x onerror=\"window.__xssFired = true\">"

                val recipient = DualKeyIdentity.generate()
                runBlocking {
                    val sendResponse =
                        httpClient.post("http://127.0.0.1:${server.boundPort}/api/mail") {
                            contentType(ContentType.Application.Json)
                            setBody(
                                json.encodeToString(
                                    NewMailRequest(
                                        recipientsHex =
                                            listOf(
                                                recipient.secp256k1KeyPair.publicKey.bytes.joinToString("") {
                                                    "%02x".format(it)
                                                },
                                            ),
                                        subject = xssSubject,
                                        body = xssBody,
                                    ),
                                ),
                            )
                        }
                    sendResponse.status.value shouldBe 200
                }

                webClient.options.isThrowExceptionOnScriptError = true
                webClient.options.isThrowExceptionOnFailingStatusCode = false
                webClient.options.isCssEnabled = false
                // mail.js uses the real fetch() API (see this class's doc comment on why the file
                // is Promise/.then()-based) - HtmlUnit's embedded engine does not implement fetch()
                // natively and needs its bundled polyfill turned on explicitly.
                webClient.options.isFetchPolyfillEnabled = true

                val page = webClient.getPage<HtmlPage>("http://127.0.0.1:${server.boundPort}/mail.html")
                webClient.waitForBackgroundJavaScript(5_000)

                // Switch to the Sent folder (populated synchronously, no gossip needed - see this
                // class's doc comment) and give the resulting fetch()+render a bounded amount of
                // time to complete.
                val sentButton = page.getElementById("folder-sent-button")
                sentButton.click<HtmlPage>()

                val deadline = Instant.now().plus(Duration.ofSeconds(20))
                var subjectText: String? = null
                while (Instant.now().isBefore(deadline)) {
                    webClient.waitForBackgroundJavaScript(500)
                    val subjectElement = page.querySelector<DomNode>(".mail-item .mail-subject")
                    val candidate = subjectElement?.textContent
                    if (!candidate.isNullOrBlank()) {
                        subjectText = candidate
                        break
                    }
                    runBlocking { delay(200) }
                }

                // 1. The injected script/onerror handler never ran - proves the payload was never
                // interpreted as live markup by the real browser engine, not merely that the HTTP
                // response body happened to contain escaped characters. A never-set global reads
                // back as JS `undefined` (Rhino's Undefined singleton, not a Java null) -
                // ScriptResult.isUndefined is the correct check for that, mirroring how this
                // codebase would check any other "never happened" JS-side condition via HtmlUnit.
                val xssFiredResult = page.executeJavaScript("window.__xssFired")
                ScriptResult.isUndefined(xssFiredResult) shouldBe true

                // 2. The rendered DOM node's own text content is the LITERAL payload string - a
                // live-inert text node, exactly what a correct textContent assignment produces.
                subjectText shouldBe xssSubject

                // 3. No injected <script> element exists anywhere in the page beyond mail.js's own
                // <script src> tag - if the payload had been innerHTML'd instead of textContent'd,
                // the browser would have parsed and inserted a real <script> element here.
                val scriptTags = page.getElementsByTagName("script")
                scriptTags.size shouldBe 1
                scriptTags.single().getAttribute("src") shouldContain "/mail.js"

                // 4. The serialized DOM shows the payload HTML-entity-escaped, not raw markup -
                // confirms escaping happened at the DOM layer, not just "the browser engine
                // happened not to run it this time".
                page.asXml() shouldContain "&lt;script&gt;"
            } finally {
                webClient.close()
                httpClient.close()
                runCatching { server.stop() }
            }
        }

        test(
            "an XSS payload in a sent message's attachment name renders as escaped, inert text - never executes",
        ).config(
            timeout = 60.seconds,
        ) {
            // Mirrors the subject/body test above exactly, but targets renderAttachmentsInto's
            // setText(linkEl, attachment.name) call in mail.js - a DIFFERENT rendering call site
            // from fillSummaryInto's subject/body setText calls, reached via a different response
            // field (MailSummaryResponse.attachments[].name), so proving subject/body is inert says
            // nothing about whether this call site was also written correctly.
            val identity = DualKeyIdentity.generate()
            val server =
                BrowserServer.start(
                    identity = identity,
                    httpPort = 0,
                    dataDirectory = Files.createTempDirectory("mail-xss-rendering-attachment-test"),
                    karmaAnchorSource = XssTestNoAnchorSource,
                )
            val httpClient = HttpClient(CIO)
            val webClient = WebClient(BrowserVersion.CHROME)

            try {
                val xssAttachmentName = "<img src=x onerror=\"window.__xssFiredAttachment = true\">.txt"
                val attachmentContentBase64 =
                    Base64.getEncoder().encodeToString("attachment payload".toByteArray(Charsets.UTF_8))

                val recipient = DualKeyIdentity.generate()
                runBlocking {
                    val sendResponse =
                        httpClient.post("http://127.0.0.1:${server.boundPort}/api/mail") {
                            contentType(ContentType.Application.Json)
                            setBody(
                                json.encodeToString(
                                    NewMailRequest(
                                        recipientsHex =
                                            listOf(
                                                recipient.secp256k1KeyPair.publicKey.bytes.joinToString("") {
                                                    "%02x".format(it)
                                                },
                                            ),
                                        subject = "attachment XSS regression",
                                        body = "see attached",
                                        attachments =
                                            listOf(
                                                NewMailAttachmentRequest(
                                                    name = xssAttachmentName,
                                                    mime = "text/plain",
                                                    contentBase64 = attachmentContentBase64,
                                                ),
                                            ),
                                    ),
                                ),
                            )
                        }
                    sendResponse.status.value shouldBe 200
                }

                webClient.options.isThrowExceptionOnScriptError = true
                webClient.options.isThrowExceptionOnFailingStatusCode = false
                webClient.options.isCssEnabled = false
                webClient.options.isFetchPolyfillEnabled = true

                val page = webClient.getPage<HtmlPage>("http://127.0.0.1:${server.boundPort}/mail.html")
                webClient.waitForBackgroundJavaScript(5_000)

                val sentButton = page.getElementById("folder-sent-button")
                sentButton.click<HtmlPage>()

                val deadline = Instant.now().plus(Duration.ofSeconds(20))
                var attachmentNameText: String? = null
                while (Instant.now().isBefore(deadline)) {
                    webClient.waitForBackgroundJavaScript(500)
                    val linkElement = page.querySelector<DomNode>(".mail-item .mail-attachment-link")
                    val candidate = linkElement?.textContent
                    if (!candidate.isNullOrBlank()) {
                        attachmentNameText = candidate
                        break
                    }
                    runBlocking { delay(200) }
                }

                // 1. The injected onerror handler never ran.
                val xssFiredResult = page.executeJavaScript("window.__xssFiredAttachment")
                ScriptResult.isUndefined(xssFiredResult) shouldBe true

                // 2. The rendered anchor's own text content is the LITERAL payload string.
                attachmentNameText shouldBe xssAttachmentName

                // 3. No injected <img> element exists anywhere in the page - if the name had been
                // innerHTML'd instead of textContent'd, the browser would have parsed and inserted
                // a real <img onerror> element here.
                page.getElementsByTagName("img").size shouldBe 0

                // 4. The serialized DOM shows the payload HTML-entity-escaped, not raw markup.
                page.asXml() shouldContain "&lt;img src=x onerror="
            } finally {
                webClient.close()
                httpClient.close()
                runCatching { server.stop() }
            }
        }
    })
