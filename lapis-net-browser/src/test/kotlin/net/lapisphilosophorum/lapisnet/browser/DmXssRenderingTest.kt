package net.lapisphilosophorum.lapisnet.browser

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import net.lapisphilosophorum.lapisnet.dm.DmAttachmentCipher
import net.lapisphilosophorum.lapisnet.dm.DmAttachmentRef
import net.lapisphilosophorum.lapisnet.dm.DmContent
import net.lapisphilosophorum.lapisnet.dm.DmInboundMessage
import net.lapisphilosophorum.lapisnet.dm.EncryptedDmAttachmentBlobCodec
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
import java.security.SecureRandom
import java.time.Duration
import java.time.Instant
import kotlin.time.Duration.Companion.seconds

private object DmXssTestNoAnchorSource : BitcoinTimeAnchorSource {
    override fun findFirstOutgoingTransaction(pubkey: Secp256k1PublicKey): TimeAnchorLookupResult =
        TimeAnchorLookupResult.NotFound

    override fun currentChainTipHeight(): Int = 0
}

/**
 * The DM analogue of `MailXssRenderingTest.kt` - proves, against the REAL `dm.js` rendering code
 * running inside a REAL, JS/DOM-executing headless browser ([WebClient]), that an XSS payload in a
 * DM's body or an attachment name is rendered as inert, escaped text, never as live markup or an
 * executed script. See `DmApi.kt`'s file-header CRITICAL SECURITY NOTE and `dm.js`'s own
 * file-header policy for the escaping discipline this test verifies - both explicitly call out that
 * this test was the missing piece before this wave.
 *
 * **Why this writes directly into [BrowserServer.dmStoreForTesting] instead of a real two-node
 * send/receive round trip:** mirrors [MailXssRenderingTest]'s own identical reasoning for
 * `/api/mail/sent` - a real DM requires a full X3DH handshake against a reachable peer, which would
 * add gossip/networking flakiness and runtime to what should be a fast, deterministic security
 * regression test. `dm.js`'s `renderMessageItem`/`renderMessageAttachmentsInto` render an inbound
 * message exactly the same way regardless of whether [net.lapisphilosophorum.lapisnet.dm.DmStore]
 * was populated by a real decrypted envelope or directly by a test - the rendering code under test
 * is identical either way.
 */
class DmXssRenderingTest :
    FunSpec({
        test(
            "an XSS payload in an inbound DM's body renders as escaped, inert text - never executes",
        ).config(
            timeout = 60.seconds,
        ) {
            val identity = DualKeyIdentity.generate()
            val server =
                BrowserServer.start(
                    identity = identity,
                    httpPort = 0,
                    dataDirectory = Files.createTempDirectory("dm-xss-rendering-test"),
                    karmaAnchorSource = DmXssTestNoAnchorSource,
                )
            val webClient = WebClient(BrowserVersion.CHROME)

            try {
                val xssBody = "<img src=x onerror=\"window.__dmXssFired = true\">"
                val sender = DualKeyIdentity.generate().secp256k1KeyPair.publicKey
                val senderHex = sender.bytes.joinToString("") { "%02x".format(it) }

                server.dmStoreForTesting.recordInbound(
                    DmInboundMessage(
                        sender = sender,
                        plaintext = ByteArray(0),
                        content = DmContent(xssBody),
                        quarantined = false,
                        dedupKey = ByteArray(1),
                        receivedAtEpochSecond = Instant.now().epochSecond,
                    ),
                )

                webClient.options.isThrowExceptionOnScriptError = true
                webClient.options.isThrowExceptionOnFailingStatusCode = false
                webClient.options.isCssEnabled = false
                // dm.js uses the real fetch() API (see this file's own doc comment on why dm.js is
                // Promise/.then()-based) - HtmlUnit's embedded engine does not implement fetch()
                // natively and needs its bundled polyfill turned on explicitly.
                webClient.options.isFetchPolyfillEnabled = true

                val page = webClient.getPage<HtmlPage>("http://127.0.0.1:${server.boundPort}/dm.html")
                webClient.waitForBackgroundJavaScript(5_000)

                // dm.js's openConversation() drives both the conversation list AND thread rendering
                // for a given peerHex - calling it directly here is equivalent to a user clicking
                // the conversation in the list, without needing that list item to already exist.
                page.executeJavaScript("openConversation('$senderHex')")

                val deadline = Instant.now().plus(Duration.ofSeconds(20))
                var bodyText: String? = null
                while (Instant.now().isBefore(deadline)) {
                    webClient.waitForBackgroundJavaScript(500)
                    val bodyElement = page.querySelector<DomNode>(".dm-message-item .dm-message-body")
                    val candidate = bodyElement?.textContent
                    if (!candidate.isNullOrBlank()) {
                        bodyText = candidate
                        break
                    }
                    runBlocking { delay(200) }
                }

                // 1. The injected onerror handler never ran - proves the payload was never
                // interpreted as live markup by the real browser engine.
                val xssFiredResult = page.executeJavaScript("window.__dmXssFired")
                ScriptResult.isUndefined(xssFiredResult) shouldBe true

                // 2. The rendered DOM node's own text content is the LITERAL payload string.
                bodyText shouldBe xssBody

                // 3. No injected <img> element exists anywhere in the page - if the body had been
                // innerHTML'd instead of textContent'd, the browser would have parsed and inserted
                // a real <img onerror> element here.
                page.getElementsByTagName("img").size shouldBe 0

                // 4. The serialized DOM shows the payload HTML-entity-escaped, not raw markup.
                page.asXml() shouldContain "&lt;img src=x onerror="
            } finally {
                webClient.close()
                runCatching { server.stop() }
            }
        }

        test(
            "an XSS payload in an inbound DM attachment's name renders as escaped, inert text - never executes",
        ).config(
            timeout = 60.seconds,
        ) {
            // Mirrors the body test above exactly, but targets renderMessageAttachmentsInto's
            // setText(linkEl, attachment.name) call in dm.js - a DIFFERENT rendering call site from
            // renderMessageItem's body setText call, reached via a different response field
            // (DmMessageResponse.attachments[].name), so proving the body is inert says nothing
            // about whether this call site was also written correctly.
            val identity = DualKeyIdentity.generate()
            val server =
                BrowserServer.start(
                    identity = identity,
                    httpPort = 0,
                    dataDirectory = Files.createTempDirectory("dm-xss-rendering-attachment-test"),
                    karmaAnchorSource = DmXssTestNoAnchorSource,
                )
            val webClient = WebClient(BrowserVersion.CHROME)

            try {
                val xssAttachmentName = "<img src=x onerror=\"window.__dmXssFiredAttachment = true\">.txt"
                val sender = DualKeyIdentity.generate().secp256k1KeyPair.publicKey
                val senderHex = sender.bytes.joinToString("") { "%02x".format(it) }

                // dm.js never dereferences the attachment's cid in this test (it only reads
                // .name/.mime/.size for display) - still `put` it into the server's own NabuStorage
                // via the storageForTesting seam so DmAttachmentRef gets a real, resolvable cid
                // rather than a hand-rolled one, mirroring DmApiRoutingTest's putEncryptedAttachment.
                val encrypted =
                    DmAttachmentCipher.encrypt("attachment payload".toByteArray(Charsets.UTF_8), SecureRandom())
                val attachmentCid =
                    server.storageForTesting.put(EncryptedDmAttachmentBlobCodec.encode(encrypted.blob))
                val attachmentRef =
                    DmAttachmentRef(attachmentCid, xssAttachmentName, "text/plain", 19L, encrypted.key)

                server.dmStoreForTesting.recordInbound(
                    DmInboundMessage(
                        sender = sender,
                        plaintext = ByteArray(0),
                        content = DmContent("see attached", listOf(attachmentRef)),
                        quarantined = false,
                        dedupKey = ByteArray(1),
                        receivedAtEpochSecond = Instant.now().epochSecond,
                    ),
                )

                webClient.options.isThrowExceptionOnScriptError = true
                webClient.options.isThrowExceptionOnFailingStatusCode = false
                webClient.options.isCssEnabled = false
                webClient.options.isFetchPolyfillEnabled = true

                val page = webClient.getPage<HtmlPage>("http://127.0.0.1:${server.boundPort}/dm.html")
                webClient.waitForBackgroundJavaScript(5_000)

                page.executeJavaScript("openConversation('$senderHex')")

                val deadline = Instant.now().plus(Duration.ofSeconds(20))
                var attachmentNameText: String? = null
                while (Instant.now().isBefore(deadline)) {
                    webClient.waitForBackgroundJavaScript(500)
                    val linkElement = page.querySelector<DomNode>(".dm-message-attachment-link")
                    val candidate = linkElement?.textContent
                    if (!candidate.isNullOrBlank()) {
                        attachmentNameText = candidate
                        break
                    }
                    runBlocking { delay(200) }
                }

                // 1. The injected onerror handler never ran.
                val xssFiredResult = page.executeJavaScript("window.__dmXssFiredAttachment")
                ScriptResult.isUndefined(xssFiredResult) shouldBe true

                // 2. The rendered anchor's own text content is the LITERAL payload string.
                attachmentNameText shouldBe xssAttachmentName

                // 3. No injected <img> element exists anywhere in the page.
                page.getElementsByTagName("img").size shouldBe 0

                // 4. The serialized DOM shows the payload HTML-entity-escaped, not raw markup.
                page.asXml() shouldContain "&lt;img src=x onerror="
            } finally {
                webClient.close()
                runCatching { server.stop() }
            }
        }
    })
