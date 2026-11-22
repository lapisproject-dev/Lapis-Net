package net.lapisphilosophorum.lapisnet.browser

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import net.lapisphilosophorum.lapisnet.networking.config.AnonymityPaddingMode
import net.lapisphilosophorum.lapisnet.onionwire.anonymity.ANONYMITY_INCOMPLETE_WARNING
import net.lapisphilosophorum.lapisnet.onionwire.anonymity.ANONYMITY_INCOMPLETE_WARNING_CALL_MEDIA_EXPOSED
import net.lapisphilosophorum.lapisnet.onionwire.anonymity.ANONYMITY_PADDING_OFF_SENTENCE
import net.lapisphilosophorum.lapisnet.onionwire.anonymity.anonymityIncompleteWarning

private fun resource(name: String): String =
    AnonymityStaticAssetsTest::class.java
        .getResourceAsStream("/static/$name")!!
        .readBytes()
        .toString(Charsets.UTF_8)

/** The browser UI shows the incomplete-anonymity notice with fixed text, through textContent only. */
class AnonymityStaticAssetsTest :
    FunSpec({
        // the very constant the log, the CLI and the status use: the browser text must be character-identical
        val warning = ANONYMITY_INCOMPLETE_WARNING

        test("app.js carries the exact warning text and writes the anonymity status through textContent only") {
            val js = resource("app.js")
            js shouldContain warning
            val fn = js.substring(js.indexOf("function renderAnonymityStatus"), js.indexOf("// V0.9.15 status panel."))
            fn shouldContain "textContent"
            fn shouldNotContain "innerHTML"
            fn shouldNotContain "insertAdjacentHTML"
            // the warning text is a constant, never taken from the server response
            fn shouldContain "anonymityWarningText("
            js shouldContain "ANONYMITY_WARNING_TEXT"
            fn shouldNotContain "status.anonymityWarning"
        }

        test("the warning text is character-identical in the Kotlin constant, app.js and docs/anonymity.adoc") {
            warning shouldContain "Direct messages, mail and call signals travel over circuits"
            warning shouldNotContain "mail and call media"
            val exposed = ANONYMITY_INCOMPLETE_WARNING_CALL_MEDIA_EXPOSED
            exposed shouldContain "--anonymity-allow-call-media=true"
            resource("app.js") shouldContain warning
            resource("app.js") shouldContain exposed
            val docs = java.io.File("../docs/anonymity.adoc")
            if (docs.exists()) {
                docs.readText() shouldContain warning
                docs.readText() shouldContain exposed
            }
        }

        test("all four warning texts (calls x padding) are character-identical in Kotlin, app.js and the docs") {
            val js = resource("app.js")
            val docs = java.io.File("../docs/anonymity.adoc")
            for (calls in listOf(false, true)) {
                for (padding in AnonymityPaddingMode.entries) {
                    val text = anonymityIncompleteWarning(calls, padding)
                    js shouldContain text
                    if (docs.exists()) docs.readText() shouldContain text
                }
            }
            anonymityIncompleteWarning(false, AnonymityPaddingMode.OFF) shouldContain ANONYMITY_PADDING_OFF_SENTENCE
            anonymityIncompleteWarning(false, AnonymityPaddingMode.STANDARD) shouldNotContain "Padding is off"
        }

        test("the eighth status line shows padding with fixed texts and numbers only") {
            val js = resource("app.js")
            js shouldContain "anonymityPaddingLine(status)"
            js shouldContain "Padding: off (message sizes and timing are visible to an observer of your connection)"
            val fn =
                js.substring(
                    js.indexOf("function anonymityPaddingLine"),
                    js.indexOf("function renderAnonymityStatus"),
                )
            fn shouldNotContain "innerHTML"
        }

        test("the status panel's mail line says mail travels over circuits and states the offline limit") {
            val js = resource("app.js")
            js shouldContain
                "Mail: over circuits (small mail also offline; up to 1 MiB with attachments only while both are online)"
            js shouldNotContain "Mail: direct connection"
        }

        test("mail.js maps the anonymity error codes to fixed texts and shows a fixed, undismissable notice") {
            val js = resource("mail.js")
            for (
            code in
            listOf(
                "recipient-not-reachable-anonymously",
                "anonymity-not-ready",
                "mail-too-large-anonymous",
                "attachments-unavailable-anonymous",
            )
            ) {
                js shouldContain "\"$code\""
            }
            js shouldContain "mailErrorText(error)"
            js shouldContain "MAIL_ANONYMITY_NOTICE"
            js
                .lines()
                .filterNot { it.trimStart().let { l -> l.startsWith("//") || l.startsWith("/*") || l.startsWith("*") } }
                .joinToString("\n") shouldNotContain "innerHTML"
            val html = resource("mail.html")
            html shouldContain "id=\"mail-anonymity-notice\" role=\"status\""
            html shouldNotContain "mail-anonymity-notice-close"
            (html.indexOf("id=\"mail-anonymity-notice\"") < html.indexOf("id=\"compose-recipients\"")) shouldBe true
        }

        test("the warning card is a status region above the node status list and can not be dismissed") {
            val html = resource("index.html")
            html shouldContain "id=\"anonymity-warning\" role=\"status\""
            (html.indexOf("id=\"anonymity-warning\"") < html.indexOf("id=\"node-status-list\"")) shouldBe true
            html shouldNotContain "anonymity-warning-close"
            html.substring(
                html.indexOf("id=\"anonymity-warning\""),
                html.indexOf("id=\"node-status-list\""),
            ) shouldNotContain
                "<button"
        }

        test("the amber tokens exist for the light and the dark scheme") {
            val css = resource("style.css")
            for (token in listOf("--anonymity-warning-bg", "--anonymity-warning-fg", "--anonymity-warning-border")) {
                Regex(Regex.escape("$token:")).findAll(css).count() shouldBe 2
            }
            css shouldContain "#anonymity-warning"
            css shouldContain "@media (prefers-color-scheme: light)"
        }

        test("the node status shows seven fixed anonymity lines, written as list items through textContent") {
            val js = resource("app.js")
            js shouldContain "ANONYMITY_STATUS_LINES"
            val lines =
                js.substring(
                    js.indexOf("const ANONYMITY_STATUS_LINES"),
                    js.indexOf("];", js.indexOf("const ANONYMITY_STATUS_LINES")),
                )
            // five fixed lines here, the call media line (two fixed variants) and the counts line built from two numbers
            Regex("\"[A-Z][^\"]*\"").findAll(lines).count() shouldBe 5
            js shouldContain "Call signals: through circuits"
            js shouldContain "Call media: off (would reveal your IP address)"
            js shouldContain "Call media: direct connection, your IP address is visible to the other party"
            val fn = js.substring(js.indexOf("function renderAnonymityStatus"), js.indexOf("// V0.9.15 status panel."))
            fn shouldContain "item.textContent"
            fn shouldNotContain "innerHTML"
            js shouldContain "\"recipient-unreachable\""
        }

        test(
            "dm.js maps error codes to fixed texts, never shows the server's text; attachments are fetched over circuits",
        ) {
            val js = resource("dm.js")
            for (
            code in
            listOf(
                "recipient-not-reachable-anonymously",
                "anonymity-not-ready",
                "rate-limited",
                "message-too-large-anonymous",
                "attachments-unavailable-anonymous",
                "attachment-too-large-anonymous",
                "attachment-fetch-timeout-anonymous",
                "dm-send-failed",
            )
            ) {
                js shouldContain "\"$code\""
            }
            js shouldContain "dmErrorText(error)"
            // wave Q21: attachments are no longer disabled in anonymity mode; a download goes through fetch() and a
            // refusal is shown as fixed text looked up by its code
            js shouldNotContain "addAttachmentButton.disabled = true"
            js shouldContain "downloadAttachmentAnonymously(url, attachment.name, statusEl)"
            js shouldContain "attachmentDownloadText(body && body.error)"
            js shouldContain "DM_ANONYMITY_NOTICE"
            js
                .lines()
                .filterNot { it.trimStart().let { l -> l.startsWith("//") || l.startsWith("/*") || l.startsWith("*") } }
                .joinToString("\n") shouldNotContain "innerHTML"
            val html = resource("dm.html")
            html shouldContain "id=\"dm-anonymity-notice\" role=\"status\""
            html shouldNotContain "dm-anonymity-notice-close"
            // the notice sits above the input field and has no button inside it
            (html.indexOf("id=\"dm-anonymity-notice\"") < html.indexOf("id=\"dm-compose-body\"")) shouldBe true
        }

        test("Q21: mail.js maps the attachment download codes to fixed texts") {
            val js = resource("mail.js")
            for (code in listOf(
                "attachments-unavailable-anonymous",
                "attachment-too-large-anonymous",
                "attachment-fetch-timeout-anonymous",
                "anonymity-not-ready",
                "rate-limited",
            )) {
                js shouldContain "\"$code\""
            }
            js shouldContain "downloadAttachmentAnonymously(url, attachment.name, statusEl)"
            js shouldContain "attachmentDownloadText(body && body.error)"
            resource("mail.html") shouldContain "class=\"mail-attachment-status\" role=\"status\""
            resource("dm.html") shouldContain "class=\"dm-message-attachment-status\" role=\"status\""
        }

        test("J3: every warning text says experimental, incomplete and unreviewed, in sentences") {
            for (calls in listOf(false, true)) {
                for (padding in AnonymityPaddingMode.entries) {
                    val text = anonymityIncompleteWarning(calls, padding)
                    text.substringBefore(". ") shouldContain "experimental"
                    text.substringBefore(". ") shouldContain "incomplete"
                    text shouldContain "no external security review"
                    text shouldNotContain "; The transport key"
                    text shouldContain ". The transport key is fresh per run."
                    // the calls part and the padding part start sentences of their own
                    text shouldNotContain "; calls are"
                    text shouldNotContain "; but calls"
                    text shouldNotContain "; padding is off"
                    // no lookup of mail or names is claimed (none is wired in this mode)
                    text shouldNotContain "mail and names are fetched"
                    text shouldContain
                        "Attachments are fetched from the sender's onion service while the sender is online (up to 4 MiB each); inbox rendezvous records are not reachable in this mode."
                    text shouldContain "which nodes do for the newest posts they hold"
                    text shouldNotContain "nodes do not announce posts in the DHT"
                }
            }
        }

        test("J3: the lookup status line uses numbers and fixed text only, never a relay identity") {
            val js = resource("app.js")
            js shouldContain "anonymityLookupLine(status)"
            val fn =
                js.substring(
                    js.indexOf("function anonymityLookupLine"),
                    js.indexOf("function renderAnonymityStatus"),
                )
            for (field in listOf(
                "anonymityLookupRequested",
                "anonymityLookupFound",
                "anonymityLookupNotFound",
                "anonymityLookupNotFoundUnconfirmed",
                "anonymityLookupFailed",
                "anonymityLookupRejected",
                "anonymityLookupRelaysAvailable",
                "anonymityLookupRelaysKnown",
                "anonymityLookupRelaysOnBackoff",
            )) {
                fn shouldContain "status.$field"
            }
            fn shouldContain "\"Lookups: \""
            fn shouldContain " lookup relay(s) available, "
            js shouldContain "Number.isFinite(value)"
            for (bad in listOf("identity", "toString(16)", "hex", "fingerprint", "innerHTML")) fn shouldNotContain bad
            js shouldContain
                "Network mesh: guards only (they see your address); missing posts are looked up through circuits"
            js shouldNotContain "Network mesh, DHT and fetches: direct"
        }

        test("J3: the two timeline placeholders are fixed texts written through textContent") {
            val js = resource("app.js")
            js shouldContain "\"Fetching through circuits; reload to see it.\""
            js shouldContain "\"Not found through two relays.\""
            js shouldContain "post.contentState === \"fetching\""
            js shouldContain "post.contentState === \"not-found\""
            js shouldContain ".timeline-text\").textContent = timelineBodyText(post)"
            val fn = js.substring(js.indexOf("function timelineBodyText"), js.indexOf("function renderTimelineItem"))
            fn shouldNotContain "innerHTML"
            fn shouldNotContain "setTimeout"
            fn shouldNotContain "location.reload"
        }
    })
