package net.lapisphilosophorum.lapisnet.browser

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import net.lapisphilosophorum.lapisnet.onionwire.anonymity.ANONYMITY_INCOMPLETE_WARNING
import net.lapisphilosophorum.lapisnet.onionwire.anonymity.ANONYMITY_INCOMPLETE_WARNING_CALL_MEDIA_EXPOSED

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
            fn shouldContain "ANONYMITY_WARNING_TEXT"
            fn shouldNotContain "status.anonymityWarning"
        }

        test("the warning text is character-identical in the Kotlin constant, app.js and docs/anonymity.adoc") {
            warning shouldContain "direct messages, mail and call signals travel over circuits"
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

        test("dm.js maps error codes to fixed texts, never shows the server's text, and disables attachments") {
            val js = resource("dm.js")
            for (
            code in
            listOf(
                "recipient-not-reachable-anonymously",
                "anonymity-not-ready",
                "rate-limited",
                "message-too-large-anonymous",
                "attachments-unavailable-anonymous",
                "dm-send-failed",
            )
            ) {
                js shouldContain "\"$code\""
            }
            js shouldContain "dmErrorText(error)"
            js shouldContain "addAttachmentButton.disabled = true"
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
    })
