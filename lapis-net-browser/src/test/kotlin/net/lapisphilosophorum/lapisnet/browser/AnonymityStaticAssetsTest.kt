package net.lapisphilosophorum.lapisnet.browser

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain

private fun resource(name: String): String =
    AnonymityStaticAssetsTest::class.java
        .getResourceAsStream("/static/$name")!!
        .readBytes()
        .toString(Charsets.UTF_8)

/** The browser UI shows the incomplete-anonymity notice with fixed text, through textContent only. */
class AnonymityStaticAssetsTest :
    FunSpec({
        val warning =
            "Anonymity mode is incomplete: direct messages, mail and call signalling still use direct connections " +
                "and reveal your IP address; only the directory publication and path selection are active."

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
    })
