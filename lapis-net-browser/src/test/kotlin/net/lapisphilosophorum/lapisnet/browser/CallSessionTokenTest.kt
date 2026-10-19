package net.lapisphilosophorum.lapisnet.browser

import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.read.ListAppender
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.server.testing.testApplication
import org.slf4j.LoggerFactory

private const val P = TEST_PORT

class CallSessionTokenTest :
    FunSpec({
        test("matches accepts exactly the generated token and rejects malformed candidates") {
            val token = CallSessionToken.generate()
            token.matches(token.hex) shouldBe true
            token.matches(token.hex.uppercase()) shouldBe true
            token.matches(null) shouldBe false
            token.matches("") shouldBe false
            token.matches(token.hex.dropLast(2)) shouldBe false
            token.matches("zz".repeat(32)) shouldBe false
            token.matches(CallSessionToken.generate().hex) shouldBe false
            token.hex.length shouldBe 64
        }

        test("scope is stable, 32 hex chars, differs per token and does not reveal the token") {
            val token = CallSessionToken.generate()
            token.scope shouldBe token.scope
            token.scope.length shouldBe 32
            token.scope shouldNotBe CallSessionToken.generate().scope
            token.hex shouldNotContain token.scope
        }

        test("toString never contains the token") {
            val token = CallSessionToken.generate()
            token.toString() shouldNotContain token.hex
            token.toString() shouldContain "redacted"
        }

        test(
            "the correct token yields 200 with the scope and an HttpOnly SameSite=Strict cookie whose Path is the secret scope",
        ) {
            val token = CallSessionToken.generate()
            testApplication {
                application { installCallOnly(testCallDeps(FakeCallRemote(), token = token)) }
                val response =
                    client.post("/api/call/session") {
                        header(HttpHeaders.Host, "127.0.0.1:$P")
                        header(HttpHeaders.Origin, "http://127.0.0.1:$P")
                        header(HttpHeaders.ContentType, "application/json")
                        setBody("{\"token\":\"${token.hex}\"}")
                    }
                response.status.value shouldBe 200
                response.bodyAsText() shouldContain "\"scope\":\"${token.scope}\""
                val cookie =
                    response.headers
                        .getAll(HttpHeaders.SetCookie)
                        .orEmpty()
                        .single()
                cookie shouldContain "lapis_call=${token.hex}"
                cookie shouldContain "HttpOnly"
                cookie shouldContain "SameSite=Strict"
                cookie shouldContain "Path=/api/call/${token.scope}"
                cookie shouldNotContain "Path=/api/call;"
            }
        }

        test(
            "wrong token, wrong length and non-hex give 403; the 11th failed attempt gives 429, the right token is never throttled",
        ) {
            val token = CallSessionToken.generate()
            val appender = ListAppender<ILoggingEvent>().also { it.start() }
            val root = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME) as Logger
            root.addAppender(appender)
            try {
                testApplication {
                    application { installCallOnly(testCallDeps(FakeCallRemote(), token = token)) }

                    suspend fun attempt(candidate: String) =
                        client
                            .post("/api/call/session") {
                                header(HttpHeaders.Host, "127.0.0.1:$P")
                                header(HttpHeaders.Origin, "http://127.0.0.1:$P")
                                header(HttpHeaders.ContentType, "application/json")
                                setBody("{\"token\":\"$candidate\"}")
                            }.status.value

                    attempt(CallSessionToken.generate().hex) shouldBe 403
                    attempt("abcd") shouldBe 403
                    attempt("not-hex-at-all") shouldBe 403
                    repeat(7) { attempt(CallSessionToken.generate().hex) shouldBe 403 }
                    // Failed attempts 11+ are throttled; the correct token still gets through.
                    attempt(CallSessionToken.generate().hex) shouldBe 429
                    attempt(token.hex) shouldBe 200
                }
            } finally {
                root.detachAppender(appender)
            }
            appender.list.filter { it.formattedMessage.contains(token.hex) }.shouldBeEmpty()
        }
    })
