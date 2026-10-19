package net.lapisphilosophorum.lapisnet.browser

import io.kotest.assertions.withClue
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.ktor.client.HttpClient
import io.ktor.client.request.HttpRequestBuilder
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.options
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.OutgoingContent
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.writeStringUtf8

private const val P = TEST_PORT

/** Applies a fully valid same-origin request profile; individual tests then break one thing. */
private fun HttpRequestBuilder.valid(
    token: CallSessionToken,
    post: Boolean,
    host: String = "127.0.0.1:$P",
) {
    header(HttpHeaders.Host, host)
    header("Cookie", "$CALL_COOKIE_NAME=${token.hex}")
    if (post) header(HttpHeaders.Origin, "http://127.0.0.1:$P")
}

private suspend fun HttpClient.postJson(
    path: String,
    body: String = "{}",
    configure: HttpRequestBuilder.() -> Unit,
): HttpResponse =
    post(path) {
        configure()
        header(HttpHeaders.ContentType, "application/json")
        setBody(body)
    }

class CallApiGuardTest :
    FunSpec({
        fun app(
            deps: CallApiDependencies,
            block: suspend ApplicationTestBuilder.() -> Unit,
        ) = testApplication {
            application { installCallOnly(deps) }
            block()
        }

        test("a wrong Host header is refused with 421 (DNS rebinding defence)") {
            val token = CallSessionToken.generate()
            val deps = testCallDeps(FakeCallRemote(), token = token)
            for (host in listOf(
                "evil.example:$P",
                "127.0.0.1:${P + 1}",
                "localhost",
                "127.0.0.1.nip.io:$P",
                "0x7f000001:$P",
            )) {
                app(deps) {
                    val response =
                        client.get("/api/call/${token.scope}/status") {
                            valid(token, post = false, host = host)
                        }
                    response.status.value shouldBe 421
                }
            }
        }

        test("loopback host spellings with the right port pass") {
            val token = CallSessionToken.generate()
            val deps = testCallDeps(FakeCallRemote(), token = token)
            for (host in listOf("127.0.0.1:$P", "localhost:$P", "LOCALHOST:$P", "[::1]:$P")) {
                app(deps) {
                    val response =
                        client.get("/api/call/${token.scope}/status") {
                            valid(token, post = false, host = host)
                        }
                    withClue("host $host") { response.status shouldBe HttpStatusCode.OK }
                }
            }
        }

        test("a foreign or malformed Origin is refused with 403") {
            val token = CallSessionToken.generate()
            val deps = testCallDeps(FakeCallRemote(), token = token)
            val badOrigins =
                listOf(
                    "http://evil.example",
                    "http://localhost:${P + 1}",
                    "null",
                    "https://127.0.0.1:$P",
                    "http://127.0.0.1",
                )
            for (origin in badOrigins) {
                app(deps) {
                    val response =
                        client.postJson("/api/call/${token.scope}/place") {
                            valid(token, post = true)
                            header(HttpHeaders.Origin, origin)
                        }
                    response.status.value shouldBe 403
                }
            }
        }

        test("a POST without Origin is refused with 403") {
            val token = CallSessionToken.generate()
            app(testCallDeps(FakeCallRemote(), token = token)) {
                val response =
                    client.postJson("/api/call/${token.scope}/place") {
                        header(HttpHeaders.Host, "127.0.0.1:$P")
                        header("Cookie", "$CALL_COOKIE_NAME=${token.hex}")
                    }
                response.status.value shouldBe 403
            }
        }

        test("Sec-Fetch-Site cross-site and same-site are refused with 403, same-origin and none pass") {
            val token = CallSessionToken.generate()
            val deps = testCallDeps(FakeCallRemote(), token = token)
            for ((site, expected) in listOf(
                "cross-site" to 403,
                "same-site" to 403,
                "same-origin" to 200,
                "none" to 200,
            )) {
                app(deps) {
                    val response =
                        client.get("/api/call/${token.scope}/status") {
                            valid(token, post = false)
                            header("Sec-Fetch-Site", site)
                        }
                    response.status.value shouldBe expected
                }
            }
        }

        test("a simple-request content type (form, text) is refused with 415") {
            val token = CallSessionToken.generate()
            val deps = testCallDeps(FakeCallRemote(), token = token)
            for (type in listOf("application/x-www-form-urlencoded", "text/plain", "multipart/form-data")) {
                app(deps) {
                    val response =
                        client.post("/api/call/${token.scope}/place") {
                            valid(token, post = true)
                            header(HttpHeaders.ContentType, type)
                            setBody("{}")
                        }
                    response.status.value shouldBe 415
                }
            }
        }

        test("an oversized body is refused with 413, an undeclared length with 411") {
            val token = CallSessionToken.generate()
            val deps = testCallDeps(FakeCallRemote(), token = token)
            app(deps) {
                val big =
                    client.postJson(
                        "/api/call/${token.scope}/place",
                        body = "{\"peer\":\"" + "a".repeat(5000) + "\"}",
                    ) {
                        valid(token, post = true)
                    }
                big.status.value shouldBe 413
            }
            app(deps) {
                val chunked =
                    client.post("/api/call/${token.scope}/place") {
                        valid(token, post = true)
                        setBody(
                            object : OutgoingContent.WriteChannelContent() {
                                override val contentType = ContentType.Application.Json

                                override suspend fun writeTo(channel: ByteWriteChannel) {
                                    channel.writeStringUtf8("{}")
                                }
                            },
                        )
                    }
                chunked.status.value shouldBe 411
            }
        }

        test("an empty or broken JSON body is a 400, never a 500") {
            val token = CallSessionToken.generate()
            val deps = testCallDeps(FakeCallRemote(), token = token)
            for (body in listOf("", "{not json", "[]", "{\"peer\":5}")) {
                app(deps) {
                    val response =
                        client.postJson(
                            "/api/call/${token.scope}/place",
                            body = body,
                        ) { valid(token, post = true) }
                    response.status.value shouldBe 400
                }
            }
        }

        test("missing or wrong session cookie is a 401") {
            val token = CallSessionToken.generate()
            val deps = testCallDeps(FakeCallRemote(), token = token)
            app(deps) {
                client
                    .get("/api/call/${token.scope}/status") { header(HttpHeaders.Host, "127.0.0.1:$P") }
                    .status.value shouldBe 401
                client
                    .get("/api/call/${token.scope}/status") {
                        header(HttpHeaders.Host, "127.0.0.1:$P")
                        header("Cookie", "$CALL_COOKIE_NAME=${CallSessionToken.generate().hex}")
                    }.status.value shouldBe 401
                client
                    .get("/api/call/${token.scope}/events") { header(HttpHeaders.Host, "127.0.0.1:$P") }
                    .status.value shouldBe 401
            }
        }

        test("a valid cookie on a path outside the secret scope is refused (404 unscoped, 401 wrong scope)") {
            val token = CallSessionToken.generate()
            app(testCallDeps(FakeCallRemote(), token = token)) {
                // The old unscoped paths no longer exist at all.
                client.get("/api/call/status") { valid(token, post = false) }.status.value shouldBe 404
                client.get("/api/call/${"0".repeat(32)}/status") { valid(token, post = false) }.status.value shouldBe
                    401
                client.get("/api/call/${token.scope}/status") { valid(token, post = false) }.status.value shouldBe 200
            }
        }

        test("the guard answers 503 while the server port is not yet known") {
            val token = CallSessionToken.generate()
            app(testCallDeps(FakeCallRemote(), token = token, port = 0)) {
                client.get("/api/call/${token.scope}/status") { valid(token, post = false) }.status.value shouldBe 503
            }
        }

        test("no response ever carries a CORS header, preflight included; no-store and no-referrer are set") {
            val token = CallSessionToken.generate()
            val deps = testCallDeps(FakeCallRemote(), token = token)
            app(deps) {
                val responses =
                    listOf(
                        client.get("/api/call/${token.scope}/status") { valid(token, post = false) },
                        client.get("/api/call/${token.scope}/status") { header(HttpHeaders.Host, "127.0.0.1:$P") },
                        client.postJson("/api/call/session", body = "{\"token\":\"00\"}") { valid(token, post = true) },
                        client.options("/api/call/${token.scope}/place") {
                            header(HttpHeaders.Host, "127.0.0.1:$P")
                            header(HttpHeaders.Origin, "http://evil.example")
                            header("Access-Control-Request-Method", "POST")
                        },
                    )
                for (response in responses) {
                    response.headers.names().none { it.lowercase().startsWith("access-control-") } shouldBe true
                }
                responses[0].headers[HttpHeaders.CacheControl] shouldBe "no-store"
                responses[0].headers["Referrer-Policy"] shouldBe "no-referrer"
            }
        }
    })
