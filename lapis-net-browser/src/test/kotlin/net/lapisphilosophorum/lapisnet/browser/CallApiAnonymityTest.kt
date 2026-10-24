package net.lapisphilosophorum.lapisnet.browser

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import kotlinx.serialization.json.Json
import net.lapisphilosophorum.lapisnet.call.CallEvent
import net.lapisphilosophorum.lapisnet.call.CallMediaPolicy
import net.lapisphilosophorum.lapisnet.call.CallSuppressCause
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey

private val json = Json { ignoreUnknownKeys = true }

private fun hex(key: Secp256k1PublicKey) = key.bytes.joinToString("") { "%02x".format(it) }

private class AnonAuthed(
    val builder: ApplicationTestBuilder,
    val token: CallSessionToken,
) {
    private fun scoped(path: String) = path.replaceFirst("/api/call/", "/api/call/${token.scope}/")

    suspend fun get(path: String): HttpResponse =
        builder.client.get(scoped(path)) {
            header(HttpHeaders.Host, "127.0.0.1:$TEST_PORT")
            header("Cookie", "$CALL_COOKIE_NAME=${token.hex}")
        }

    suspend fun post(
        path: String,
        body: String = "{}",
    ): HttpResponse =
        builder.client.post(scoped(path)) {
            header(HttpHeaders.Host, "127.0.0.1:$TEST_PORT")
            header("Cookie", "$CALL_COOKIE_NAME=${token.hex}")
            header(HttpHeaders.Origin, "http://127.0.0.1:$TEST_PORT")
            header(HttpHeaders.ContentType, "application/json")
            setBody(body)
        }
}

private fun routedWith(
    remote: FakeCallRemote,
    media: CallMediaPolicy,
    hub: CallEventHub = CallEventHub(remote, autoRejectQuarantined = true),
    block: suspend AnonAuthed.() -> Unit,
) {
    val token = CallSessionToken.generate()
    testApplication {
        application { installCallOnly(testCallDeps(remote, hub = hub, token = token, callMedia = media)) }
        AnonAuthed(this, token).block()
    }
}

class CallApiAnonymityTest :
    FunSpec({
        test("disabled: place is a 409 with the fixed code, before the peer check, and the remote is never called") {
            val remote = FakeCallRemote()
            routedWith(remote, CallMediaPolicy.DISABLED) {
                val valid = post("/api/call/place", "{\"peer\":\"${hex(randomPeer())}\",\"confirmMediaExposure\":true}")
                valid.status.value shouldBe 409
                val body = json.decodeFromString<CallErrorResponse>(valid.bodyAsText())
                body.code shouldBe "CALL_MEDIA_DISABLED_IN_ANONYMITY_MODE"
                body.error shouldBe
                    "Calls are not available in anonymity mode because call media reveals your IP address"
                // even an invalid peer gets the same 409 (checked before the peer): no side channel
                post("/api/call/place", "{\"peer\":\"zz\"}").status.value shouldBe 409
            }
            remote.totalMutatingCalls shouldBe 0
        }

        test("exposed: place and accept without the confirmation are 409 and never reach the remote; with it 202") {
            val remote = FakeCallRemote()
            val id = randomCallId()
            remote.active = listOf(remote.snapshot(id, randomPeer()))
            val idHex = id.bytes.joinToString("") { "%02x".format(it) }
            val peer = hex(randomPeer())
            routedWith(remote, CallMediaPolicy.EXPOSED) {
                val noConfirm = post("/api/call/place", "{\"peer\":\"$peer\"}")
                noConfirm.status.value shouldBe 409
                json.decodeFromString<CallErrorResponse>(noConfirm.bodyAsText()).code shouldBe
                    "MEDIA_EXPOSURE_CONFIRMATION_REQUIRED"
                post("/api/call/place", "{\"peer\":\"$peer\",\"confirmMediaExposure\":false}").status.value shouldBe 409
                post("/api/call/$idHex/accept").status.value shouldBe 409
                post("/api/call/$idHex/accept", "{\"confirmMediaExposure\":false}").status.value shouldBe 409
                remote.totalMutatingCalls shouldBe 0

                post("/api/call/place", "{\"peer\":\"$peer\",\"confirmMediaExposure\":true}").status.value shouldBe 202
                post("/api/call/$idHex/accept", "{\"confirmMediaExposure\":true}").status.value shouldBe 202
                // reject and hangup never need a confirmation
                post("/api/call/$idHex/reject").status.value shouldBe 202
                post("/api/call/$idHex/hangup").status.value shouldBe 202
            }
            remote.placedConfirmed.toList() shouldBe listOf(true)
            remote.acceptedConfirmed.toList() shouldBe listOf(true)
        }

        test("the confirmation answer is no existence oracle: an unknown call id is a 404 either way") {
            val remote = FakeCallRemote()
            routedWith(remote, CallMediaPolicy.EXPOSED) {
                post("/api/call/${"ab".repeat(16)}/accept").status.value shouldBe 404
                post("/api/call/${"ab".repeat(16)}/accept", "{\"confirmMediaExposure\":true}").status.value shouldBe 404
            }
            remote.totalMutatingCalls shouldBe 0
        }

        test("an old empty body {} stays valid in direct mode") {
            val remote = FakeCallRemote()
            val id = randomCallId()
            remote.active = listOf(remote.snapshot(id, randomPeer()))
            val idHex = id.bytes.joinToString("") { "%02x".format(it) }
            routedWith(remote, CallMediaPolicy.DIRECT) {
                post("/api/call/$idHex/accept").status.value shouldBe 202
                post("/api/call/place", "{\"peer\":\"${hex(randomPeer())}\"}").status.value shouldBe 202
            }
            remote.acceptedConfirmed.toList() shouldBe listOf(false)
        }

        test("status reports anonymity and callMedia, also when calls are unavailable") {
            for (
            (policy, anon, wire) in
            listOf(
                Triple(CallMediaPolicy.DIRECT, "off", "direct"),
                Triple(CallMediaPolicy.DISABLED, "on", "disabled"),
                Triple(CallMediaPolicy.EXPOSED, "on", "exposed"),
            )
            ) {
                val remote = FakeCallRemote()
                routedWith(remote, policy) {
                    val status = json.decodeFromString<CallStatusResponse>(get("/api/call/status").bodyAsText())
                    status.anonymity shouldBe anon
                    status.callMedia shouldBe wire
                }
                val token = CallSessionToken.generate()
                testApplication {
                    application { installCallOnly(testCallDeps(null, hub = null, token = token, callMedia = policy)) }
                    val response =
                        client.get("/api/call/${token.scope}/status") {
                            header(HttpHeaders.Host, "127.0.0.1:$TEST_PORT")
                            header("Cookie", "$CALL_COOKIE_NAME=${token.hex}")
                        }
                    val status = json.decodeFromString<CallStatusResponse>(response.bodyAsText())
                    status.available shouldBe false
                    status.callMedia shouldBe wire
                }
            }
        }

        test("a suppressed call is unknown to accept and reject (404) and shows up as a blocked history row") {
            val remote = FakeCallRemote()
            val hub = CallEventHub(remote, autoRejectQuarantined = true)
            val id = randomCallId()
            val idHex = id.bytes.joinToString("") { "%02x".format(it) }
            remote.emit(CallEvent.IncomingSuppressed(id, randomPeer(), CallSuppressCause.ANONYMITY_MODE))
            routedWith(remote, CallMediaPolicy.DISABLED, hub) {
                post("/api/call/$idHex/accept").status.value shouldBe 404
                post("/api/call/$idHex/reject").status.value shouldBe 404
                val body = get("/api/call/status").bodyAsText()
                body shouldContain "ANONYMITY_MODE"
                body shouldNotContain "Calls are not available"
            }
            remote.totalMutatingCalls shouldBe 0
        }
    })
