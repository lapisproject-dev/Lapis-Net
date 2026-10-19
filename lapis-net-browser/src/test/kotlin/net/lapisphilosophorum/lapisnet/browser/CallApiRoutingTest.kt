package net.lapisphilosophorum.lapisnet.browser

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
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
import net.lapisphilosophorum.lapisnet.call.CallEndReason
import net.lapisphilosophorum.lapisnet.call.CallLogEntry
import net.lapisphilosophorum.lapisnet.call.CallState
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey

private val json = Json { ignoreUnknownKeys = true }

private fun hex(key: Secp256k1PublicKey) = key.bytes.joinToString("") { "%02x".format(it) }

private class Authed(
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

private fun routed(
    remote: CallRemote?,
    own: Secp256k1PublicKey = randomPeer(),
    hub: CallEventHub? = remote?.let { CallEventHub(it, autoRejectQuarantined = true) },
    block: suspend Authed.() -> Unit,
) {
    val token = CallSessionToken.generate()
    testApplication {
        application { installCallOnly(testCallDeps(remote, hub = hub, token = token, own = own)) }
        Authed(this, token).block()
    }
}

class CallApiRoutingTest :
    FunSpec({
        test("place returns 202 with a call id and hands the peer to the remote exactly once") {
            val remote = FakeCallRemote()
            val peer = randomPeer()
            routed(remote) {
                val response = post("/api/call/place", "{\"peer\":\"${hex(peer)}\"}")
                response.status.value shouldBe 202
                json.decodeFromString<CallPlaceResponse>(response.bodyAsText()).callId.length shouldBe 32
            }
            remote.placed.map { hex(it) } shouldContainExactly listOf(hex(peer))
        }

        test("place rejects an invalid peer and the node's own key with 400") {
            val remote = FakeCallRemote()
            val own = randomPeer()
            routed(remote, own) {
                post("/api/call/place", "{\"peer\":\"zz\"}").status.value shouldBe 400
                post("/api/call/place", "{\"peer\":\"${"00".repeat(33)}\"}").status.value shouldBe 400
                post("/api/call/place", "{\"peer\":\"${hex(own)}\"}").status.value shouldBe 400
            }
            remote.placed.size shouldBe 0
        }

        test("accept, reject and hangup on a known call answer 202 and reach the remote exactly once") {
            val remote = FakeCallRemote()
            val id = randomCallId()
            remote.active = listOf(remote.snapshot(id, randomPeer()))
            val idHex = id.bytes.joinToString("") { "%02x".format(it) }
            routed(remote) {
                post("/api/call/$idHex/accept").status.value shouldBe 202
                post("/api/call/$idHex/reject").status.value shouldBe 202
                post("/api/call/$idHex/hangup").status.value shouldBe 202
            }
            remote.accepted shouldContainExactly listOf(id)
            remote.rejected shouldContainExactly listOf(id)
            remote.hungUp shouldContainExactly listOf(id)
        }

        test("malformed call ids give 400, an unknown call id gives 404 without touching the remote") {
            val remote = FakeCallRemote()
            routed(remote) {
                post("/api/call/abc/accept").status.value shouldBe 400
                post("/api/call/${"zz".repeat(16)}/accept").status.value shouldBe 400
                post("/api/call/${"00".repeat(16)}/accept").status.value shouldBe 400
                post("/api/call/${"ab".repeat(16)}/accept").status.value shouldBe 404
                post("/api/call/${"ab".repeat(16)}/hangup").status.value shouldBe 404
            }
            remote.totalMutatingCalls shouldBe 0
        }

        test("accept on a blocked call id is a 404 and never reaches the remote, even if the id looks active") {
            val remote = FakeCallRemote()
            val hub = CallEventHub(remote, autoRejectQuarantined = true)
            val id = randomCallId()
            val peer = randomPeer()
            remote.emit(
                net.lapisphilosophorum.lapisnet.call.CallEvent
                    .IncomingCall(id, peer, quarantined = true),
            )
            // Even a (hypothetical) active entry with the same id must not make the route act.
            remote.active = listOf(remote.snapshot(id, peer))
            val idHex = id.bytes.joinToString("") { "%02x".format(it) }
            routed(remote, hub = hub) {
                post("/api/call/$idHex/accept").status.value shouldBe 404
                post("/api/call/$idHex/reject").status.value shouldBe 404
                post("/api/call/$idHex/hangup").status.value shouldBe 404
            }
            remote.totalMutatingCalls shouldBe 0
        }

        test("without a remote status reports unavailable and every mutating route answers 503") {
            routed(null) {
                val status = json.decodeFromString<CallStatusResponse>(get("/api/call/status").bodyAsText())
                status.available shouldBe false
                status.active.size shouldBe 0
                post("/api/call/place", "{\"peer\":\"${hex(randomPeer())}\"}").status.value shouldBe 503
                post("/api/call/${"ab".repeat(16)}/accept").status.value shouldBe 503
                post("/api/call/${"ab".repeat(16)}/reject").status.value shouldBe 503
                post("/api/call/${"ab".repeat(16)}/hangup").status.value shouldBe 503
                get("/api/call/events").status.value shouldBe 503
            }
        }

        test("status merges active calls with ended and blocked history, newest first") {
            val remote = FakeCallRemote()
            val peer = randomPeer()
            val activeId = randomCallId()
            remote.active = listOf(remote.snapshot(activeId, peer, CallState.ACTIVE))
            remote.history =
                listOf(
                    CallLogEntry(randomCallId(), peer, CallEndReason.REMOTE_HANGUP, 1000),
                    CallLogEntry(randomCallId(), peer, CallEndReason.DECLINED, 3000),
                )
            val hub = CallEventHub(remote, autoRejectQuarantined = true, clockSeconds = { 2000 })
            remote.emit(
                net.lapisphilosophorum.lapisnet.call.CallEvent
                    .IncomingCall(randomCallId(), peer, quarantined = true),
            )
            routed(remote, hub = hub) {
                val status = json.decodeFromString<CallStatusResponse>(get("/api/call/status").bodyAsText())
                status.available shouldBe true
                status.active.single().state shouldBe "ACTIVE"
                status.history.map { it.outcome } shouldContainExactly listOf("DECLINED", "BLOCKED", "REMOTE_HANGUP")
                status.history[1].blocked shouldBe true
            }
        }

        test("300 ended calls are capped to 50 history rows in status") {
            val remote = FakeCallRemote()
            val peer = randomPeer()
            remote.history = (1..300).map { CallLogEntry(randomCallId(), peer, CallEndReason.NONE, it.toLong()) }
            routed(remote) {
                val body = get("/api/call/status").bodyAsText()
                val status = json.decodeFromString<CallStatusResponse>(body)
                status.history.size shouldBe 50
                status.history.first().atEpochSecond shouldBe 300
            }
        }

        test("status body never contains a field outside the documented DTO") {
            routed(FakeCallRemote()) {
                get("/api/call/status").bodyAsText() shouldContain "\"available\":true"
            }
        }
    })
