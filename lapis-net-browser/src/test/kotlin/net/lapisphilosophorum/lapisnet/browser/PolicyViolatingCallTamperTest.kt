package net.lapisphilosophorum.lapisnet.browser

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.shouldBe
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Instant
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.time.Duration.Companion.seconds

private val json = Json { ignoreUnknownKeys = true }

private class Peer(
    val identity: DualKeyIdentity,
    val server: BrowserServer,
) {
    val key get() = identity.secp256k1KeyPair.publicKey
    val hex get() = hexOfKey(key)
}

private fun LinkedBlockingQueue<String>.nextEventOfType(
    type: String,
    timeoutSeconds: Long,
): CallUiEvent? {
    val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(timeoutSeconds)
    while (System.nanoTime() < deadline) {
        val line = poll(100, TimeUnit.MILLISECONDS) ?: continue
        if (line == "event: $type") {
            val data = poll(5, TimeUnit.SECONDS) ?: error("no data line after event: $type")
            return json.decodeFromString(data.removePrefix("data: "))
        }
    }
    return null
}

private fun postJson(
    http: HttpClient,
    url: String,
    origin: String,
    body: String,
): HttpResponse<String> =
    http.send(
        HttpRequest
            .newBuilder(URI(url))
            .header("Content-Type", "application/json")
            .header("Origin", origin)
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build(),
        HttpResponse.BodyHandlers.ofString(),
    )

/** Two connected servers with a DM session A -> B (a call never starts a first contact). */
private fun connectedPair(bConfig: BrowserConfig): Pair<Peer, Peer> {
    val aId = DualKeyIdentity.generate()
    val bId = DualKeyIdentity.generate()
    val a = Peer(aId, startWiredTestServer(identity = aId))
    val b = Peer(bId, startWiredTestServer(identity = bId, config = bConfig))
    val http = HttpClient.newHttpClient()
    val deadline = Instant.now().plusSeconds(60)
    val bAddr =
        b.server.nodeForTesting
            .listenAddresses()
            .first()
            .withP2P(b.server.nodeForTesting.peerId)
            .toString()
    val base = "http://127.0.0.1:${a.server.boundPort}"
    postJson(
        http,
        "$base/api/peers/connect",
        base,
        json.encodeToString(ConnectPeerRequest(bAddr)),
    ).statusCode() shouldBe
        200
    var converged = false
    while (!converged && Instant.now().isBefore(deadline)) {
        a.server.republishSelfForDmTesting()
        b.server.republishSelfForDmTesting()
        converged =
            a.server.peerDirectoryForDmTesting.lookup(b.key) != null &&
            a.server.prekeyBundleGossipForDmTesting.lookup(b.key) != null
        if (!converged) Thread.sleep(300)
    }
    check(converged) { "directory convergence did not complete" }
    var delivered = false
    while (!delivered && Instant.now().isBefore(deadline)) {
        val send = postJson(http, "$base/api/dm/${b.hex}", base, json.encodeToString(NewDmRequest(body = "hi")))
        if (send.statusCode() == 200) {
            Thread.sleep(500)
            delivered =
                b.server.dmStoreForTesting
                    .peers()
                    .isNotEmpty()
        }
        if (!delivered) Thread.sleep(300)
    }
    check(delivered) { "initial DM was not delivered" }
    return a to b
}

/**
 * T3 - a call that violates the receiver's acceptance policy is silently dropped: B sees exactly one `blocked` with the
 * gate that stopped it, the caller learns NOTHING (neither RINGING from B nor a REJECT - a rejection would confirm that
 * the node is online and reward probing), B tracks no call for it, and no browser click can accept it. Accepting the
 * contact is the only thing that lets calls through.
 */
class PolicyViolatingCallTamperTest :
    FunSpec({
        test(
            "T3: a call from a sender below the Veritas gate is blocked silently, with the reason, and cannot be accepted",
        ).config(timeout = 240.seconds) {
            val (a, b) = connectedPair(BrowserConfig(acceptance = DmAcceptanceSettings(veritasGate = true)))
            try {
                val ca = CallHttpClient(a.server)
                val cb = CallHttpClient(b.server)
                ca.exchangeToken() shouldBe 200
                cb.exchangeToken() shouldBe 200
                val (_, linesA) = ca.openEvents()
                val (_, linesB) = cb.openEvents()

                val callId =
                    json
                        .decodeFromString<CallPlaceResponse>(
                            ca.post("/api/call/place", "{\"peer\":\"${b.hex}\"}").body(),
                        ).callId

                // B: exactly one blocked event, with the single gate that failed - and no incoming ring
                val blocked = linesB.nextEventOfType("blocked", 30)
                blocked!!.callId shouldBe callId
                blocked.blockReason shouldBe "VERITAS_BELOW_THRESHOLD"
                linesB.nextEventOfType("incoming", 2) shouldBe null

                // B tracks no call at all, and the history shows the reason
                b.server.callManagerForTesting!!
                    .activeCalls()
                    .shouldBeEmpty()
                val bStatus = json.decodeFromString<CallStatusResponse>(cb.get("/api/call/status").body())
                bStatus.history.single { it.callId == callId }.let {
                    it.blocked shouldBe true
                    it.blockReason shouldBe "VERITAS_BELOW_THRESHOLD"
                }
                bStatus.active.shouldBeEmpty()

                // the caller learns nothing: for the whole window the call stays plain "ringing" - an ended
                // event (DECLINED/BUSY/...) would mean B answered
                linesA.nextEventOfType("ended", 4) shouldBe null
                val aStatus = json.decodeFromString<CallStatusResponse>(ca.get("/api/call/status").body())
                aStatus.active.single { it.callId == callId }.state shouldBe "OUTGOING_RINGING"

                // no browser click can pull the dropped call through
                cb.post("/api/call/$callId/accept").statusCode() shouldBe 404
                cb.post("/api/call/$callId/reject").statusCode() shouldBe 404
                b.server.callManagerForTesting!!
                    .activeCalls()
                    .shouldBeEmpty()

                // positive control: accepting the contact lifts the gate for the next call
                ca.post("/api/call/$callId/hangup").statusCode() shouldBe 202
                linesA.nextEventOfType("ended", 10)!!.reason shouldBe "LOCAL_HANGUP"
                val base = "http://127.0.0.1:${b.server.boundPort}"
                postJson(
                    HttpClient.newHttpClient(),
                    "$base/api/dm/${a.hex}/accept",
                    base,
                    "{}",
                ).statusCode() shouldBe
                    200
                val second =
                    json
                        .decodeFromString<CallPlaceResponse>(
                            ca.post("/api/call/place", "{\"peer\":\"${b.hex}\"}").body(),
                        ).callId
                linesB.nextEventOfType("incoming", 30)!!.callId shouldBe second
            } finally {
                runCatching { a.server.stop() }
                runCatching { b.server.stop() }
            }
        }

        test(
            "without any gate configured the same call rings (accept-all stays the default)",
        ).config(timeout = 240.seconds) {
            val (a, b) = connectedPair(BrowserConfig.DEFAULT)
            try {
                val ca = CallHttpClient(a.server)
                val cb = CallHttpClient(b.server)
                ca.exchangeToken() shouldBe 200
                cb.exchangeToken() shouldBe 200
                val (_, linesB) = cb.openEvents()
                val callId =
                    json
                        .decodeFromString<CallPlaceResponse>(
                            ca.post("/api/call/place", "{\"peer\":\"${b.hex}\"}").body(),
                        ).callId
                linesB.nextEventOfType("incoming", 30)!!.callId shouldBe callId
            } finally {
                runCatching { a.server.stop() }
                runCatching { b.server.stop() }
            }
        }
    })
