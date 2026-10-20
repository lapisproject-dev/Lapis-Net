package net.lapisphilosophorum.lapisnet.browser

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.GossipPubSubException
import java.time.Instant
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.time.Duration.Companion.seconds

private val json = Json { ignoreUnknownKeys = true }

private class Node(
    val identity: DualKeyIdentity,
    val server: BrowserServer,
) {
    val key get() = identity.secp256k1KeyPair.publicKey
    val hex get() = key.bytes.joinToString("") { "%02x".format(it) }
}

private fun startNode(): Node {
    val identity = DualKeyIdentity.generate()
    return Node(identity, startCallTestServer(identity = identity))
}

private fun LinkedBlockingQueue<String>.awaitType(
    type: String,
    timeoutSeconds: Long = 30,
): CallUiEvent {
    val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(timeoutSeconds)
    while (System.nanoTime() < deadline) {
        val line = poll(100, TimeUnit.MILLISECONDS) ?: continue
        if (line == "event: $type") {
            val data = poll(5, TimeUnit.SECONDS) ?: error("no data line after event: $type")
            return json.decodeFromString(data.removePrefix("data: "))
        }
    }
    error("event '$type' not received within ${timeoutSeconds}s")
}

private fun awaitUntil(
    timeoutSeconds: Long,
    message: String,
    condition: () -> Boolean,
) {
    val deadline = Instant.now().plusSeconds(timeoutSeconds)
    while (Instant.now().isBefore(deadline)) {
        if (condition()) return
        Thread.sleep(200)
    }
    error(message)
}

/**
 * Two real [BrowserServer]s (real libp2p, real DM stack, real [net.lapisphilosophorum.lapisnet.call.CallManager]
 * on each side) driven purely over their HTTP/SSE call API, with a fake media engine that "connects"
 * immediately. Proves the whole remote-control path: place -> incoming -> accept -> active ->
 * hangup -> ended, and the history on both sides.
 */
class CallManagerBrowserIntegrationTest :
    FunSpec({
        fun twoConnectedServers(): Pair<Node, Node> {
            val a = startNode()
            val b = startNode()
            val deadline = Instant.now().plusSeconds(60)
            val bAddr =
                b.server.nodeForTesting
                    .listenAddresses()
                    .first()
                    .withP2P(
                        b.server.nodeForTesting.peerId,
                    ).toString()
            val http =
                java.net.http.HttpClient
                    .newHttpClient()
            val connect =
                http.send(
                    java.net.http.HttpRequest
                        .newBuilder(java.net.URI("http://127.0.0.1:${a.server.boundPort}/api/peers/connect"))
                        .header("Content-Type", "application/json")
                        .POST(
                            java.net.http.HttpRequest.BodyPublishers.ofString(
                                json.encodeToString(ConnectPeerRequest(bAddr)),
                            ),
                        ).build(),
                    java.net.http.HttpResponse.BodyHandlers
                        .ofString(),
                )
            connect.statusCode() shouldBe 200
            val bKey = b.key
            var converged = false
            while (!converged && Instant.now().isBefore(deadline)) {
                // Best-effort and retried by this loop: right after connecting, GossipSub may not have an
                // outbound stream to the peer yet (SemiDuplexNoOutboundStreamException), which fails the
                // publish. That must not abort the test setup (seen under CPU load, V0.9.16).
                for (node in listOf(a, b)) {
                    try {
                        node.server.republishSelfForDmTesting()
                    } catch (_: GossipPubSubException) {
                        // retried on the next iteration
                    }
                }
                // Both directions: the callee answers (ACCEPT / REJECT / HANGUP) only if ITS directory knows the
                // caller. Waiting for A -> B alone left the REJECT of the second test lost whenever the
                // gossip A -> B arrived late (V0.9.16, found under CPU load).
                converged =
                    a.server.peerDirectoryForDmTesting.lookup(bKey) != null &&
                    a.server.prekeyBundleGossipForDmTesting.lookup(bKey) != null &&
                    b.server.peerDirectoryForDmTesting.lookup(a.key) != null
                if (!converged) Thread.sleep(300)
            }
            check(converged) { "directory convergence did not complete" }
            // A call never starts a first contact: establish a DM session A -> B first.
            var delivered = false
            while (!delivered && Instant.now().isBefore(deadline)) {
                val send =
                    http.send(
                        java.net.http.HttpRequest
                            .newBuilder(java.net.URI("http://127.0.0.1:${a.server.boundPort}/api/dm/${b.hex}"))
                            .header("Content-Type", "application/json")
                            .POST(
                                java.net.http.HttpRequest.BodyPublishers.ofString(
                                    json.encodeToString(NewDmRequest(body = "hi")),
                                ),
                            ).build(),
                        java.net.http.HttpResponse.BodyHandlers
                            .ofString(),
                    )
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

        test("place -> incoming -> accept -> active -> hangup -> ended, history on both sides").config(
            timeout = 150.seconds,
        ) {
            val (a, b) = twoConnectedServers()
            try {
                val ca = CallHttpClient(a.server)
                val cb = CallHttpClient(b.server)
                ca.exchangeToken() shouldBe 200
                cb.exchangeToken() shouldBe 200
                val (respA, linesA) = ca.openEvents()
                val (respB, linesB) = cb.openEvents()
                respA.statusCode() shouldBe 200
                respB.statusCode() shouldBe 200

                val place = ca.post("/api/call/place", "{\"peer\":\"${b.hex}\"}")
                place.statusCode() shouldBe 202
                val callId = json.decodeFromString<CallPlaceResponse>(place.body()).callId

                linesA.awaitType("ringing").callId shouldBe callId
                val incoming = linesB.awaitType("incoming")
                incoming.callId shouldBe callId
                incoming.peerFingerprint shouldBe a.key.fingerprint()

                cb.post("/api/call/$callId/accept").statusCode() shouldBe 202
                linesB.awaitType("active").callId shouldBe callId
                linesA.awaitType("active").callId shouldBe callId

                ca.post("/api/call/$callId/hangup").statusCode() shouldBe 202
                linesA.awaitType("ended").reason shouldBe "LOCAL_HANGUP"
                linesB.awaitType("ended").reason shouldBe "REMOTE_HANGUP"

                for (client in listOf(ca, cb)) {
                    awaitUntil(10, "history entry missing") {
                        json
                            .decodeFromString<CallStatusResponse>(client.get("/api/call/status").body())
                            .history
                            .any { it.callId == callId }
                    }
                }
                respA.body().close()
                respB.body().close()
            } finally {
                runCatching { a.server.stop() }
                runCatching { b.server.stop() }
            }
        }

        test("a rejected call ends on both sides with DECLINED").config(timeout = 150.seconds) {
            val (a, b) = twoConnectedServers()
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
                linesB.awaitType("incoming").callId shouldBe callId
                cb.post("/api/call/$callId/reject").statusCode() shouldBe 202
                linesB.awaitType("ended").reason shouldBe "DECLINED"
                linesA.awaitType("ended").reason shouldBe "DECLINED"
            } finally {
                runCatching { a.server.stop() }
                runCatching { b.server.stop() }
            }
        }
    })
