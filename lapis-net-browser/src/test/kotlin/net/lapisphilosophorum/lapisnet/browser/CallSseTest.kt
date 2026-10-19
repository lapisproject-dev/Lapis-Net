package net.lapisphilosophorum.lapisnet.browser

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldStartWith
import kotlinx.serialization.json.Json
import net.lapisphilosophorum.lapisnet.call.CallEvent
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.karma.BitcoinTimeAnchorSource
import net.lapisphilosophorum.lapisnet.karma.TimeAnchorLookupResult
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

private object SseNoAnchor : BitcoinTimeAnchorSource {
    override fun findFirstOutgoingTransaction(pubkey: Secp256k1PublicKey): TimeAnchorLookupResult =
        TimeAnchorLookupResult.NotFound

    override fun currentChainTipHeight(): Int = 0
}

/** A minimal same-origin client for the call routes of a real [BrowserServer]. */
internal class CallHttpClient(
    private val server: BrowserServer,
) {
    val http: HttpClient = HttpClient.newHttpClient()
    private val base = "http://127.0.0.1:${server.boundPort}"
    var cookie: String? = null

    private fun builder(path: String): HttpRequest.Builder {
        val scoped =
            if (path == "/api/call/session") {
                path
            } else {
                path.replaceFirst("/api/call/", "/api/call/${server.callTokenForTesting.scope}/")
            }
        val b = HttpRequest.newBuilder(URI("$base$scoped"))
        cookie?.let { b.header("Cookie", it) }
        return b
    }

    fun exchangeToken(): Int {
        val request =
            builder("/api/call/session")
                .header("Origin", base)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"token\":\"${server.callTokenForTesting.hex}\"}"))
                .build()
        val response = http.send(request, HttpResponse.BodyHandlers.ofString())
        response.headers().firstValue("set-cookie").ifPresent { cookie = it.substringBefore(';') }
        return response.statusCode()
    }

    fun post(
        path: String,
        body: String = "{}",
    ): HttpResponse<String> =
        http.send(
            builder(path)
                .header("Origin", base)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build(),
            HttpResponse.BodyHandlers.ofString(),
        )

    fun get(path: String): HttpResponse<String> =
        http.send(builder(path).GET().build(), HttpResponse.BodyHandlers.ofString())

    /** Opens the event stream; the returned lines queue is fed by a daemon reader thread. */
    fun openEvents(): Pair<HttpResponse<java.io.InputStream>, LinkedBlockingQueue<String>> {
        val response =
            http.send(builder("/api/call/events").GET().build(), HttpResponse.BodyHandlers.ofInputStream())
        val lines = LinkedBlockingQueue<String>()
        if (response.statusCode() == 200) {
            Thread {
                runCatching {
                    BufferedReader(InputStreamReader(response.body())).use { reader ->
                        while (true) lines.put(reader.readLine() ?: break)
                    }
                }
            }.apply { isDaemon = true }.start()
        }
        return response to lines
    }
}

internal fun startCallTestServer(
    identity: DualKeyIdentity = DualKeyIdentity.generate(),
    remote: CallRemote? = null,
    heartbeat: kotlin.time.Duration = 15.seconds,
): BrowserServer =
    BrowserServer.start(
        identity = identity,
        httpPort = 0,
        dataDirectory = Files.createTempDirectory("call-sse-test"),
        karmaAnchorSource = SseNoAnchor,
        callMediaEngineFactory = { FakeBrowserCallMediaEngine() },
        callHeartbeatInterval = heartbeat,
        callRemoteOverride = remote,
    )

private fun LinkedBlockingQueue<String>.awaitLine(
    timeoutSeconds: Long = 10,
    predicate: (String) -> Boolean,
): String {
    val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(timeoutSeconds)
    while (System.nanoTime() < deadline) {
        val line = poll(100, TimeUnit.MILLISECONDS) ?: continue
        if (predicate(line)) return line
    }
    error("expected line not received within ${timeoutSeconds}s")
}

class CallSseTest :
    FunSpec({
        test("the stream sends retry, heartbeats and events as event/data frames with valid JSON").config(
            timeout = 60.seconds,
        ) {
            val remote = FakeCallRemote()
            val server = startCallTestServer(remote = remote, heartbeat = 200.milliseconds)
            try {
                val client = CallHttpClient(server)
                client.exchangeToken() shouldBe 200
                val (response, lines) = client.openEvents()
                response.statusCode() shouldBe 200
                response.headers().firstValue("content-type").get() shouldStartWith "text/event-stream"
                response.headers().firstValue("cache-control").get() shouldBe "no-store"
                lines.awaitLine { it == "retry: 3000" }
                lines.awaitLine { it == ": ping" }

                remote.emit(CallEvent.OutgoingRinging(randomCallId(), randomPeer()))
                lines.awaitLine { it == "event: ringing" }
                val data = lines.awaitLine { it.startsWith("data: ") }
                val parsed = Json.decodeFromString<CallUiEvent>(data.removePrefix("data: "))
                parsed.type shouldBe "ringing"
                data shouldContain "\"unaccepted\":false"
                response.body().close()
            } finally {
                server.stop()
            }
        }

        test("only four streams are served at once; the fifth and sixth get 429; closing one frees a slot").config(
            timeout = 60.seconds,
        ) {
            val server = startCallTestServer(remote = FakeCallRemote(), heartbeat = 200.milliseconds)
            try {
                val client = CallHttpClient(server)
                client.exchangeToken() shouldBe 200
                val opened = (1..6).map { client.openEvents().first }
                opened.map { it.statusCode() } shouldBe listOf(200, 200, 200, 200, 429, 429)
                opened[0].body().close()
                val hub = server.callEventHubForTesting!!
                val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
                while (hub.subscriberCountForTesting() > 3 && System.nanoTime() < deadline) Thread.sleep(50)
                hub.subscriberCountForTesting() shouldBe 3
                client.openEvents().first.statusCode() shouldBe 200
                opened.drop(1).take(3).forEach { runCatching { it.body().close() } }
            } finally {
                server.stop()
            }
        }

        test("after the client disconnects the subscriber count drops back to zero").config(timeout = 60.seconds) {
            val server = startCallTestServer(remote = FakeCallRemote(), heartbeat = 200.milliseconds)
            try {
                val client = CallHttpClient(server)
                client.exchangeToken() shouldBe 200
                val (response, lines) = client.openEvents()
                response.statusCode() shouldBe 200
                lines.awaitLine { it == "retry: 3000" }
                val hub = server.callEventHubForTesting!!
                hub.subscriberCountForTesting() shouldBe 1
                response.body().close()
                val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
                while (hub.subscriberCountForTesting() > 0 && System.nanoTime() < deadline) Thread.sleep(50)
                hub.subscriberCountForTesting() shouldBe 0
            } finally {
                server.stop()
            }
        }

        test("an unauthenticated stream request is refused before a slot is taken").config(timeout = 60.seconds) {
            val server = startCallTestServer(remote = FakeCallRemote())
            try {
                val client = CallHttpClient(server)
                client.openEvents().first.statusCode() shouldBe 401
                server.callEventHubForTesting!!.subscriberCountForTesting() shouldBe 0
            } finally {
                server.stop()
            }
        }
    })
