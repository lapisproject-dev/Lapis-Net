package net.lapisphilosophorum.lapisnet.browser

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import kotlinx.serialization.json.Json
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.config.DeclaredReachability
import net.lapisphilosophorum.lapisnet.networking.config.NodeWiringOptions
import kotlin.time.Duration.Companion.seconds

private val json = Json { ignoreUnknownKeys = true }

class NodeStatusAndGuardTest :
    FunSpec({
        test("GET /api/node/status reports the configuration and no absolute path").config(timeout = 90.seconds) {
            val config =
                BrowserConfig(
                    NodeWiringOptions(reachability = DeclaredReachability.PUBLIC, dhtFallback = false),
                    DmAcceptanceSettings(veritasGate = true, karmaMinScore = 4.0),
                )
            val server = startWiredTestServer(config = config)
            try {
                val port = server.boundPort
                val (status, body) = rawHttp(port, "GET", "/api/node/status", mapOf("Host" to "127.0.0.1:$port"))
                status shouldBe 200
                val parsed = json.decodeFromString<NodeStatusResponse>(body)
                parsed.reachability shouldBe "public"
                parsed.dhtFallback shouldBe false
                parsed.autoRelay shouldBe false
                parsed.autoRelayRunning shouldBe false
                parsed.relayReservations shouldBe 0
                parsed.publishRelayReliability shouldBe false
                // hole punching: default auto, but a public node does not punch
                parsed.holePunching.mode shouldBe "auto"
                parsed.holePunching.active shouldBe false
                parsed.holePunching.attempts shouldBe 0L
                parsed.acceptanceGates shouldBe listOf("veritas-path", "karma>=4.0")
                parsed.configFile shouldBe "browser.properties"
                body shouldNotContain "/home/"
                body shouldNotContain "/tmp"
            } finally {
                server.stop()
            }
        }

        test("the status and the accept route refuse a foreign Host header (DNS rebinding) and foreign origins").config(
            timeout = 90.seconds,
        ) {
            val server = startWiredTestServer()
            try {
                val port = server.boundPort
                val peer = hexOfKey(DualKeyIdentity.generate().secp256k1KeyPair.publicKey)
                rawHttp(port, "GET", "/api/node/status", mapOf("Host" to "evil.example:$port")).first shouldBe 421
                rawHttp(port, "GET", "/api/node/status", mapOf("Host" to "127.0.0.1:1")).first shouldBe 421
                rawHttp(
                    port,
                    "GET",
                    "/api/node/status",
                    mapOf("Host" to "127.0.0.1:$port", "Sec-Fetch-Site" to "cross-site"),
                ).first shouldBe 403
                rawHttp(
                    port,
                    "GET",
                    "/api/node/status",
                    mapOf("Host" to "127.0.0.1:$port", "Origin" to "http://evil.example"),
                ).first shouldBe 403

                val acceptPath = "/api/dm/$peer/accept"
                val jsonHeaders = mapOf("Content-Type" to "application/json")

                fun accept(extra: Map<String, String>) =
                    rawHttp(port, "POST", acceptPath, jsonHeaders + extra, "{}").first
                accept(mapOf("Host" to "evil.example:$port")) shouldBe 421
                accept(mapOf("Host" to "127.0.0.1:$port", "Origin" to "http://evil.example")) shouldBe 403
                accept(mapOf("Host" to "127.0.0.1:$port", "Origin" to "http://127.0.0.1:${port + 1}")) shouldBe 403
                accept(mapOf("Host" to "127.0.0.1:$port", "Sec-Fetch-Site" to "cross-site")) shouldBe 403
                server.acceptedContactsForTesting().snapshot() shouldBe emptyList()

                // the send route also accepts the recipient as a contact, so it is guarded the same way
                fun send(extra: Map<String, String>) =
                    rawHttp(port, "POST", "/api/dm/$peer", jsonHeaders + extra, """{"body":"hi"}""").first
                send(mapOf("Host" to "evil.example:$port")) shouldBe 421
                send(mapOf("Host" to "127.0.0.1:$port", "Origin" to "http://evil.example")) shouldBe 403
                send(mapOf("Host" to "127.0.0.1:$port", "Sec-Fetch-Site" to "cross-site")) shouldBe 403
                server.acceptedContactsForTesting().snapshot() shouldBe emptyList()
                // the page itself is allowed
                accept(mapOf("Host" to "127.0.0.1:$port", "Origin" to "http://127.0.0.1:$port")) shouldBe 200
                server.acceptedContactsForTesting().snapshot().size shouldBe 1
            } finally {
                server.stop()
            }
        }

        test("the status route tells the DHT fallback state, and the page shows it").config(timeout = 90.seconds) {
            val server = startWiredTestServer()
            try {
                val port = server.boundPort
                val (_, body) = rawHttp(port, "GET", "/api/node/status", mapOf("Host" to "127.0.0.1:$port"))
                json.decodeFromString<NodeStatusResponse>(body).dhtFallback shouldBe true
                val (pageStatus, page) = rawHttp(port, "GET", "/index.html", mapOf("Host" to "127.0.0.1:$port"))
                pageStatus shouldBe 200
                page shouldContain "node-status-dht"
                page shouldContain "node-status-acceptance"
            } finally {
                server.stop()
            }
        }

        test("GET /api/node/status reports mail gates and blocked counters, with no key or path in the JSON").config(
            timeout = 90.seconds,
        ) {
            val config =
                BrowserConfig(
                    NodeWiringOptions(dhtFallback = false),
                    DmAcceptanceSettings(),
                    MailAcceptanceSettings(veritasGate = true, karmaMinScore = 3.0),
                )
            val server = startWiredTestServer(config = config)
            try {
                val port = server.boundPort

                fun status(): Pair<NodeStatusResponse, String> {
                    val (code, body) = rawHttp(port, "GET", "/api/node/status", mapOf("Host" to "127.0.0.1:$port"))
                    code shouldBe 200
                    return json.decodeFromString<NodeStatusResponse>(body) to body
                }
                val (initial, _) = status()
                initial.mailAcceptanceGates shouldBe listOf("veritas-path", "karma>=3.0")
                initial.acceptanceGates shouldBe emptyList()
                initial.mailBlocked shouldBe MailBlockedStatus()

                server.acceptanceForTesting.mailBlocks.record(MailBlockReason.ALL_ACTIVE_GATES_FAILED, 42L)
                server.acceptanceForTesting.mailBlocks.record(MailBlockReason.VERITAS_BELOW_THRESHOLD, 43L)
                val (after, body) = status()
                after.mailBlocked.total shouldBe 2
                after.mailBlocked.byReason shouldBe
                    mapOf("all-active-gates-failed" to 1L, "veritas-below-threshold" to 1L)
                after.mailBlocked.lastBlockedEpochSecond shouldBe 43L
                Regex("[0-9a-fA-F]{64}").containsMatchIn(body) shouldBe false
                body shouldNotContain "/home/"
                body shouldNotContain "/tmp"
            } finally {
                server.stop()
            }
        }

        test("a status response without the V0.9.17 fields still decodes (defaults)") {
            val old =
                """{"reachability":"public","autoRelay":false,"autoRelayRunning":false,"relayReservations":0,""" +
                    """"dhtFallback":true,"publishRelayReliability":false,"acceptanceGates":[],"configFile":"browser.properties"}"""
            val parsed = json.decodeFromString<NodeStatusResponse>(old)
            parsed.mailAcceptanceGates shouldBe emptyList()
            parsed.mailBlocked.total shouldBe 0
        }
    })
