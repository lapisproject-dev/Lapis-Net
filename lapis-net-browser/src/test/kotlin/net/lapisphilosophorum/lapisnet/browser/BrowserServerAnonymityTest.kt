@file:OptIn(net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.browser

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import kotlinx.serialization.json.Json
import net.lapisphilosophorum.lapisnet.directory.DirectoryAnonymityMode
import net.lapisphilosophorum.lapisnet.directory.DirectoryModeState
import net.lapisphilosophorum.lapisnet.directory.FileDirectoryModeStore
import net.lapisphilosophorum.lapisnet.dm.DmAnonymousDeliveryException
import net.lapisphilosophorum.lapisnet.dm.DmAnonymousFailure
import net.lapisphilosophorum.lapisnet.dm.DmContent
import net.lapisphilosophorum.lapisnet.dm.DmRoute
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.config.AnonymityMode
import net.lapisphilosophorum.lapisnet.networking.config.NodeWiringOptions
import net.lapisphilosophorum.lapisnet.networking.dcutr.HolePunchMode
import java.nio.file.Files
import kotlin.time.Duration.Companion.seconds

private val json = Json { ignoreUnknownKeys = true }

private fun onionThreads(): List<String> =
    Thread
        .getAllStackTraces()
        .keys
        .filter { it.isAlive && (it.name.startsWith("lapis-net-onion") || it.name.startsWith("lapis-net-anonymous")) }
        .map { it.name }

class BrowserServerAnonymityTest :
    FunSpec({
        test(
            "anonymity off: status says so, no runtime, no onion thread, and OFF is persisted",
        ).config(timeout = 90.seconds) {
            val dir = Files.createTempDirectory("browser-anon-off")
            val server = startWiredTestServer(dataDirectory = dir)
            try {
                val port = server.boundPort
                val (code, body) = rawHttp(port, "GET", "/api/node/status", mapOf("Host" to "127.0.0.1:$port"))
                code shouldBe 200
                val parsed = json.decodeFromString<NodeStatusResponse>(body)
                parsed.anonymityMode shouldBe "off"
                parsed.anonymityIncomplete shouldBe false
                parsed.guards shouldBe 0
                parsed.activeCircuits shouldBe 0
                parsed.lastAnonymityError shouldBe "none"
                server.anonymityRuntimeForTesting.shouldBeNull()
                // normal mode: the direct DM path with the own mailbox topic, exactly as before
                server.mailboxGossipOrNullForTesting.shouldNotBeNull()
                server.dmSessionManagerForTesting.routeMode() shouldBe DmRoute.DIRECT
                server.anonymityStatus().mode shouldBe "off"
                onionThreads() shouldBe emptyList()
                FileDirectoryModeStore(dir.resolve("directory-mode.state")).load().shouldNotBeNull().mode shouldBe
                    DirectoryAnonymityMode.OFF
                // the connect code works as before
                rawHttp(port, "GET", "/api/connect/info", mapOf("Host" to "127.0.0.1:$port")).first shouldBe 200
            } finally {
                server.stop()
            }
        }

        test(
            "a start in normal mode without any mesh peer keeps ON: a revocation nobody received is not 'sent'",
        ).config(
            timeout = 90.seconds,
        ) {
            val dir = Files.createTempDirectory("browser-anon-retire")
            val identity = DualKeyIdentity.generate()
            FileDirectoryModeStore(dir.resolve("directory-mode.state"))
                .save(DirectoryModeState(DirectoryAnonymityMode.ON, System.currentTimeMillis() - 1000))
            val server = startWiredTestServer(identity = identity, dataDirectory = dir)
            try {
                // OFF is persisted only after a mesh peer received the revocation; a lone test node has none, so the old
                // mode stays and the next start builds a fresh, higher-numbered revocation
                FileDirectoryModeStore(dir.resolve("directory-mode.state")).load().shouldNotBeNull().mode shouldBe
                    DirectoryAnonymityMode.ON
                val own =
                    server.peerDirectoryForDmTesting.lookup(identity.secp256k1KeyPair.publicKey)
                own.shouldNotBeNull().addresses.isNotEmpty() shouldBe true
            } finally {
                server.stop()
            }
        }

        test(
            "anonymity on: status fields, no address anywhere, connect code refused, hole punching off, clean stop",
        ).config(timeout = 120.seconds) {
            val dir = Files.createTempDirectory("browser-anon-on")
            val baseline = onionThreads().size
            val config =
                BrowserConfig(NodeWiringOptions(anonymity = AnonymityMode.ON, holePunching = HolePunchMode.OFF))
            val server = startWiredTestServer(config = config, dataDirectory = dir)
            try {
                val port = server.boundPort
                server.anonymityRuntimeForTesting.shouldNotBeNull()
                // the own direct mailbox topic is NOT subscribed and sends use circuits only; until the runtime is
                // ready a send is refused (no fallback to a direct connection)
                server.mailboxGossipOrNullForTesting.shouldBeNull()
                server.dmSessionManagerForTesting.routeMode() shouldBe DmRoute.CIRCUIT
                val refused =
                    shouldThrow<DmAnonymousDeliveryException> {
                        server.dmSessionManagerForTesting.sendAuto(
                            DualKeyIdentity.generate().secp256k1KeyPair.publicKey,
                            DmContent(body = "no route yet"),
                        )
                    }
                refused.failure shouldBe DmAnonymousFailure.ANONYMITY_NOT_READY
                // the periodic maintenance runs once after a second; loopback has no relay at all
                var parsed: NodeStatusResponse
                var body: String
                val deadline = System.nanoTime() + 20_000_000_000L
                do {
                    Thread.sleep(200)
                    body = rawHttp(port, "GET", "/api/node/status", mapOf("Host" to "127.0.0.1:$port")).second
                    parsed = json.decodeFromString<NodeStatusResponse>(body)
                } while (parsed.lastAnonymityError != "insufficient-relays" && System.nanoTime() < deadline)
                parsed.anonymityMode shouldBe "on"
                parsed.anonymityIncomplete shouldBe true
                parsed.lastAnonymityError shouldBe "insufficient-relays"
                (parsed.lastAnonymityErrorAgeSeconds != null) shouldBe true
                parsed.guards shouldBe 0
                parsed.holePunching.mode shouldBe "off"
                parsed.holePunching.active shouldBe false
                for (leak in listOf("127.0.0.1", "/ip4", "/tcp", "12D3Koo", "/p2p/")) body shouldNotContain leak

                // the connect code would hand out the node's address (leak #17)
                for (path in listOf("/api/connect/qr.svg", "/api/connect/info")) {
                    val (code, text) = rawHttp(port, "GET", path, mapOf("Host" to "127.0.0.1:$port"))
                    code shouldBe 409
                    text shouldContain "disabled while anonymity mode is on"
                    text shouldNotContain "lapisnet://"
                }
                // nothing was published from this node itself
                Files.exists(dir.resolve("directory-mode.state")) shouldBe false
            } finally {
                server.stop()
            }
            val deadline = System.nanoTime() + 15_000_000_000L
            while (System.nanoTime() < deadline && onionThreads().size > baseline) Thread.sleep(100)
            onionThreads().size shouldBe baseline
        }
    })
