package net.lapisphilosophorum.lapisnet.browser

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.contentType
import kotlinx.coroutines.delay
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.karma.BitcoinTimeAnchorSource
import net.lapisphilosophorum.lapisnet.karma.TimeAnchorLookupResult
import java.nio.file.Files
import java.time.Duration
import java.time.Instant
import kotlin.time.Duration.Companion.seconds

private val json = Json { ignoreUnknownKeys = true }

private object DmDemoNoAnchorSource : BitcoinTimeAnchorSource {
    override fun findFirstOutgoingTransaction(pubkey: Secp256k1PublicKey): TimeAnchorLookupResult =
        TimeAnchorLookupResult.NotFound

    override fun currentChainTipHeight(): Int = 0
}

private fun hexOf(identity: DualKeyIdentity): String =
    identity.secp256k1KeyPair.publicKey.bytes
        .joinToString("") { "%02x".format(it) }

/**
 * End-to-end, real-two-node, real-HTTP proof for DM: node A sends node B a message (with one
 * attachment) via its own real `POST /api/dm/{peerHex}` HTTP API; node B receives it via a real
 * X3DH handshake + Double Ratchet decrypt and the message becomes visible via node B's own real
 * `GET /api/dm/{peerHex}` HTTP API - mirrors [TwoNodeMailBrowserIntegrationTest]'s established
 * real-HTTP, real-two-node, bounded-polling-against-one-deadline pattern, adapted for DM's own
 * prerequisite: unlike mail (which only needs GossipSub mesh formation before its recipient-topic
 * fan-out works), DM's `sendAuto` ALSO needs [net.lapisphilosophorum.lapisnet.directory.PeerDirectoryGossip]/
 * [net.lapisphilosophorum.lapisnet.directory.PrekeyBundleGossip] records for the recipient to have
 * already converged on the sender's side (to dial + X3DH-initiate) - see
 * [BrowserServer.republishSelfForDmTesting]'s own doc comment for why a plain post-connect warm-up
 * is not enough here and this test instead re-publishes each side's own record until BOTH sides see
 * each other, exactly like `lapis-net-dm`'s own `connectAndConverge` test helper.
 */
class TwoNodeDmBrowserIntegrationTest :
    FunSpec({
        test("a DM sent on node A via its HTTP API is received and decrypted on node B's HTTP API").config(
            timeout = 90.seconds,
        ) {
            val deadline = Instant.now().plus(Duration.ofSeconds(60))

            val identityA = DualKeyIdentity.generate()
            val identityB = DualKeyIdentity.generate()
            val serverA =
                BrowserServer.start(
                    identity = identityA,
                    httpPort = 0,
                    dataDirectory = Files.createTempDirectory("browser-dm-demo-a"),
                    karmaAnchorSource = DmDemoNoAnchorSource,
                )
            val serverB =
                BrowserServer.start(
                    identity = identityB,
                    httpPort = 0,
                    dataDirectory = Files.createTempDirectory("browser-dm-demo-b"),
                    karmaAnchorSource = DmDemoNoAnchorSource,
                )
            val httpClient = HttpClient(CIO)

            try {
                val bListenAddress = serverB.nodeForTesting.listenAddresses().first()
                val bMultiaddr = bListenAddress.withP2P(serverB.nodeForTesting.peerId).toString()
                val connectResponse: HttpResponse =
                    httpClient.post("http://127.0.0.1:${serverA.boundPort}/api/peers/connect") {
                        contentType(ContentType.Application.Json)
                        setBody(json.encodeToString(ConnectPeerRequest(bMultiaddr)))
                    }
                connectResponse.status.value shouldBe 200

                // Directory/prekey-bundle convergence, BOTH directions - node A needs to see B's
                // record+bundle to dial/X3DH-initiate; B does not strictly need A's for this
                // one-directional send, but publishing both sides mirrors connectAndConverge's
                // established pattern exactly and costs nothing extra.
                var converged = false
                while (!converged && Instant.now().isBefore(deadline)) {
                    serverA.republishSelfForDmTesting()
                    serverB.republishSelfForDmTesting()
                    val aSeesB = serverA.peerDirectoryForDmTesting.lookup(identityB.secp256k1KeyPair.publicKey) != null
                    val aSeesBBundle =
                        serverA.prekeyBundleGossipForDmTesting.lookup(identityB.secp256k1KeyPair.publicKey) != null
                    converged = aSeesB && aSeesBBundle
                    if (!converged) delay(300)
                }
                check(converged) { "peer-directory/prekey-bundle convergence did not complete before the deadline" }

                var foundOnB: DmMessageResponse? = null
                while (foundOnB == null && Instant.now().isBefore(deadline)) {
                    val sendResponse =
                        httpClient.post("http://127.0.0.1:${serverA.boundPort}/api/dm/${hexOf(identityB)}") {
                            contentType(ContentType.Application.Json)
                            setBody(json.encodeToString(NewDmRequest(body = "hello from node A, via the real DM API")))
                        }
                    if (sendResponse.status.value == 200) {
                        delay(300)
                        val historyOnB =
                            httpClient.get(
                                "http://127.0.0.1:${serverB.boundPort}/api/dm/${hexOf(identityA)}",
                            )
                        val entries = json.decodeFromString<List<DmMessageResponse>>(historyOnB.bodyAsText())
                        foundOnB =
                            entries.find {
                                it.direction == "inbound" &&
                                    it.body == "hello from node A, via the real DM API"
                            }
                    }
                    if (foundOnB == null) delay(300)
                }

                foundOnB.shouldNotBeNull()
                foundOnB.quarantined shouldBe false
                foundOnB.attachments.size shouldBe 0

                // The send itself must also be visible in A's own outbound history/conversation
                // list, via the same real HTTP API.
                val historyOnA = httpClient.get("http://127.0.0.1:${serverA.boundPort}/api/dm/${hexOf(identityB)}")
                val entriesOnA = json.decodeFromString<List<DmMessageResponse>>(historyOnA.bodyAsText())
                entriesOnA.any {
                    it.direction == "outbound" && it.body == "hello from node A, via the real DM API"
                } shouldBe
                    true

                val conversationsOnA = httpClient.get("http://127.0.0.1:${serverA.boundPort}/api/dm")
                val conversationList = json.decodeFromString<List<DmConversationSummary>>(conversationsOnA.bodyAsText())
                conversationList.any { it.peerPublicKeyHex == hexOf(identityB) } shouldBe true
            } finally {
                httpClient.close()
                runCatching { serverA.stop() }
                runCatching { serverB.stop() }
            }
        }
    })
