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
import io.libp2p.core.pubsub.ValidationResult
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
import java.util.Base64
import java.util.Collections
import kotlin.time.Duration.Companion.seconds

private val json = Json { ignoreUnknownKeys = true }

/** Disposable warm-up topic - a separate, differently-named topic from
 * [TwoNodeKarmaBrowserIntegrationTest]'s/[TwoNodeBrowserPilotDemoTest]'s own so this file's warm-up
 * traffic can never collide with theirs on the same GossipSub topic string. */
private const val WARMUP_TOPIC = "lapisnet-browser-mail-demo:warmup:v1"

private object MailDemoNoAnchorSource : BitcoinTimeAnchorSource {
    override fun findFirstOutgoingTransaction(pubkey: Secp256k1PublicKey): TimeAnchorLookupResult =
        TimeAnchorLookupResult.NotFound

    override fun currentChainTipHeight(): Int = 0
}

private fun recipientHexFor(identity: DualKeyIdentity): String =
    identity.secp256k1KeyPair.publicKey.bytes
        .joinToString("") { "%02x".format(it) }

/**
 * End-to-end, real-two-node, real-HTTP proof for mail: node A composes and sends a message (with
 * one unencrypted attachment) via its own real `POST /api/mail` HTTP API; node B receives it via
 * real GossipSub propagation and the message becomes visible via node B's own real
 * `GET /api/mail` HTTP API - mirrors [TwoNodeKarmaBrowserIntegrationTest]'s established real-HTTP,
 * real-two-node, bounded-polling-against-one-deadline pattern exactly.
 *
 * **Scoping note, matching a documented, pre-existing limitation (see [NabuStorage.get]'s doc
 * comment; `MailApi.kt`'s `GET /api/mail/attachment/{cid}` route repeats it): this test does NOT
 * assert that node B can successfully fetch the attachment CROSS-NODE.** `NabuStorage.get()`'s
 * cross-node fetch path (`Kademlia.dialPeer`/provider-discovery) has been documented broken since
 * V0.1.4 - a node can only reliably retrieve a blob it already has locally. This test instead
 * asserts (a) the attachment's METADATA (name/mime/size/encrypted) round-trips correctly to B via
 * gossip, and (b) node A - the node that actually has the blob locally - can fetch its own
 * just-sent attachment via its own `GET /api/mail/attachment/{cid}` (the realistic end-to-end proof
 * this codebase's actual capabilities support; the single-node encrypted/unencrypted attachment
 * round trip is additionally covered directly in [BrowserApiMailRoutingTest]).
 *
 * Each retry issues a FRESH `POST /api/mail` call rather than replaying one frame via a
 * `MailSender.republish`-style call (unlike [TwoNodeMailGossipIntegrationTest], `MailSender` is not
 * reachable through the HTTP surface for a raw re-publish) - this mints a new envelope with a new
 * `sentAtEpochSecond` (and therefore a new content id/cid) on every retry, so the test always reads
 * back the LATEST response's `cid`, never a cid asserted before the retry loop started.
 */
class TwoNodeMailBrowserIntegrationTest :
    FunSpec({
        test("a message composed and sent on node A via its HTTP API propagates to node B's HTTP API").config(
            timeout = 90.seconds,
        ) {
            val deadline = Instant.now().plus(Duration.ofSeconds(60))

            val identityA = DualKeyIdentity.generate()
            val identityB = DualKeyIdentity.generate()
            val serverA =
                BrowserServer.start(
                    identity = identityA,
                    httpPort = 0,
                    dataDirectory = Files.createTempDirectory("browser-mail-demo-a"),
                    karmaAnchorSource = MailDemoNoAnchorSource,
                )
            val serverB =
                BrowserServer.start(
                    identity = identityB,
                    httpPort = 0,
                    dataDirectory = Files.createTempDirectory("browser-mail-demo-b"),
                    karmaAnchorSource = MailDemoNoAnchorSource,
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

                // Warm-up phase - see WARMUP_TOPIC's/TwoNodeKarmaBrowserIntegrationTest's doc
                // comments: GossipSub mesh formation (GRAFT) is asynchronous, so a publish issued
                // immediately after connecting has no delivery guarantee at all.
                val warmupReceivedOnB = Collections.synchronizedList(mutableListOf<ByteArray>())
                serverB.pubsubForTesting.subscribe(WARMUP_TOPIC) { bytes, _ ->
                    warmupReceivedOnB.add(bytes)
                    ValidationResult.Valid
                }
                var warmupSeq = 0
                while (warmupReceivedOnB.isEmpty() && Instant.now().isBefore(deadline)) {
                    warmupSeq++
                    runCatching { serverA.pubsubForTesting.publish(WARMUP_TOPIC, "warmup-$warmupSeq".toByteArray()) }
                    delay(200)
                }
                check(warmupReceivedOnB.isNotEmpty()) { "warm-up phase did not complete before the deadline" }

                val attachmentBase64 = Base64.getEncoder().encodeToString("attachment from node A".toByteArray())
                val newMailRequest =
                    NewMailRequest(
                        recipientsHex = listOf(recipientHexFor(identityB)),
                        subject = "mail two-node demo",
                        body = "# hello\n\nfrom node A, via the real browser HTTP API",
                        attachments =
                            listOf(
                                NewMailAttachmentRequest(
                                    name = "note.txt",
                                    mime = "text/plain",
                                    contentBase64 = attachmentBase64,
                                    encrypt = false,
                                ),
                            ),
                    )

                // Bounded polling loop against B's real /api/mail HTTP endpoint - each iteration
                // issues a FRESH POST /api/mail on A (see this class's doc comment for why a fresh
                // send, not a raw republish, is used here), so `latestCid` always tracks the most
                // recently sent envelope's cid, never a stale one from an earlier retry.
                var latestCid: String? = null
                var foundOnB: MailSummaryResponse? = null
                while (foundOnB == null && Instant.now().isBefore(deadline)) {
                    val sendResponse =
                        httpClient.post("http://127.0.0.1:${serverA.boundPort}/api/mail") {
                            contentType(ContentType.Application.Json)
                            setBody(json.encodeToString(newMailRequest))
                        }
                    sendResponse.status.value shouldBe 200
                    latestCid = json.decodeFromString<NewMailResponse>(sendResponse.bodyAsText()).cid

                    delay(300)
                    val inboxOnB = httpClient.get("http://127.0.0.1:${serverB.boundPort}/api/mail")
                    val entries = json.decodeFromString<List<MailSummaryResponse>>(inboxOnB.bodyAsText())
                    foundOnB = entries.find { it.cid == latestCid }
                }

                foundOnB.shouldNotBeNull()
                foundOnB.subject shouldBe "mail two-node demo"
                foundOnB.bodyPreview shouldBe "# hello\n\nfrom node A, via the real browser HTTP API"
                foundOnB.sender shouldBe identityA.secp256k1KeyPair.publicKey.fingerprint()
                foundOnB.decryptionFailed shouldBe false
                foundOnB.attachments.size shouldBe 1
                val attachmentOnB = foundOnB.attachments.single()
                attachmentOnB.name shouldBe "note.txt"
                attachmentOnB.mime shouldBe "text/plain"
                attachmentOnB.encrypted shouldBe false

                // The realistic end-to-end proof this codebase's actual capabilities support (see
                // this class's doc comment on the cross-node fetch scoping): node A, which has the
                // attachment blob locally, fetches its own just-sent attachment via its own real
                // GET /api/mail/attachment/{cid}.
                val attachmentOnA =
                    httpClient.get("http://127.0.0.1:${serverA.boundPort}/api/mail/attachment/${attachmentOnB.cid}")
                attachmentOnA.status.value shouldBe 200
                attachmentOnA.bodyAsText() shouldBe "attachment from node A"
            } finally {
                httpClient.close()
                runCatching { serverA.stop() }
                runCatching { serverB.stop() }
            }
        }
    })
