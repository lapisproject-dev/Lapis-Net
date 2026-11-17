package net.lapisphilosophorum.lapisnet.browser

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import net.lapisphilosophorum.lapisnet.directory.ANONYMOUS_MAILBOX_GOSSIP_TOPIC
import net.lapisphilosophorum.lapisnet.directory.ANONYMOUS_PEER_RECORD_GOSSIP_TOPIC
import net.lapisphilosophorum.lapisnet.directory.ONION_RELAY_DESCRIPTOR_GOSSIP_TOPIC
import net.lapisphilosophorum.lapisnet.directory.ONION_SERVICE_DESCRIPTOR_GOSSIP_TOPIC
import net.lapisphilosophorum.lapisnet.directory.PeerDirectoryGossip
import net.lapisphilosophorum.lapisnet.directory.PrekeyBundleGossip
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.karma.KarmaGossip
import net.lapisphilosophorum.lapisnet.madli.MadliGossip
import net.lapisphilosophorum.lapisnet.networking.ANONYMITY_GOSSIP_ALLOWLIST
import net.lapisphilosophorum.lapisnet.networking.config.AnonymityMode
import net.lapisphilosophorum.lapisnet.networking.config.NodeWiringOptions
import net.lapisphilosophorum.lapisnet.networking.dcutr.HolePunchMode
import net.lapisphilosophorum.lapisnet.networking.deriveLibp2pPeerId
import net.lapisphilosophorum.lapisnet.storage.StorageNetworkMode
import net.lapisphilosophorum.lapisnet.trust.VeritasGossip
import net.lapisphilosophorum.lapisnet.virtus.LtrGossip
import kotlin.time.Duration.Companion.seconds

/** Every endpoint that would publish from the node itself or dial a peer directly, with a minimal JSON body. */
private val REFUSED_ENDPOINTS: List<Triple<String, String, String>> =
    listOf(
        Triple("/api/posts", """{"text":"hello"}""", "anonymity-publish-unavailable"),
        Triple("/api/karma", """{"targetCid":"x"}""", "anonymity-publish-unavailable"),
        Triple("/api/trust", """{"targetPublicKeyHex":"00","trustMicros":1}""", "anonymity-publish-unavailable"),
        Triple(
            "/api/ltr/lightning",
            """{"cid":"x","viewIdHex":"00","preimageHex":"00","signedInvoice":"x"}""",
            "anonymity-publish-unavailable",
        ),
        Triple("/api/self-link", """{"targetPublicKeyHex":"00","label":""}""", "anonymity-publish-unavailable"),
        Triple("/api/peers/connect", """{"multiaddr":"/ip4/127.0.0.1/tcp/1"}""", "anonymity-connect-unavailable"),
        Triple("/api/connect/uri", """{"uri":"lapisnet://connect"}""", "anonymity-connect-unavailable"),
    )

/** Wave V0.10.0-J1a in the browser: per-run transport key, local-only storage, receive-only gossip, 409 refusals. */
class BrowserAnonymityTransportHygieneTest :
    FunSpec({
        test("the gossip allowlist repeats the real topic constants character for character") {
            ANONYMITY_GOSSIP_ALLOWLIST shouldBe
                setOf(
                    ANONYMOUS_PEER_RECORD_GOSSIP_TOPIC,
                    ONION_SERVICE_DESCRIPTOR_GOSSIP_TOPIC,
                    ONION_RELAY_DESCRIPTOR_GOSSIP_TOPIC,
                    ANONYMOUS_MAILBOX_GOSSIP_TOPIC,
                    MadliGossip.MADLI_DAILY_VECTOR_GOSSIP_TOPIC,
                    PeerDirectoryGossip.PEER_RECORD_GOSSIP_TOPIC,
                    PrekeyBundleGossip.PREKEY_BUNDLE_GOSSIP_TOPIC,
                    VeritasGossip.VERITAS_GRANT_GOSSIP_TOPIC,
                    LtrGossip.LTR_RECORD_GOSSIP_TOPIC,
                    KarmaGossip.KARMA_VOTE_GOSSIP_TOPIC,
                    PostAnnouncementGossip.POST_ANNOUNCEMENT_GOSSIP_TOPIC,
                )
        }

        test("anonymity on: ephemeral PeerId, no mDNS, local-only storage, no DHT, receive-only gossip, 409s").config(
            timeout = 120.seconds,
        ) {
            val identity = DualKeyIdentity.generate()
            val config =
                BrowserConfig(NodeWiringOptions(anonymity = AnonymityMode.ON, holePunching = HolePunchMode.OFF))
            val server = startWiredTestServer(identity = identity, config = config)
            try {
                val port = server.boundPort
                server.nodeForTesting.peerId shouldNotBe identity.deriveLibp2pPeerId()
                server.nodeForTesting.mdnsRunning shouldBe false
                server.storageForTesting.networkMode shouldBe StorageNetworkMode.LOCAL_ONLY
                server.directoryDhtForTesting.shouldBeNull()
                server.dhtOutboxForTesting.shouldBeNull()
                server.autoRelaySelectorForTesting.shouldBeNull()
                server.relayReliabilityJobForTesting.shouldBeNull()
                server.pubsubForTesting.anonymityRestricted shouldBe true
                // every subscribed topic is on the allowlist, and nothing was published from the node
                (server.pubsubForTesting.subscribedTopics() - ANONYMITY_GOSSIP_ALLOWLIST) shouldBe emptySet()
                server.pubsubForTesting.refusedSubscriptions shouldBe 0
                for ((path, body, code) in REFUSED_ENDPOINTS) {
                    val (status, text) =
                        rawHttp(
                            port,
                            "POST",
                            path,
                            mapOf("Host" to "127.0.0.1:$port", "Content-Type" to "application/json"),
                            body,
                        )
                    withClue(path) {
                        status shouldBe 409
                        text shouldContain code
                    }
                }
                server.pubsubForTesting.refusedPublications shouldBe 0
            } finally {
                server.stop()
            }
        }

        test(
            "anonymity off: identity-derived PeerId, mDNS, network storage, DHT, and no 409 on these endpoints",
        ).config(
            timeout = 90.seconds,
        ) {
            val identity = DualKeyIdentity.generate()
            val server = startWiredTestServer(identity = identity)
            try {
                val port = server.boundPort
                server.nodeForTesting.peerId shouldBe identity.deriveLibp2pPeerId()
                server.nodeForTesting.mdnsRunning shouldBe true
                server.storageForTesting.networkMode shouldBe StorageNetworkMode.NETWORK
                server.directoryDhtForTesting.shouldNotBeNull()
                server.pubsubForTesting.anonymityRestricted shouldBe false
                for ((path, body, _) in REFUSED_ENDPOINTS) {
                    val (status, _) =
                        rawHttp(
                            port,
                            "POST",
                            path,
                            mapOf("Host" to "127.0.0.1:$port", "Content-Type" to "application/json"),
                            body,
                        )
                    withClue(path) { status shouldNotBe 409 }
                }
            } finally {
                server.stop()
            }
        }
    })

private inline fun <T> withClue(
    clue: String,
    block: () -> T,
): T = io.kotest.assertions.withClue(clue, block)
