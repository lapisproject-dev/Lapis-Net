package net.lapisphilosophorum.lapisnet.dm

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.ratchet.RatchetMessageCodec
import java.time.Duration
import java.time.Instant
import java.util.Collections
import kotlin.random.Random

/**
 * A REAL two-node loopback test: two actual [net.lapisphilosophorum.lapisnet.networking.LapisNode]
 * instances, real libp2p transport (TCP+Noise+mplex), directory/prekey-bundle gossip actually
 * converging, a real X3DH handshake, a real Double Ratchet session, and a real `/lapis/dm/1.0.0`
 * stream - node A sends a real message to node B via the FULL stack, node B receives and decrypts
 * it, asserted byte-for-byte. Mirrors `TwoNodePrekeyBundleGossipIntegrationTest`'s/
 * `TwoNodeMailGossipIntegrationTest`'s bounded-polling-against-one-deadline discipline: no fixed
 * `Thread.sleep` wait for the OUTCOME, only a short sleep between retries.
 *
 * **Generously timed on purpose.** A raw stream-protocol handshake (directory lookup + prekey-bundle
 * lookup + dial + X3DH + Double Ratchet + the `/lapis/dm/1.0.0` stream itself) has more moving parts
 * than a bare gossip publish - a prior sub-wave's two-node GOSSIP integration test flaked once in CI
 * on a `SemiDuplexNoOutboundStreamException`-class libp2p timing issue, resolved by a rerun. This
 * test's `send()` retry loop below retries the WHOLE `send()` call (not just the polling
 * assertion) on failure, mirroring `TwoNodeMailGossipIntegrationTest`'s republish-on-timeout pattern
 * adapted for this wave: each retry legitimately produces a fresh envelope over the SAME session
 * after the first attempt (or a fresh X3DH_INITIAL if the first attempt never got far enough to
 * persist a session at all).
 */
class TwoNodeDmIntegrationTest :
    FunSpec({
        test("node A sends a real DM to node B through the full stack - directory, X3DH, ratchet, DmProtocol stream") {
            val nodeA = buildDmTestNode()
            val nodeB = buildDmTestNode()
            try {
                connectAndConverge(nodeA, nodeB)

                val received = Collections.synchronizedList(mutableListOf<DmInboundMessage>())
                nodeB.dmSessionManager.addInboundListener { received.add(it) }

                val identityAPub = nodeA.identity.secp256k1KeyPair.publicKey
                val identityBPub = nodeB.identity.secp256k1KeyPair.publicKey
                val plaintext = Random.nextBytes(4096) // large enough to not be a trivially-tiny payload

                val deadline = Instant.now().plus(Duration.ofSeconds(30))
                while (received.isEmpty() && Instant.now().isBefore(deadline)) {
                    runCatching { nodeA.dmSessionManager.send(identityBPub, plaintext) }
                    Thread.sleep(1000)
                }

                received.isEmpty() shouldBe false
                val message = received[0]
                message.sender shouldBe identityAPub
                message.plaintext shouldBe plaintext
                message.dedupKey.size shouldBe 32
            } finally {
                nodeA.stop()
                nodeB.stop()
            }
        }

        test(
            "a MAXIMUM-size DM (RatchetMessageCodec.MAX_PLAINTEXT_BYTES plaintext, producing exactly " +
                "DmEnvelopeCodec.MAX_ENVELOPE_BYTES of encoded envelope) round-trips through the REAL " +
                "two-node stack, not just through DmEnvelopeCodec directly (security audit round 1 " +
                "finding, 2026-08-11: DmProtocolHandler's own LengthFieldBasedFrameDecoder was " +
                "misconfigured 4 bytes too small - maxFrameLength = MAX_ENVELOPE_BYTES instead of " +
                "MAX_ENVELOPE_BYTES + the 4-byte length prefix Netty also counts - so exactly the " +
                "largest legitimate envelopes DmEnvelopeCodec itself accepts were silently discarded " +
                "on the wire with no error surfaced to the sender, since this wave is fire-and-forget " +
                "with no application-level ack; no prior test in this suite sent a maximum-size " +
                "envelope through the real prepender/decoder pair to catch it)",
        ) {
            val nodeA = buildDmTestNode()
            val nodeB = buildDmTestNode()
            try {
                connectAndConverge(nodeA, nodeB)

                val received = Collections.synchronizedList(mutableListOf<DmInboundMessage>())
                nodeB.dmSessionManager.addInboundListener { received.add(it) }

                val identityAPub = nodeA.identity.secp256k1KeyPair.publicKey
                val identityBPub = nodeB.identity.secp256k1KeyPair.publicKey
                val plaintext = Random.nextBytes(RatchetMessageCodec.MAX_PLAINTEXT_BYTES)

                val deadline = Instant.now().plus(Duration.ofSeconds(30))
                while (received.isEmpty() && Instant.now().isBefore(deadline)) {
                    runCatching { nodeA.dmSessionManager.send(identityBPub, plaintext) }
                    Thread.sleep(1000)
                }

                received.isEmpty() shouldBe false
                val message = received[0]
                message.sender shouldBe identityAPub
                message.plaintext shouldBe plaintext
            } finally {
                nodeA.stop()
                nodeB.stop()
            }
        }
    })
