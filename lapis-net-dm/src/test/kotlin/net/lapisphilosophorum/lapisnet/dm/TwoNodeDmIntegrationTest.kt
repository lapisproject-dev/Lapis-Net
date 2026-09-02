package net.lapisphilosophorum.lapisnet.dm

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import java.time.Duration
import java.time.Instant
import java.util.Collections

/**
 * A REAL two-node loopback test: two actual [net.lapisphilosophorum.lapisnet.networking.LapisNode]
 * instances, real libp2p transport (TCP+Noise+mplex), directory/prekey-bundle gossip actually
 * converging, a real X3DH handshake, a real Double Ratchet session, and a real `/lapis/dm/1.1.0`
 * stream - node A sends a real message to node B via the FULL stack, node B receives and decrypts
 * it, asserted byte-for-byte. Mirrors `TwoNodePrekeyBundleGossipIntegrationTest`'s/
 * `TwoNodeMailGossipIntegrationTest`'s bounded-polling-against-one-deadline discipline: no fixed
 * `Thread.sleep` wait for the OUTCOME, only a short sleep between retries.
 *
 * **Generously timed on purpose.** A raw stream-protocol handshake (directory lookup + prekey-bundle
 * lookup + dial + X3DH + Double Ratchet + the `/lapis/dm/1.1.0` stream itself) has more moving parts
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
                // Large enough to not be a trivially-tiny payload; DmContent.body is UTF-8 text
                // (V0.8.6), so this uses an ASCII string whose byte length is exactly 4096, not raw
                // random bytes - "aaa..." repeated is deliberately non-random: this test's point is
                // payload SIZE and byte-for-byte fidelity, not entropy.
                val bodyText = "a".repeat(4096)

                val deadline = Instant.now().plus(Duration.ofSeconds(30))
                while (received.isEmpty() && Instant.now().isBefore(deadline)) {
                    runCatching { nodeA.dmSessionManager.send(identityBPub, DmContent(body = bodyText)) }
                    Thread.sleep(1000)
                }

                received.isEmpty() shouldBe false
                val message = received[0]
                message.sender shouldBe identityAPub
                message.content.body shouldBe bodyText
                message.dedupKey.size shouldBe 32
            } finally {
                nodeA.stop()
                nodeB.stop()
            }
        }

        test(
            "the LARGEST DmContent this API can build (max body + 4 max attachments + a max-size " +
                "deposit section) round-trips through the REAL two-node stack, not just through " +
                "DmEnvelopeCodec directly - the regression this test protects predates DmContent " +
                "(security audit round 1 finding, 2026-08-11: DmProtocolHandler's own " +
                "LengthFieldBasedFrameDecoder was misconfigured 4 bytes too small - maxFrameLength = " +
                "MAX_ENVELOPE_BYTES instead of MAX_ENVELOPE_BYTES + the 4-byte length prefix Netty " +
                "also counts). **V0.8.6 note**: DmContent's own field caps (MAX_DM_BODY_BYTES etc.) " +
                "mean the largest content this API can legally construct (~36.4 KB, see " +
                "DmContentCodec.MAX_CONTENT_BYTES's own worst-case-arithmetic doc comment) no longer " +
                "reaches RatchetMessageCodec.MAX_PLAINTEXT_BYTES (65,459 B) directly - DmContent.encode " +
                "cannot produce a plaintext that large any more. The `+ LENGTH_FIELD_SIZE` frame-decoder " +
                "arithmetic this test protects is still exercised at whatever size IS reachable; a " +
                "byte-for-byte proof of the frame decoder's OWN ceiling independent of DmContent lives " +
                "in DmEnvelopeCodecTest instead.",
        ) {
            val nodeA = buildDmTestNode()
            val nodeB = buildDmTestNode()
            try {
                connectAndConverge(nodeA, nodeB)

                val received = Collections.synchronizedList(mutableListOf<DmInboundMessage>())
                nodeB.dmSessionManager.addInboundListener { received.add(it) }

                val identityAPub = nodeA.identity.secp256k1KeyPair.publicKey
                val identityBPub = nodeB.identity.secp256k1KeyPair.publicKey
                val bodyText = "b".repeat(DmContentCodec.MAX_DM_BODY_BYTES)
                val attachments =
                    (1..DmContentCodec.MAX_DM_ATTACHMENTS).map { i ->
                        DmAttachmentRef(
                            cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { i.toByte() }),
                            name = "n".repeat(DmContentCodec.MAX_ATTACHMENT_NAME_BYTES),
                            mime = "m".repeat(DmContentCodec.MAX_ATTACHMENT_MIME_BYTES),
                            size = DmContentCodec.MAX_DM_ATTACHMENT_TOTAL_BYTES / DmContentCodec.MAX_DM_ATTACHMENTS,
                            encryptionKey = ByteArray(32) { i.toByte() },
                        )
                    }
                // A genuinely max-size deposit section - DmFirstContactDeposit needs no session/
                // handshake state, so it can be built up front like body/attachments, unlike
                // DmDepositBinding (which is bound to the real X3DH ephemeral key this send()
                // generates internally, and cannot be pre-built by a test caller).
                val deposit =
                    DmFirstContactDeposit(
                        preimage = ByteArray(32) { it.toByte() },
                        paymentHash = ByteArray(32) { it.toByte() },
                        signedInvoice = "i".repeat(DmContentCodec.MAX_SIGNED_INVOICE_BYTES),
                        requiredAmountMsat = 1_000_000L,
                    )
                val content = DmContent(body = bodyText, attachments = attachments, firstContactDeposit = deposit)

                val deadline = Instant.now().plus(Duration.ofSeconds(30))
                while (received.isEmpty() && Instant.now().isBefore(deadline)) {
                    runCatching { nodeA.dmSessionManager.send(identityBPub, content) }
                    Thread.sleep(1000)
                }

                received.isEmpty() shouldBe false
                val message = received[0]
                message.sender shouldBe identityAPub
                message.content.body shouldBe bodyText
                message.content.attachments.size shouldBe DmContentCodec.MAX_DM_ATTACHMENTS
                message.content.firstContactDeposit shouldBe deposit
            } finally {
                nodeA.stop()
                nodeB.stop()
            }
        }
    })
