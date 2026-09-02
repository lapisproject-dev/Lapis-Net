package net.lapisphilosophorum.lapisnet.dm

import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.Host
import io.libp2p.core.PeerId
import io.libp2p.core.Stream
import io.libp2p.core.multiformats.Multiaddr
import io.libp2p.core.multistream.StrictProtocolBinding
import io.libp2p.protocol.ProtocolHandler
import io.netty.buffer.Unpooled
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.EncryptionKeyBinding
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.ratchet.X3dhPreKeyMessageHeader
import java.security.SecureRandom
import java.util.Collections
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

// ---------------------------------------------------------------------------------------------
// A minimal, test-only "raw" initiator protocol on the SAME DM_PROTOCOL_ID: no codec pushed on the
// dialing side (initProtocolStream is the default no-op), so writeAndFlush(ByteBuf) puts EXACTLY
// the bytes we hand it onto the wire, with none of DmProtocol's own outbound length-prefixing.
// This is what lets these tests construct the exact malicious byte sequences each adversarial case
// needs (a fake oversized length prefix, a truncated frame, a single dribbled byte, garbage) - the
// real DmSendHandle.sendEnvelope always writes well-formed frames, so it cannot be used to attack
// its own peer.
// ---------------------------------------------------------------------------------------------

private class RawStreamController(
    val stream: Stream,
)

private class RawInitiatorProtocolHandler : ProtocolHandler<RawStreamController>(Long.MAX_VALUE, Long.MAX_VALUE) {
    override fun onStartInitiator(stream: Stream): CompletableFuture<RawStreamController> =
        CompletableFuture.completedFuture(RawStreamController(stream))
}

private class RawProtocolBinding :
    StrictProtocolBinding<RawStreamController>(DM_PROTOCOL_ID, RawInitiatorProtocolHandler())

/** Starts dialling WITHOUT blocking - callers that need to open several streams close together in
 * wall-clock time (e.g. to test a per-peer concurrent-stream cap before the read-idle timeout fires
 * on the earliest ones) should start every dial first via this function, then `.get()` each result,
 * rather than dialling one at a time through [dialRaw] (which blocks per call and can, over enough
 * sequential dials, burn most of [READ_IDLE_TIMEOUT_SECONDS] on negotiation overhead alone). */
private fun startDialRaw(
    fromHost: Host,
    toPeer: PeerId,
    addresses: List<Multiaddr>,
): CompletableFuture<Stream> {
    // Host.newStream (which ProtocolBinding.dial delegates to) resolves the OUTBOUND protocol
    // binding from the DIALING host's OWN addProtocolHandler-registered list - passing a binding
    // object only to dial() is not enough, it must also be registered locally first. Registering
    // repeatedly (once per call) is harmless - HostImpl.addProtocolHandler just appends.
    val binding = RawProtocolBinding()
    fromHost.addProtocolHandler(binding)
    val promise = binding.dial(fromHost, toPeer, *addresses.toTypedArray())
    return promise.controller.thenApply { it.stream }
}

private fun dialRaw(
    fromHost: Host,
    toPeer: PeerId,
    addresses: List<Multiaddr>,
): Stream = startDialRaw(fromHost, toPeer, addresses).get(15, TimeUnit.SECONDS)

private fun bigEndian4(value: Int): ByteArray =
    byteArrayOf((value ushr 24).toByte(), (value ushr 16).toByte(), (value ushr 8).toByte(), value.toByte())

/** `true` once [future] completes (successfully or exceptionally) within [timeoutSeconds]; `false`
 * if it is still pending at that point - never throws either way, so a caller can assert on
 * "closed" vs. "still open" without a `TimeoutException` obscuring the actual assertion. */
private fun completesWithin(
    future: CompletableFuture<*>,
    timeoutSeconds: Long,
): Boolean =
    try {
        future.get(timeoutSeconds, TimeUnit.SECONDS)
        true
    } catch (e: TimeoutException) {
        false
    } catch (e: java.util.concurrent.ExecutionException) {
        true // completed exceptionally (e.g. a reset) still counts as "closed"
    }

private fun buildRawNode(): LapisNode {
    val node = LapisNode.create(DualKeyIdentity.generate())
    node.start(bootstrapPeers = emptyList())
    return node
}

/**
 * The mandatory, central security spec of this wave: [DmProtocolHandler] is the FIRST place in this
 * codebase parsing untrusted bytes off a raw libp2p stream with no GossipSub size ceiling
 * backstopping it. Every case below drives either a REAL raw stream against a REAL
 * [DmProtocolHandler] (cases a-d, f), or [DmSessionManager.handleInboundEnvelope] directly with a
 * hand-forged envelope (cases e, g, and f's direct-call variant) - never mocks.
 */
class DmStreamAbuseTest :
    FunSpec({
        test("(a) an oversized declared frame length is rejected BEFORE any allocation proportional to it") {
            val victim = buildRawNode()
            val attacker = buildRawNode()
            val received = Collections.synchronizedList(mutableListOf<ByteArray>())
            DmProtocol.attachToHost(victim.host) { _, bytes -> received.add(bytes) }
            try {
                val stream = dialRaw(attacker.host, victim.host.peerId, victim.listenAddresses())
                // Declares ~1GB, only 10 actual bytes follow - the exact malicious-length-style
                // payload this codebase's CID-length-OOM history demands checking for.
                val malicious = bigEndian4(1_000_000_000) + ByteArray(10)
                val start = System.nanoTime()
                stream.writeAndFlush(Unpooled.wrappedBuffer(malicious))

                val closed = completesWithin(stream.closeFuture(), 10)
                val elapsedMs = (System.nanoTime() - start) / 1_000_000

                closed shouldBe true
                (elapsedMs < 10_000).shouldBe(true)
                received.isEmpty() shouldBe true
            } finally {
                attacker.stop()
                victim.stop()
            }
        }

        test("(b) a truncated frame - stream closed mid-frame - is rejected cleanly, never hangs or crashes") {
            val victim = buildRawNode()
            val attacker = buildRawNode()
            val received = Collections.synchronizedList(mutableListOf<ByteArray>())
            DmProtocol.attachToHost(victim.host) { _, bytes -> received.add(bytes) }
            try {
                val stream = dialRaw(attacker.host, victim.host.peerId, victim.listenAddresses())
                // Declares 1000 bytes, writes only 10, then closes - a valid length prefix, an
                // incomplete body, stream torn down mid-frame.
                val truncated = bigEndian4(1000) + ByteArray(10) { it.toByte() }
                stream.writeAndFlush(Unpooled.wrappedBuffer(truncated))
                stream.close()

                // Must close within well under the absolute MAX_STREAM_LIFETIME_SECONDS budget -
                // not left hanging forever.
                completesWithin(stream.closeFuture(), 25) shouldBe true
                received.isEmpty() shouldBe true
            } finally {
                attacker.stop()
                victim.stop()
            }
        }

        test(
            "(c) slowloris - one byte then silence - is force-closed within the read-idle timeout, " +
                "not left open forever",
        ) {
            val victim = buildRawNode()
            val attacker = buildRawNode()
            DmProtocol.attachToHost(victim.host) { _, _ -> }
            try {
                val stream = dialRaw(attacker.host, victim.host.peerId, victim.listenAddresses())
                stream.writeAndFlush(Unpooled.wrappedBuffer(byteArrayOf(0)))
                // No further writes at all - classic slowloris. ReadTimeoutHandler's own window is
                // 10s; give generous headroom.
                completesWithin(stream.closeFuture(), 20) shouldBe true
            } finally {
                attacker.stop()
                victim.stop()
            }
        }

        test(
            "(c2) a slow-drip stream (one byte just often enough to dodge the read-idle timeout) is " +
                "still force-closed by the ABSOLUTE stream lifetime deadline - the defense beyond a " +
                "literal reading of the slowloris case, since ReadTimeoutHandler alone resets on ANY " +
                "read, however small",
        ) {
            val victim = buildRawNode()
            val attacker = buildRawNode()
            DmProtocol.attachToHost(victim.host) { _, _ -> }
            try {
                val stream = dialRaw(attacker.host, victim.host.peerId, victim.listenAddresses())
                // Drip one byte every 8s (< the 10s read-idle window, so ReadTimeoutHandler never
                // fires) for up to 3 rounds (24s total) - the absolute MAX_STREAM_LIFETIME_SECONDS
                // (20s) budget must still force closure before this loop naturally exhausts.
                var closed = false
                repeat(3) {
                    if (completesWithin(stream.closeFuture(), 8)) {
                        closed = true
                        return@repeat
                    }
                    if (!closed) stream.writeAndFlush(Unpooled.wrappedBuffer(byteArrayOf(0)))
                }
                closed shouldBe true
            } finally {
                attacker.stop()
                victim.stop()
            }
        }

        test("(d) an unsolicited-stream flood from one peer is capped, without affecting a different peer") {
            val victim = buildRawNode()
            val attacker1 = buildRawNode()
            val attacker2 = buildRawNode()
            DmProtocol.attachToHost(victim.host) { _, _ -> }
            try {
                // Start ALL dials back-to-back (non-blocking), THEN await every result - dialling
                // one at a time and blocking per call can, over 9 sequential negotiations, burn
                // enough wall-clock time that the EARLIEST streams' idle-read window
                // (READ_IDLE_TIMEOUT_SECONDS, 10s - these streams never exchange any application
                // data at all) starts to expire before this test ever gets to check them, which has
                // nothing to do with the per-peer cap this test actually means to exercise.
                val pendingStreams =
                    (1..(MAX_CONCURRENT_STREAMS_PER_PEER + 1)).map {
                        startDialRaw(attacker1.host, victim.host.peerId, victim.listenAddresses())
                    }
                val streams = pendingStreams.map { it.get(15, TimeUnit.SECONDS) }
                // A SINGLE short wait, THEN check every closeFuture's `isDone` at once (never one
                // `completesWithin(..., timeout)` blocking wait PER stream in sequence) - none of
                // these 9 streams ever exchange any application data, so EVERY one of them is
                // equally subject to READ_IDLE_TIMEOUT_SECONDS (10s) counted from ITS OWN dial time;
                // checking them one at a time with a multi-second blocking wait each would itself
                // burn enough cumulative wall-clock time to run every remaining stream's timer out
                // before this loop even reaches them - a self-inflicted false failure with nothing
                // to do with the per-peer cap this test means to exercise.
                Thread.sleep(2000)
                // Asserting on the aggregate COUNT, not a specific stream index (e.g. "exactly the
                // last one") - our own local onStartInitiator completion (what the dial above waits
                // on) and the responder's own onStartResponder are two independent async callbacks
                // not strictly guaranteed to complete in dial order under concurrency.
                val closedCount = streams.count { it.closeFuture().isDone }
                // Exactly ONE of the MAX_CONCURRENT_STREAMS_PER_PEER + 1 streams is rejected/reset -
                // the cap is enforced, and enforced exactly at its documented boundary.
                closedCount shouldBe 1

                // A DIFFERENT peer can still open its own stream fine - the cap is per-peer, not global.
                val otherStream = dialRaw(attacker2.host, victim.host.peerId, victim.listenAddresses())
                completesWithin(otherStream.closeFuture(), 2) shouldBe false
                otherStream.reset()

                streams.forEach { s -> runCatching { s.reset() } }
            } finally {
                attacker1.stop()
                attacker2.stop()
                victim.stop()
            }
        }

        test(
            "(f) garbage bytes over a REAL raw stream, through the REAL production DmSessionManager " +
                "wiring, never crash the node or leave it wedged - a well-FRAMED but content-garbage " +
                "frame is handed off (framing is DmProtocolHandler's job; rejecting the CONTENT is " +
                "DmSessionManager.handleInboundEnvelope's, see case (f2)), and the node stays fully " +
                "responsive to a legitimate follow-up dial from the SAME peer immediately after",
        ) {
            // A real DmTestNode (not attachToHost's bare callback) so this drives the ACTUAL
            // production wiring end to end: DmProtocolHandler -> DmSessionManager.handleInboundEnvelope.
            val victim = buildDmTestNode()
            val attacker = buildRawNode()
            try {
                val random = SecureRandom()
                val garbageBody = ByteArray(300).also(random::nextBytes)
                val stream = dialRaw(attacker.host, victim.node.host.peerId, victim.node.listenAddresses())
                // No exception escapes this call, whatever DmSessionManager does internally with the
                // garbage content - the whole point of this case.
                shouldNotThrowAny {
                    stream.writeAndFlush(Unpooled.wrappedBuffer(bigEndian4(garbageBody.size) + garbageBody))
                }

                // Liveness proof: the node is NOT wedged by the garbage frame - a fresh, legitimate
                // dial from the SAME peer succeeds promptly right afterward. (A plain graceful
                // Stream.close() - what the responder calls after processing any one-shot frame,
                // garbage or not - does not reliably propagate to the INITIATOR's own closeFuture()
                // within a short window the way Stream.reset() does in cases (a)/(c)/(d), so this
                // liveness check is the robust signal here, not a closeFuture() wait.)
                val secondStream = dialRaw(attacker.host, victim.node.host.peerId, victim.node.listenAddresses())
                secondStream.writeAndFlush(Unpooled.wrappedBuffer(bigEndian4(4) + byteArrayOf(1, 2, 3, 4)))
            } finally {
                attacker.stop()
                victim.stop()
            }
        }

        test("(f2) garbage bytes fed directly to handleInboundEnvelope never throw - the full handler round trip") {
            val victim = buildDmTestNode()
            try {
                val random = SecureRandom()
                repeat(20) {
                    val garbage = ByteArray(100 + random.nextInt(400)).also(random::nextBytes)
                    shouldNotThrowAny {
                        victim.dmSessionManager.handleInboundEnvelope(victim.node.peerId, garbage)
                    }
                }
            } finally {
                victim.stop()
            }
        }

        test(
            "(e) a DmEnvelope claiming senderIdentity X, but whose ratchet bytes actually decrypt " +
                "under an unrelated session Y, is rejected - the claimed field alone is never trusted",
        ) {
            val nodeX = buildDmTestNode()
            val nodeY = buildDmTestNode()
            val victim = buildDmTestNode()
            try {
                connectAndConverge(nodeX, victim)
                connectAndConverge(nodeY, victim)

                val identityX = nodeX.identity.secp256k1KeyPair.publicKey
                val identityY = nodeY.identity.secp256k1KeyPair.publicKey
                val identityVictim = victim.identity.secp256k1KeyPair.publicKey

                val received = Collections.synchronizedList(mutableListOf<DmInboundMessage>())
                victim.dmSessionManager.addInboundListener { received.add(it) }

                // Establish two REAL, independent sessions on the victim: one with X, one with Y.
                sendAndAwait(nodeX, victim, identityVictim, received, "hello from X")
                sendAndAwait(nodeY, victim, identityVictim, received, "hello from Y")

                // Y's OWN live sending session encrypts a genuine message - this ciphertext is only
                // decryptable under victim's session(victim, Y).
                val ySendingSession = requireNotNull(nodeY.dmSessionManager.liveSessionForTest(identityVictim))
                val forgedRatchetMessage = ySendingSession.encrypt("forged as if from X".toByteArray())

                // Wrap it in an envelope claiming senderIdentity = X.
                val forgedEnvelope = DmEnvelope(DmMessageType.TEXT, identityX, null, forgedRatchetMessage)
                val forgedBytes = DmEnvelopeCodec.encode(forgedEnvelope)

                val beforeCount = received.size
                victim.dmSessionManager.handleInboundEnvelope(nodeX.node.peerId, forgedBytes)

                // Never delivered.
                received.size shouldBe beforeCount

                // Session X's state is UNCHANGED by the rejected attempt - DoubleRatchetSession only
                // commits state after the AEAD tag verifies, and it never did here. Proven
                // BEHAVIOURALLY (this module's test sources cannot reach `DoubleRatchetSession`'s
                // `internal` message-counter accessors, which belong to a different Gradle module):
                // a genuinely NEXT message from X must still decrypt correctly - if the forged
                // attempt had incorrectly advanced X's receive position, this legitimate follow-up
                // would now be spuriously rejected as "already consumed".
                sendAndAwait(nodeX, victim, identityVictim, received, "genuinely the next message from X")

                // Session Y (the one that ACTUALLY produced the forged ciphertext) was never even
                // consulted by the victim for that call either - its own next legitimate message
                // still decrypts fine too.
                sendAndAwait(nodeY, victim, identityVictim, received, "genuinely the next message from Y")
            } finally {
                nodeX.stop()
                nodeY.stop()
                victim.stop()
            }
        }

        test(
            "(g) a message correctly decrypting under session A is rejected if replayed verbatim on " +
                "an unrelated session B (a different peer pair's session entirely)",
        ) {
            val nodeX = buildDmTestNode()
            val victim1 = buildDmTestNode()
            val victim2 = buildDmTestNode()
            try {
                connectAndConverge(nodeX, victim1)
                connectAndConverge(nodeX, victim2)

                val identityX = nodeX.identity.secp256k1KeyPair.publicKey
                val identityVictim1 = victim1.identity.secp256k1KeyPair.publicKey
                val identityVictim2 = victim2.identity.secp256k1KeyPair.publicKey

                val received1 = Collections.synchronizedList(mutableListOf<DmInboundMessage>())
                val received2 = Collections.synchronizedList(mutableListOf<DmInboundMessage>())
                victim1.dmSessionManager.addInboundListener { received1.add(it) }
                victim2.dmSessionManager.addInboundListener { received2.add(it) }

                // Two INDEPENDENT real X3DH handshakes/sessions: X<->victim1 and X<->victim2 - the
                // associated data differs (different responder identity), so the two sessions'
                // derived keys are entirely unrelated even though the same X initiated both.
                sendAndAwait(nodeX, victim1, identityVictim1, received1, "hello victim1")
                sendAndAwait(nodeX, victim2, identityVictim2, received2, "hello victim2")

                // X's own live session-to-victim1 encrypts one more, genuine message.
                val sessionXtoVictim1 = requireNotNull(nodeX.dmSessionManager.liveSessionForTest(identityVictim1))
                val genuineMessage =
                    sessionXtoVictim1.encrypt(DmContentCodec.encode(DmContent(body = "only for victim1")))
                val genuineEnvelope = DmEnvelope(DmMessageType.TEXT, identityX, null, genuineMessage)
                val genuineBytes = DmEnvelopeCodec.encode(genuineEnvelope)

                // Delivering it to victim1 (session A, the one it was actually encrypted for) succeeds.
                val before1 = received1.size
                victim1.dmSessionManager.handleInboundEnvelope(nodeX.node.peerId, genuineBytes)
                awaitAtLeastCount(received1, before1 + 1)
                received1.last().content.body shouldBe "only for victim1"

                // Replaying the EXACT SAME bytes against victim2's UNRELATED session (session B) is
                // rejected - it is never accepted, and never misattributed as a message from X to
                // victim2 either.
                val before2 = received2.size
                victim2.dmSessionManager.handleInboundEnvelope(nodeX.node.peerId, genuineBytes)
                Thread.sleep(500) // no positive event to await; give the (non-)delivery a moment
                received2.size shouldBe before2
            } finally {
                nodeX.stop()
                victim1.stop()
                victim2.stop()
            }
        }

        test(
            "(h) an X3DH_INITIAL envelope with a GARBAGE encryption-key-binding signature - no real " +
                "private key material at all - never consumes the one-time prekey it names (regression: " +
                "the attacker previously needed zero cryptographic material to durably burn through a " +
                "victim's whole one-time-prekey pool, since consumeOneTimePrekey ran BEFORE " +
                "EncryptionKeyBinding.verify)",
        ) {
            val victim = buildDmTestNode()
            try {
                val random = SecureRandom()
                val attackerClaimedIdentity = DualKeyIdentity.generate().secp256k1KeyPair.publicKey
                // A structurally-valid EncryptionKeyBinding - EncryptionKeyBinding's own constructor
                // only enforces a 64-byte signature SIZE, never a cryptographic check - over a
                // freshly-generated X25519 key, with a signature that is just random bytes, never
                // actually produced by attackerClaimedIdentity's (nonexistent) private key.
                val garbageBinding =
                    EncryptionKeyBinding(
                        X25519KeyPair.generate(random).publicKey,
                        ByteArray(64).also(random::nextBytes),
                    )
                val targetOneTimePrekeyId =
                    victim.prekeyStore.availableOneTimePrekeyIds().first()
                val forgedHeader =
                    X3dhPreKeyMessageHeader(
                        initiatorIdentity = attackerClaimedIdentity,
                        initiatorEncryptionBinding = garbageBinding,
                        ephemeralPublicKey = X25519KeyPair.generate(random).publicKey,
                        signedPrekeyId = victim.prekeyStore.signedPrekeyId,
                        oneTimePrekeyId = targetOneTimePrekeyId,
                    )
                val forgedEnvelope =
                    DmEnvelope(
                        DmMessageType.X3DH_INITIAL,
                        attackerClaimedIdentity,
                        forgedHeader,
                        dmSampleRatchetMessage(),
                    )
                val forgedBytes = DmEnvelopeCodec.encode(forgedEnvelope)

                val beforeCount = victim.prekeyStore.availableOneTimePrekeyCount()
                repeat(10) {
                    // Repeated to make sure this isn't a one-off - a real attack would send ~100 of
                    // these naming sequential ids; ten with the SAME id proves the fix rejects every
                    // single attempt, not merely the first.
                    victim.dmSessionManager.handleInboundEnvelope(victim.node.peerId, forgedBytes)
                }

                victim.prekeyStore.availableOneTimePrekeyCount() shouldBe beforeCount
                (targetOneTimePrekeyId in victim.prekeyStore.availableOneTimePrekeyIds()) shouldBe true
            } finally {
                victim.stop()
            }
        }

        test(
            "(h2) an X3DH_INITIAL envelope with a VALID, cryptographically genuine self-signed " +
                "encryption-key binding for a FRESHLY MINTED throwaway identity - no relationship to " +
                "the victim at all, but not garbage like case (h) - still durably consumes the named " +
                "one-time prekey (EncryptionKeyBinding.verify legitimately passes; this is NOT a bug " +
                "case (h)'s gate can or should catch), but the pool is rate-limited against a flood " +
                "and self-heals afterward rather than staying permanently drained (security audit " +
                "round 1 finding, 2026-08-11, PROVEN with an executable probe: five throwaway " +
                "self-signed identities burned a five-entry pool to zero in 2.9s)",
        ) {
            val victim = buildDmTestNode()
            try {
                val random = SecureRandom()
                val initialCount = victim.prekeyStore.availableOneTimePrekeyCount()
                val availableIds = victim.prekeyStore.availableOneTimePrekeyIds()

                availableIds.forEach { targetId ->
                    val attackerIdentity = DualKeyIdentity.generate()
                    val attackerX25519 = X25519KeyPair.generate(random)
                    // A REAL, self-signed EncryptionKeyBinding - cryptographically genuine, unlike
                    // case (h)'s random-bytes "signature". Costs the attacker one local secp256k1
                    // keygen plus one ECDSA sign - no key material shared with the victim at all.
                    val genuineBinding =
                        EncryptionKeyBinding.create(attackerIdentity.secp256k1KeyPair, attackerX25519.publicKey)
                    val forgedHeader =
                        X3dhPreKeyMessageHeader(
                            initiatorIdentity = attackerIdentity.secp256k1KeyPair.publicKey,
                            initiatorEncryptionBinding = genuineBinding,
                            ephemeralPublicKey = X25519KeyPair.generate(random).publicKey,
                            signedPrekeyId = victim.prekeyStore.signedPrekeyId,
                            oneTimePrekeyId = targetId,
                        )
                    val forgedEnvelope =
                        DmEnvelope(
                            DmMessageType.X3DH_INITIAL,
                            attackerIdentity.secp256k1KeyPair.publicKey,
                            forgedHeader,
                            dmSampleRatchetMessage(),
                        )
                    val forgedBytes = DmEnvelopeCodec.encode(forgedEnvelope)
                    victim.dmSessionManager.handleInboundEnvelope(victim.node.peerId, forgedBytes)
                }

                // Every named id really WAS consumed - this is expected, not a regression. Case (h)'s
                // garbage-signature gate cannot and must not reject a genuinely self-signed binding;
                // rejecting it would break EVERY legitimate first-contact handshake too, since a real
                // initiator's binding looks identical to this attacker's at this layer.
                availableIds.forEach { id ->
                    (id in victim.prekeyStore.availableOneTimePrekeyIds()) shouldBe false
                }

                // Self-healing: DmSessionManager.replenishOneTimePrekeysIfLow, triggered internally
                // after each successful consumeOneTimePrekey once the pool crosses its low watermark,
                // tops the pool back up on a background executor thread - poll rather than
                // sleep-then-assert since that top-up does not run inline with handleInboundEnvelope.
                val deadline = System.currentTimeMillis() + 20_000
                while (victim.prekeyStore.availableOneTimePrekeyCount() <= initialCount &&
                    System.currentTimeMillis() < deadline
                ) {
                    Thread.sleep(200)
                }
                (victim.prekeyStore.availableOneTimePrekeyCount() > initialCount) shouldBe true
            } finally {
                victim.stop()
            }
        }

        test(
            "(i) DmProtocolHandler.perPeerStreamCounts is decremented exactly ONCE per completed stream, " +
                "even though jvm-libp2p separately invokes onClosed for a stream DmInboundMessageHandler's " +
                "own onMessage-finally already finished - a peer's genuinely-still-open SECOND stream must " +
                "never have its tracking corrupted by a FIRST, already-completed stream's later, " +
                "asynchronous channel-teardown callback (regression: onFinished used to run twice per " +
                "completed stream, silently under-counting a peer holding multiple concurrent streams)",
        ) {
            val victim = buildRawNode()
            val attacker = buildRawNode()
            val dmProtocol = DmProtocol.attachToHost(victim.host) { _, _ -> }
            try {
                val peer = attacker.host.peerId

                // S1: a well-FRAMED, content-garbage one-shot frame - triggers a REAL onMessage call
                // on the victim side, whose `finally` block synchronously decrements
                // perPeerStreamCounts to 0 (removing the entry), independent of whether the
                // underlying Netty channel has actually finished tearing down yet.
                val s1 = dialRaw(attacker.host, victim.host.peerId, victim.listenAddresses())
                s1.writeAndFlush(Unpooled.wrappedBuffer(bigEndian4(4) + byteArrayOf(1, 2, 3, 4)))
                val afterS1Deadline = System.currentTimeMillis() + 10_000
                while (dmProtocol.streamCountForTest(peer) != 0 && System.currentTimeMillis() < afterS1Deadline) {
                    Thread.sleep(50)
                }
                dmProtocol.streamCountForTest(peer) shouldBe 0

                // S2: opened AFTER S1 already finished (map entry removed) - held open, NO data ever
                // sent on it, so it can never trigger its own onMessage/onFinished. A genuinely
                // concurrent second stream from the same peer.
                val s2 = dialRaw(attacker.host, victim.host.peerId, victim.listenAddresses())
                val afterS2Deadline = System.currentTimeMillis() + 10_000
                while (dmProtocol.streamCountForTest(peer) != 1 && System.currentTimeMillis() < afterS2Deadline) {
                    Thread.sleep(50)
                }
                dmProtocol.streamCountForTest(peer) shouldBe 1

                // Give S1's delayed, asynchronous channelUnregistered -> onClosed callback plenty of
                // time to fire. Before the fix, this stale second onFinished() call would erroneously
                // decrement/remove S2's CURRENT tracked entry, even though S2 is still genuinely open.
                Thread.sleep(3000)
                dmProtocol.streamCountForTest(peer) shouldBe 1

                s2.reset()
            } finally {
                attacker.stop()
                victim.stop()
            }
        }

        test(
            "(j) an attacker who harvests a legitimate correspondent's REAL, publicly-gossiped " +
                "EncryptionKeyBinding (PrekeyBundle.encryptionBinding, broadcast by PrekeyBundleGossip - " +
                "no secret material, anyone can read it) and replays it in a forged X3DH_INITIAL claiming " +
                "to BE that correspondent is still rejected - the harvested binding alone lets the forged " +
                "header pass EncryptionKeyBinding.verify (it really IS a valid signature by the " +
                "correspondent's identity), but the attacker never held the correspondent's X25519 IDENTITY " +
                "PRIVATE key (only its PUBLIC half is ever gossiped), so the resulting X3DH shared secret " +
                "the victim derives can never match what any ratchet message the attacker can actually " +
                "produce would decrypt under - follow-up hardening item 6 (2026-08-11), a permanent " +
                "regression test for a security-audit ad-hoc probe that was never committed. The victim's " +
                "REAL, already-established session with the genuine correspondent is unaffected: this " +
                "forged attempt claims the SAME identity (same withPeerLock stripe, same liveSessionCache " +
                "slot) but X3DH_INITIAL always bootstraps a BRAND-NEW session object first and only " +
                "persists/caches it AFTER a successful decrypt (see handleInboundEnvelope's own doc " +
                "comment) - since decrypt never succeeds here, the genuine cached session for the " +
                "correspondent is never even touched, let alone overwritten.",
        ) {
            val victim = buildDmTestNode()
            val correspondent = buildDmTestNode()
            try {
                connectAndConverge(correspondent, victim)

                val identityCorrespondent = correspondent.identity.secp256k1KeyPair.publicKey
                val identityVictim = victim.identity.secp256k1KeyPair.publicKey

                val received = Collections.synchronizedList(mutableListOf<DmInboundMessage>())
                victim.dmSessionManager.addInboundListener { received.add(it) }

                // A REAL, X3DH-bootstrapped session between the correspondent and the victim - the
                // genuine session this forged attempt must not disturb.
                sendAndAwait(correspondent, victim, identityVictim, received, "hello from the real correspondent")

                // Harvest the correspondent's REAL, currently-published EncryptionKeyBinding exactly the
                // way any peer on the network legitimately can - a plain PrekeyBundleGossip lookup, no
                // secret material involved, mirroring PrekeyBundle.x25519IdentityKey's own "read-through
                // alias" doc comment on what this field actually is: public.
                val harvestedBinding =
                    requireNotNull(victim.prekeyBundleGossip.lookup(identityCorrespondent)) {
                        "connectAndConverge should have made the correspondent's bundle visible to the victim"
                    }.encryptionBinding

                // Forge an X3DH_INITIAL claiming senderIdentity = the CORRESPONDENT (impersonation, not
                // just an unrelated throwaway identity like cases (h)/(h2)), reusing the harvested REAL
                // binding - it verifies fine, since it really was signed by the correspondent's identity
                // key. The ephemeral key is the attacker's own fresh one (X3DH ephemerals are per-message
                // and never gossiped, so there is nothing of the correspondent's to harvest there) - the
                // attacker has no way to supply the correspondent's real X25519 IDENTITY private key,
                // only its binding's public half, so X3dh.initiate() itself cannot be used here at all
                // (it hard-checks the supplied private key matches the binding's public key) - this
                // forged header is hand-constructed directly, exactly like cases (h)/(h2).
                val random = SecureRandom()
                val targetOneTimePrekeyId = victim.prekeyStore.availableOneTimePrekeyIds().first()
                val forgedHeader =
                    X3dhPreKeyMessageHeader(
                        initiatorIdentity = identityCorrespondent,
                        initiatorEncryptionBinding = harvestedBinding,
                        ephemeralPublicKey = X25519KeyPair.generate(random).publicKey,
                        signedPrekeyId = victim.prekeyStore.signedPrekeyId,
                        oneTimePrekeyId = targetOneTimePrekeyId,
                    )
                // The attacker cannot produce a ratchet message that actually decrypts under the real
                // shared secret the victim will derive (that would require the correspondent's real
                // X25519 identity private key) - any structurally-valid ratchet message stands in for
                // "the best an attacker without that key can do", mirroring cases (h)/(h2)'s identical
                // use of dmSampleRatchetMessage() for the same reason.
                val forgedEnvelope =
                    DmEnvelope(
                        DmMessageType.X3DH_INITIAL,
                        identityCorrespondent,
                        forgedHeader,
                        dmSampleRatchetMessage(),
                    )
                val forgedBytes = DmEnvelopeCodec.encode(forgedEnvelope)

                val beforeCount = received.size
                victim.dmSessionManager.handleInboundEnvelope(victim.node.peerId, forgedBytes)

                // Never delivered - decrypt fails, the claimed identity is never trusted on its own.
                received.size shouldBe beforeCount

                // The victim's REAL session with the genuine correspondent is unaffected: a genuinely
                // NEXT message from the correspondent still decrypts fine, proving the rejected forged
                // attempt never touched (let alone overwrote) the real cached/persisted session state.
                sendAndAwait(
                    correspondent,
                    victim,
                    identityVictim,
                    received,
                    "genuinely the next message from the real correspondent",
                )
            } finally {
                correspondent.stop()
                victim.stop()
            }
        }
    })

/** Sends [plaintext] from [from] to [recipientIdentity] (== [to]'s identity) and polls [received]
 * until it grows by at least one entry - shared by cases (e)/(g), which both need to bootstrap a
 * REAL session before forging an adversarial envelope on top of it.
 *
 * Retries the WHOLE `send()` call (not just the polling assertion) on the same generously-timed
 * bounded-polling discipline as [TwoNodeDmIntegrationTest]'s own `send()` retry loop - mirrors that
 * test's doc comment on why: a raw stream-protocol handshake over a REAL two-node libp2p transport
 * has more moving parts than a bare gossip publish, and this codebase has already observed a
 * `SemiDuplexNoOutboundStreamException`-class timing flake in exactly this shape of test. Each retry
 * legitimately produces a fresh envelope over the SAME session after the first attempt (or a fresh
 * X3DH_INITIAL if the first attempt never got far enough to persist a session at all). */
private fun sendAndAwait(
    from: DmTestNode,
    to: DmTestNode,
    recipientIdentity: net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey,
    received: MutableList<DmInboundMessage>,
    plaintext: String,
    timeoutSeconds: Long = 20,
) {
    val before = received.size
    val deadline = System.currentTimeMillis() + timeoutSeconds * 1000
    while (received.size <= before && System.currentTimeMillis() < deadline) {
        runCatching { from.dmSessionManager.send(recipientIdentity, DmContent(body = plaintext)) }
        Thread.sleep(1000)
    }
    if (received.size <= before) error("expected at least ${before + 1} inbound message(s), got ${received.size}")
}

private fun awaitAtLeastCount(
    received: MutableList<DmInboundMessage>,
    count: Int,
    timeoutSeconds: Long = 20,
) {
    val deadline = System.currentTimeMillis() + timeoutSeconds * 1000
    while (received.size < count && System.currentTimeMillis() < deadline) {
        Thread.sleep(200)
    }
    if (received.size < count) error("expected at least $count inbound message(s), got ${received.size}")
}
