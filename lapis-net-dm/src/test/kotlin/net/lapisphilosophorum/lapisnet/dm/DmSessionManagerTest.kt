package net.lapisphilosophorum.lapisnet.dm

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.libp2p.core.PeerInfo
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import java.nio.file.Files
import java.time.Duration
import java.time.Instant
import java.util.Collections

/** Polls [received] until it holds at least [count] entries or [timeout] elapses -
 * bounded-polling-against-one-deadline, mirroring this codebase's established two-node-test
 * discipline (no fixed sleep for the outcome itself). */
private fun awaitAtLeast(
    received: MutableList<DmInboundMessage>,
    count: Int,
    timeout: Duration = Duration.ofSeconds(20),
): List<DmInboundMessage> {
    val deadline = Instant.now().plus(timeout)
    while (received.size < count && Instant.now().isBefore(deadline)) {
        Thread.sleep(200)
    }
    if (received.size < count) {
        error("expected at least $count inbound message(s) within $timeout, got ${received.size}")
    }
    return synchronized(received) { received.toList() }
}

/**
 * In-process (real two-node loopback, no mocking) tests of [DmSessionManager]'s state machine:
 * first-contact X3DH bootstrap, session resumption on a second send, restart resumption from
 * disk, and clean failure for an unknown recipient. [TwoNodeDmIntegrationTest] separately covers
 * the full stack byte-for-byte, driven through the real network path exactly once - this file
 * focuses on the session state machine's OWN properties across multiple sends/restarts.
 */
class DmSessionManagerTest :
    FunSpec({
        test("unknown recipient fails cleanly with DmUnknownRecipientException, never a crash or hang") {
            val node = buildDmTestNode()
            try {
                val unknown = DualKeyIdentity.generate().secp256k1KeyPair.publicKey
                shouldThrow<DmUnknownRecipientException> {
                    node.dmSessionManager.send(unknown, "hello nobody".toByteArray())
                }
            } finally {
                node.stop()
            }
        }

        test(
            "first-contact triggers a real X3DH handshake, a second send reuses the session " +
                "(no further one-time-prekey consumption), and a restarted manager resumes " +
                "from disk rather than re-handshaking",
        ) {
            val identityA = DualKeyIdentity.generate()
            val sessionDirA = Files.createTempDirectory("dm-restart-sessions")
            var nodeA = buildDmTestNode(identity = identityA, sessionStoreDirectory = sessionDirA)
            // nodeB's pool is deliberately well above DmSessionManager.PREKEY_REPLENISH_LOW_WATERMARK
            // (20) - this test asserts EXACT availableOneTimePrekeyCount() deltas after one
            // consumption, which the security-audit-round-1 self-healing replenishment
            // (DmSessionManager.replenishOneTimePrekeysIfLow) would otherwise asynchronously
            // invalidate mid-test (a default 5-prekey pool crosses that watermark on the very first
            // consumption). See buildDmTestNode's own doc comment on this parameter.
            val nodeB = buildDmTestNode(oneTimePrekeyCount = 30)
            try {
                connectAndConverge(nodeA, nodeB)

                val received = Collections.synchronizedList(mutableListOf<DmInboundMessage>())
                nodeB.dmSessionManager.addInboundListener { received.add(it) }

                val identityAPub = identityA.secp256k1KeyPair.publicKey
                val identityBPub = nodeB.identity.secp256k1KeyPair.publicKey

                // --- FIRST CONTACT: a real X3dh.initiate is triggered, proven indirectly by a
                // one-time prekey actually being consumed on B's side (the responder). ---
                val beforeFirstContact = nodeB.prekeyStore.availableOneTimePrekeyCount()
                nodeA.dmSessionManager.send(identityBPub, "first message".toByteArray())
                var messages = awaitAtLeast(received, 1)
                messages[0].sender shouldBe identityAPub
                messages[0].plaintext.decodeToString() shouldBe "first message"
                nodeB.prekeyStore.availableOneTimePrekeyCount() shouldBe (beforeFirstContact - 1)

                // --- SESSION RESUMPTION: a second send to the SAME recipient must NOT consume
                // another one-time prekey - proof it reused the existing ratchet session rather
                // than re-handshaking. ---
                nodeA.dmSessionManager.send(identityBPub, "second message".toByteArray())
                messages = awaitAtLeast(received, 2)
                messages[1].plaintext.decodeToString() shouldBe "second message"
                nodeB.prekeyStore.availableOneTimePrekeyCount() shouldBe (beforeFirstContact - 1)

                // --- RESTART RESUMPTION: stop A's node entirely, rebuild a FRESH LapisNode/
                // DmSessionManager for the SAME identity pointed at the SAME sessionStoreDirectory,
                // reconnect, and send again - must reuse the persisted session (loaded via
                // decodeWithKey), not re-handshake (again proven via the one-time-prekey count). ---
                nodeA.node.stop()
                nodeA = buildDmTestNode(identity = identityA, sessionStoreDirectory = sessionDirA)
                connectAndConverge(nodeA, nodeB)

                nodeA.dmSessionManager.send(identityBPub, "third message after restart".toByteArray())
                messages = awaitAtLeast(received, 3)
                messages[2].sender shouldBe identityAPub
                messages[2].plaintext.decodeToString() shouldBe "third message after restart"
                nodeB.prekeyStore.availableOneTimePrekeyCount() shouldBe (beforeFirstContact - 1)
            } finally {
                nodeA.stop()
                nodeB.stop()
            }
        }

        test(
            "send() checks the directory record BEFORE bootstrapping/persisting a session - a known " +
                "prekey bundle with a still-unknown directory record (PeerRecord/PrekeyBundle have " +
                "independent TTL/propagation lifecycles) never leaves a phantom session behind " +
                "(regression for a critical review finding)",
        ) {
            val nodeA = buildDmTestNode()
            // nodeB's pool is deliberately well above DmSessionManager.PREKEY_REPLENISH_LOW_WATERMARK
            // (20) - see the identical reasoning at this file's other buildDmTestNode(oneTimePrekeyCount
            // = 30) call site.
            val nodeB = buildDmTestNode(oneTimePrekeyCount = 30)
            try {
                nodeA.node.connect(PeerInfo(nodeB.node.peerId, nodeB.node.listenAddresses()))
                val identityBPub = nodeB.identity.secp256k1KeyPair.publicKey

                // B publishes ONLY its prekey bundle - deliberately never its PeerRecord - so A can
                // learn the bundle while the directory record genuinely stays unknown, exactly the
                // race this fix closes.
                val bundleOnlyDeadline = Instant.now().plus(Duration.ofSeconds(30))
                while (Instant.now().isBefore(bundleOnlyDeadline)) {
                    val bundle = nodeB.prekeyStore.publishBundle(nodeB.identity, Instant.now().epochSecond + 3600)
                    nodeB.prekeyBundleGossip.announce(bundle)
                    if (nodeA.prekeyBundleGossip.lookup(identityBPub) != null) break
                    Thread.sleep(500)
                }
                nodeA.prekeyBundleGossip.lookup(identityBPub) shouldNotBe null
                nodeA.peerDirectory.lookup(identityBPub) shouldBe null

                shouldThrow<DmUnknownRecipientException> {
                    nodeA.dmSessionManager.send(identityBPub, "must never bootstrap a phantom session".toByteArray())
                }

                // No phantom session left behind - not cached, not persisted (liveSessionForTest
                // loads from disk too if nothing is cached, see its own doc comment).
                nodeA.dmSessionManager.liveSessionForTest(identityBPub) shouldBe null

                // Once B's directory record ALSO converges, a subsequent send must still trigger a
                // REAL, fresh X3DH handshake - proven via one-time-prekey consumption - never
                // silently reusing anything left over from the failed attempt above.
                val received = Collections.synchronizedList(mutableListOf<DmInboundMessage>())
                nodeB.dmSessionManager.addInboundListener { received.add(it) }
                val beforeFirstContact = nodeB.prekeyStore.availableOneTimePrekeyCount()
                connectAndConverge(nodeA, nodeB)
                nodeA.dmSessionManager.send(identityBPub, "genuine first message".toByteArray())
                val messages = awaitAtLeast(received, 1)
                messages[0].plaintext.decodeToString() shouldBe "genuine first message"
                nodeB.prekeyStore.availableOneTimePrekeyCount() shouldBe (beforeFirstContact - 1)
            } finally {
                nodeA.stop()
                nodeB.stop()
            }
        }
    })
