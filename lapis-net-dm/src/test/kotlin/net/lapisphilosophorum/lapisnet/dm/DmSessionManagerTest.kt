package net.lapisphilosophorum.lapisnet.dm

import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.libp2p.core.PeerInfo
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.EncryptionKeyBinding
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.ratchet.DoubleRatchetSession
import net.lapisphilosophorum.lapisnet.ratchet.X3dh
import java.nio.file.Files
import java.nio.file.Path
import java.security.SecureRandom
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

/** Mirrors [DmSessionManager]'s own private `sessionFilePath` exactly (hex-encoded peer public key
 * bytes + `.lndm`, resolved against the manager's `sessionStoreDirectory`) - this test module has no
 * access to that private function, so tests that need to plant/tamper a persisted session file on
 * disk BEFORE (or independently of) any real [DmSessionManager] call recompute the same path here. */
private fun sessionFilePathForTest(
    sessionStoreDirectory: Path,
    peer: Secp256k1PublicKey,
): Path {
    val hex = peer.bytes.joinToString("") { "%02x".format(it) }
    return sessionStoreDirectory.resolve("$hex.lndm")
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

        test(
            "a second, genuine X3DH_INITIAL from a peer that already has a live cached session " +
                "installs a brand-new session AND destroys the superseded one's key material - " +
                "regression for follow-up hardening item 1 (2026-08-11): putCached previously " +
                "overwrote liveSessionCache with a plain map assignment, never calling " +
                "DoubleRatchetSession.destroy on the value it replaced, so a re-handshaking peer's " +
                "old ratchet/root/chain key material was left un-zeroed on the heap until GC. " +
                "Mutation-tested: reverting putCached to that plain assignment leaves this test " +
                "failing on the final canSend/encrypt assertions below.",
        ) {
            val correspondent = buildDmTestNode()
            // victim's pool is comfortably above PREKEY_REPLENISH_LOW_WATERMARK (20) - two
            // handshakes each consume one one-time prekey, and this test does not assert an exact
            // remaining count, but a pool this small would otherwise risk the self-healing
            // replenishment racing the second handshake below.
            val victim = buildDmTestNode(oneTimePrekeyCount = 30)
            try {
                connectAndConverge(correspondent, victim)

                val identityCorrespondent = correspondent.identity.secp256k1KeyPair.publicKey
                val identityVictim = victim.identity.secp256k1KeyPair.publicKey

                val received = Collections.synchronizedList(mutableListOf<DmInboundMessage>())
                victim.dmSessionManager.addInboundListener { received.add(it) }

                // A REAL first session, bootstrapped the normal way via send()'s own X3DH_INITIAL path.
                correspondent.dmSessionManager.send(identityVictim, "first contact".toByteArray())
                val firstMessages = awaitAtLeast(received, 1)
                firstMessages[0].plaintext.decodeToString() shouldBe "first contact"

                val oldSession = requireNotNull(victim.dmSessionManager.liveSessionForTest(identityCorrespondent))
                oldSession.canSend shouldBe true

                // Simulate the correspondent having lost its local session state (e.g. reinstalled)
                // and genuinely re-initiating X3DH for the SAME identity - exactly the scenario
                // putCached's own doc comment describes. Built by hand, mirroring
                // DmSessionManager.send()'s own first-contact code path exactly (X3dh.initiate
                // against the victim's real, currently-published PrekeyBundle) - calling
                // correspondent.dmSessionManager.send() again would just reuse ITS OWN already
                // cached/persisted session rather than re-handshaking.
                val victimBundle = requireNotNull(correspondent.prekeyBundleGossip.lookup(identityVictim))
                val ownBinding =
                    EncryptionKeyBinding.create(
                        correspondent.identity.secp256k1KeyPair,
                        correspondent.prekeyStore.x25519IdentityPublicKey,
                    )
                val ownX25519Private = correspondent.prekeyStore.x25519IdentityPrivateKey()
                val initiation =
                    try {
                        X3dh.initiate(
                            initiatorIdentity = identityCorrespondent,
                            initiatorEncryptionBinding = ownBinding,
                            initiatorX25519IdentityPrivateKey = ownX25519Private,
                            bundle = victimBundle,
                            random = SecureRandom(),
                        )
                    } finally {
                        ownX25519Private.destroy()
                    }
                val newSendingSession =
                    DoubleRatchetSession.initializeSender(initiation.session, victimBundle.signedPrekey, SecureRandom())
                initiation.session.destroy()
                val ratchetMessage = newSendingSession.encrypt("second, fresh handshake".toByteArray())
                val secondEnvelope =
                    DmEnvelope(DmMessageType.X3DH_INITIAL, identityCorrespondent, initiation.header, ratchetMessage)
                val secondBytes = DmEnvelopeCodec.encode(secondEnvelope)

                victim.dmSessionManager.handleInboundEnvelope(victim.node.peerId, secondBytes)
                val secondMessages = awaitAtLeast(received, 2)
                secondMessages[1].plaintext.decodeToString() shouldBe "second, fresh handshake"

                // The OLD session object is destroyed, not merely dropped from the cache - proven
                // behaviourally (this module's test sources cannot reach DoubleRatchetSession's
                // internal key fields): canSend flips to false, and a further encrypt() attempt on
                // it throws the destroyed-session IllegalStateException rather than silently
                // succeeding on live key material that should have been zeroed.
                oldSession.canSend shouldBe false
                shouldThrow<IllegalStateException> {
                    oldSession.encrypt("must never succeed - this session is superseded".toByteArray())
                }

                // A genuinely NEW session object now occupies the cache slot for this peer.
                val currentSession = requireNotNull(victim.dmSessionManager.liveSessionForTest(identityCorrespondent))
                (currentSession === oldSession) shouldBe false
            } finally {
                correspondent.stop()
                victim.stop()
            }
        }

        test(
            "loadPersisted treats a STRUCTURALLY CORRUPT session file as absent - a fresh, genuine " +
                "X3DH handshake bootstraps a brand-new session on the very next send() instead of the " +
                "corrupt bytes crashing or hanging the caller (regression for follow-up hardening " +
                "item 2, 2026-08-11 - the second, corrupt/undecryptable-file half of that item)",
        ) {
            val identityA = DualKeyIdentity.generate()
            val sessionDirA = Files.createTempDirectory("dm-corrupt-session")
            val nodeA = buildDmTestNode(identity = identityA, sessionStoreDirectory = sessionDirA)
            // nodeB's pool is comfortably above PREKEY_REPLENISH_LOW_WATERMARK - see this file's
            // other buildDmTestNode(oneTimePrekeyCount = 30) call sites for the identical reasoning.
            val nodeB = buildDmTestNode(oneTimePrekeyCount = 30)
            try {
                connectAndConverge(nodeA, nodeB)
                val identityBPub = nodeB.identity.secp256k1KeyPair.publicKey

                // A session file for B that is pure garbage - wrong magic, wrong length, structurally
                // impossible to be a valid v1 session - planted BEFORE any real session for B has
                // ever existed on A's side (no prior send()/handleInboundEnvelope call for B at all).
                val corruptFile = sessionFilePathForTest(sessionDirA, identityBPub)
                Files.write(corruptFile, ByteArray(200).also { SecureRandom().nextBytes(it) })

                val received = Collections.synchronizedList(mutableListOf<DmInboundMessage>())
                nodeB.dmSessionManager.addInboundListener { received.add(it) }
                val beforePrekeys = nodeB.prekeyStore.availableOneTimePrekeyCount()

                shouldNotThrowAny {
                    nodeA.dmSessionManager.send(identityBPub, "survives a corrupt session file".toByteArray())
                }
                val messages = awaitAtLeast(received, 1)
                messages[0].plaintext.decodeToString() shouldBe "survives a corrupt session file"
                // A REAL, fresh X3DH handshake ran instead of the corrupt file wedging this peer
                // forever - proven via one-time-prekey consumption, the same proof this file's other
                // first-contact assertions already use.
                nodeB.prekeyStore.availableOneTimePrekeyCount() shouldBe (beforePrekeys - 1)
            } finally {
                nodeA.stop()
                nodeB.stop()
            }
        }

        test(
            "loadPersisted treats an AEAD-TAMPERED session file (a flipped byte anywhere in the " +
                "ciphertext/tag, or a wrong key) as absent too - the SAME re-handshake recovery as a " +
                "structurally corrupt file above, not a silently-dropped-forever inbound path " +
                "(regression for follow-up hardening item 2, 2026-08-11)",
        ) {
            val identityA = DualKeyIdentity.generate()
            val sessionDirA = Files.createTempDirectory("dm-tampered-session")
            var nodeA = buildDmTestNode(identity = identityA, sessionStoreDirectory = sessionDirA)
            val nodeB = buildDmTestNode(oneTimePrekeyCount = 30)
            try {
                connectAndConverge(nodeA, nodeB)
                val identityAPub = identityA.secp256k1KeyPair.publicKey
                val identityBPub = nodeB.identity.secp256k1KeyPair.publicKey

                val received = Collections.synchronizedList(mutableListOf<DmInboundMessage>())
                nodeB.dmSessionManager.addInboundListener { received.add(it) }

                // A REAL, legitimately-persisted session file for B, written by a genuine
                // first-contact send() - unlike the structurally-corrupt case above, this file is a
                // perfectly well-formed v1 session until it gets tampered with below.
                val beforePrekeys = nodeB.prekeyStore.availableOneTimePrekeyCount()
                nodeA.dmSessionManager.send(identityBPub, "first message".toByteArray())
                var messages = awaitAtLeast(received, 1)
                messages[0].sender shouldBe identityAPub
                nodeB.prekeyStore.availableOneTimePrekeyCount() shouldBe (beforePrekeys - 1)

                // Stop A entirely so its in-memory liveSessionCache is gone - mirrors this file's own
                // restart-resumption test. The NEXT send() for B can then only come from disk, which
                // is the only way to actually drive loadPersisted's decode path again.
                nodeA.node.stop()

                // Flip the LAST byte of the persisted file - inside the AEAD ciphertext/tag, never
                // the fixed-size structural header - a pure AEAD authentication failure, this test's
                // own counterpart to the structurally-corrupt case above (which fails on the magic/
                // length check instead, before decryption is ever attempted).
                val sessionFile = sessionFilePathForTest(sessionDirA, identityBPub)
                val bytes = Files.readAllBytes(sessionFile)
                bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 0xFF).toByte()
                Files.write(sessionFile, bytes)

                nodeA = buildDmTestNode(identity = identityA, sessionStoreDirectory = sessionDirA)
                connectAndConverge(nodeA, nodeB)

                shouldNotThrowAny {
                    nodeA.dmSessionManager.send(identityBPub, "survives a tampered session file".toByteArray())
                }
                messages = awaitAtLeast(received, 2)
                messages[1].plaintext.decodeToString() shouldBe "survives a tampered session file"
                // A REAL, fresh X3DH handshake ran again - proven via a SECOND one-time-prekey
                // consumption, not merely "did not throw".
                nodeB.prekeyStore.availableOneTimePrekeyCount() shouldBe (beforePrekeys - 2)
            } finally {
                nodeA.stop()
                nodeB.stop()
            }
        }
    })
