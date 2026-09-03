package net.lapisphilosophorum.lapisnet.dm

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.policy.AcceptanceGate
import net.lapisphilosophorum.lapisnet.policy.KarmaScoreLookup
import net.lapisphilosophorum.lapisnet.trust.TrustGraph
import java.time.Duration
import java.time.Instant
import java.util.Collections

/** Sends `body` as an ordinary TEXT DM from [sender] to [recipient], retrying the whole send (real
 * two-node timing - mirrors [TwoNodeDmIntegrationTest]'s own established pattern) until [received]
 * gains an entry or [timeout] elapses. */
private fun sendTextUntilReceived(
    sender: DmTestNode,
    recipient: DmTestNode,
    body: String,
    received: MutableList<DmInboundMessage>,
    timeout: Duration = Duration.ofSeconds(30),
) {
    val recipientPub = recipient.identity.secp256k1KeyPair.publicKey
    val deadline = Instant.now().plus(timeout)
    while (received.isEmpty() && Instant.now().isBefore(deadline)) {
        runCatching { sender.dmSessionManager.send(recipientPub, DmContent(body = body)) }
        Thread.sleep(1000)
    }
    if (received.isEmpty()) error("text DM \"$body\" was not received within $timeout")
}

/**
 * V0.8.7: [DmSessionManager.sendCallSignal]/[DmSessionManager.addCallSignalListener] - real two-node
 * loopback tests, mirroring [TwoNodeDmIntegrationTest]'s own established real-stack discipline.
 */
class DmSessionManagerCallSignalTest :
    FunSpec({
        test(
            "sendCallSignal without an established session throws DmNoSessionException, without ever bootstrapping one",
        ) {
            val nodeA = buildDmTestNode()
            val nodeB = buildDmTestNode()
            try {
                connectAndConverge(nodeA, nodeB)
                val bPub = nodeB.identity.secp256k1KeyPair.publicKey

                nodeA.dmSessionManager.liveSessionForTest(bPub) shouldBe null
                shouldThrow<DmNoSessionException> {
                    nodeA.dmSessionManager.sendCallSignal(bPub, "hello".toByteArray(), marksAcceptance = true)
                }
                // No session was bootstrapped as a side effect of the failed attempt - a call never
                // begins a first contact (see DmSessionManager's own class doc comment).
                nodeA.dmSessionManager.liveSessionForTest(bPub) shouldBe null
            } finally {
                nodeA.stop()
                nodeB.stop()
            }
        }

        test(
            "sendCallSignal over an established session delivers to the recipient's call-signal listener, never to addInboundListener",
        ) {
            val nodeA = buildDmTestNode()
            val nodeB = buildDmTestNode()
            try {
                connectAndConverge(nodeA, nodeB)
                val aPub = nodeA.identity.secp256k1KeyPair.publicKey
                val bPub = nodeB.identity.secp256k1KeyPair.publicKey

                val textReceived = Collections.synchronizedList(mutableListOf<DmInboundMessage>())
                nodeB.dmSessionManager.addInboundListener { textReceived.add(it) }
                sendTextUntilReceived(nodeA, nodeB, "hi", textReceived)

                val callSignalsReceived = Collections.synchronizedList(mutableListOf<DmInboundCallSignal>())
                nodeB.dmSessionManager.addCallSignalListener { callSignalsReceived.add(it) }

                val payload = "opaque-call-signal-bytes".toByteArray()
                nodeA.dmSessionManager.sendCallSignal(bPub, payload, marksAcceptance = true)

                val deadline = Instant.now().plus(Duration.ofSeconds(30))
                while (callSignalsReceived.isEmpty() && Instant.now().isBefore(deadline)) Thread.sleep(200)

                callSignalsReceived.isEmpty() shouldBe false
                callSignalsReceived[0].sender shouldBe aPub
                callSignalsReceived[0].payload shouldBe payload
                callSignalsReceived[0].quarantined shouldBe false

                // Exactly the one earlier TEXT message - the call signal never also reached this
                // listener.
                textReceived.size shouldBe 1
            } finally {
                nodeA.stop()
                nodeB.stop()
            }
        }

        test("sendCallSignal rejects a payload larger than MAX_CALL_SIGNAL_PAYLOAD_BYTES with DmSessionException") {
            val node = buildDmTestNode()
            try {
                val someoneElse =
                    net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
                        .generate()
                        .secp256k1KeyPair.publicKey
                val oversized = ByteArray(DmSessionManager.MAX_CALL_SIGNAL_PAYLOAD_BYTES + 1)
                // Rejected BEFORE any directory lookup - see DmSessionManager.sendCallSignal's own
                // doc comment; no real peer/session is needed to observe this failure mode.
                shouldThrow<DmSessionException> {
                    node.dmSessionManager.sendCallSignal(someoneElse, oversized, marksAcceptance = true)
                }
            } finally {
                node.stop()
            }
        }

        test("an inbound call signal's quarantined flag correctly reflects the recipient's DmAcceptancePolicy") {
            val nodeA = buildDmTestNode()
            val acceptance =
                DmAcceptanceCheck(
                    gates = listOf(AcceptanceGate.VeritasPath),
                    trustGraph = TrustGraph.fromEdges(emptyList()),
                    karmaScoreOf = KarmaScoreLookup { 0.0 },
                )
            val nodeB = buildDmTestNode(acceptance = acceptance)
            try {
                connectAndConverge(nodeA, nodeB)
                val bPub = nodeB.identity.secp256k1KeyPair.publicKey

                val textReceived = Collections.synchronizedList(mutableListOf<DmInboundMessage>())
                nodeB.dmSessionManager.addInboundListener { textReceived.add(it) }
                sendTextUntilReceived(nodeA, nodeB, "hi", textReceived)

                val callSignalsReceived = Collections.synchronizedList(mutableListOf<DmInboundCallSignal>())
                nodeB.dmSessionManager.addCallSignalListener { callSignalsReceived.add(it) }
                nodeA.dmSessionManager.sendCallSignal(bPub, "x".toByteArray(), marksAcceptance = true)

                val deadline = Instant.now().plus(Duration.ofSeconds(30))
                while (callSignalsReceived.isEmpty() && Instant.now().isBefore(deadline)) Thread.sleep(200)

                callSignalsReceived.isEmpty() shouldBe false
                callSignalsReceived[0].quarantined shouldBe true
            } finally {
                nodeA.stop()
                nodeB.stop()
            }
        }

        test(
            "sendCallSignal(marksAcceptance = false) never promotes the recipient to accepted " +
                "contact, but sendCallSignal(marksAcceptance = true) does - round-11 review finding " +
                "(2026-09-03): an automatically emitted call signal is protocol state, not a local " +
                "user decision, and DmAcceptedContacts' own class doc comment requires exactly the " +
                "latter before a peer may bypass DmAcceptancePolicy",
        ) {
            // acceptedContacts is wired on the SENDER (nodeA) - prepareCallEnvelopeLocked's
            // acceptedContacts?.accept(recipient) call runs in the SENDING DmSessionManager and
            // promotes the RECIPIENT in the sender's own ledger (see that function's own doc
            // comment) - so nodeA, not nodeB, is where this test must observe the effect.
            //
            // The session-establishing TEXT message is sent nodeB -> nodeA (not the other way
            // around): [DmSessionManager.send]'s own prepareEnvelopeLocked unconditionally marks its
            // recipient accepted for EVERY outbound send (pre-existing V0.8.6 behavior, untouched by
            // this fix) - had nodeA sent first, that alone would already flip nodeAAcceptedContacts
            // before this test's own sendCallSignal calls ever ran, making the "still false"
            // assertion below trivially true for the wrong reason. Receiving B's inbound X3DH-initial
            // message is enough for nodeA's OWN session with B to reach canSend = true (see
            // DoubleRatchetSession's own "bootstrap asymmetry" doc comment: decrypting the first
            // inbound message on a freshly initializeReceiver()'d session performs the DH ratchet
            // step that establishes its sending chain too) - so nodeA can sendCallSignal right after,
            // with nodeA itself never having sent anything, hence never having auto-accepted bPub.
            val nodeAAcceptedContacts = DmAcceptedContacts()
            val nodeA = buildDmTestNode(acceptedContacts = nodeAAcceptedContacts)
            val nodeB = buildDmTestNode()
            try {
                connectAndConverge(nodeA, nodeB)
                val bPub = nodeB.identity.secp256k1KeyPair.publicKey

                val textReceived = Collections.synchronizedList(mutableListOf<DmInboundMessage>())
                nodeA.dmSessionManager.addInboundListener { textReceived.add(it) }
                sendTextUntilReceived(nodeB, nodeA, "hi", textReceived)

                nodeAAcceptedContacts.isAccepted(bPub) shouldBe false

                // An AUTOMATIC, protocol-driven signal (e.g. CallManager's own BUSY/SDP-policy
                // auto-reject or ring/connect timeout) - marksAcceptance = false - must NEVER flip
                // isAccepted, no matter how many times it is sent. THIS is the exact regression the
                // round-11 finding describes: before the fix, every sendCallSignal call flipped this
                // unconditionally regardless of why CallManager was sending it.
                nodeA.dmSessionManager.sendCallSignal(
                    recipient = bPub,
                    payload = "auto-reject".toByteArray(),
                    marksAcceptance = false,
                )
                nodeAAcceptedContacts.isAccepted(bPub) shouldBe false

                // A genuinely USER-decided signal to COMMUNICATE (e.g. CallManager's own INVITE from
                // placeCall, an ACCEPT from acceptCall, or a HANGUP for a call already placed/
                // answered) - marksAcceptance = true - is the only case allowed to flip it. Round-12
                // review finding (2026-09-03): REJECT and an unanswered HANGUP are user-initiated
                // too, but are a decision NOT to communicate, so CallManager always sends those with
                // marksAcceptance = false - see CallManager.rejectCallOnStateThread's/
                // hangUpOnStateThread's own doc comments.
                nodeA.dmSessionManager.sendCallSignal(
                    recipient = bPub,
                    payload = "user-decided".toByteArray(),
                    marksAcceptance = true,
                )
                nodeAAcceptedContacts.isAccepted(bPub) shouldBe true
            } finally {
                nodeA.stop()
                nodeB.stop()
            }
        }
    })
