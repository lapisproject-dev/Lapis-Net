package net.lapisphilosophorum.lapisnet.dm

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import java.time.Duration
import java.time.Instant
import java.util.Collections

/**
 * V0.8.7 - proves [DmSessionManager.handleOfflineEnvelope]'s `CALL_SIGNAL` rejection is structural
 * (before any decrypt attempt) and leaves the ratchet session fully usable afterward, mirroring
 * [MailboxAbuseTest]'s established "hand-craft a hostile envelope, feed it through the offline path
 * directly" discipline.
 */
class CallSignalMailboxRejectionTest :
    FunSpec({
        test(
            "a hand-built CALL_SIGNAL envelope delivered via the offline mailbox path is rejected " +
                "outright (final, no decrypt attempt, no listener call), and the ratchet session " +
                "remains fully usable for a subsequent real TEXT DM",
        ) {
            val nodeA = buildDmTestNode()
            val nodeB = buildDmTestNode()
            try {
                connectAndConverge(nodeA, nodeB)
                val aPub = nodeA.identity.secp256k1KeyPair.publicKey
                val bPub = nodeB.identity.secp256k1KeyPair.publicKey

                // Establish a real, bidirectional session with one ordinary TEXT DM.
                val received = Collections.synchronizedList(mutableListOf<DmInboundMessage>())
                nodeB.dmSessionManager.addInboundListener { received.add(it) }
                val firstDeadline = Instant.now().plus(Duration.ofSeconds(30))
                while (received.isEmpty() && Instant.now().isBefore(firstDeadline)) {
                    runCatching { nodeA.dmSessionManager.send(bPub, DmContent(body = "hello")) }
                    Thread.sleep(1000)
                }
                received.isEmpty() shouldBe false

                // Hand-build a CALL_SIGNAL envelope over A's now-established live session with B -
                // internal DmEnvelope ctor + liveSessionForTest, both same-module test seams (mirrors
                // DmStreamAbuseTest's own established use of liveSessionForTest to drive a party's
                // REAL session directly, outside the normal send() path).
                val aSession = nodeA.dmSessionManager.liveSessionForTest(bPub)
                requireNotNull(aSession) { "expected an established session with B after the TEXT DM above" }
                val ratchetMessage =
                    aSession.encrypt(
                        "fake-call-signal-bytes-not-a-real-CallSignal-frame".toByteArray(),
                    )
                val callSignalEnvelope = DmEnvelope(DmMessageType.CALL_SIGNAL, aPub, null, ratchetMessage)

                val callSignalsReceived = Collections.synchronizedList(mutableListOf<DmInboundCallSignal>())
                nodeB.dmSessionManager.addCallSignalListener { callSignalsReceived.add(it) }

                // Delivered via the OFFLINE path directly - exactly what MailboxPoller would call
                // after a successful Bitswap fetch + structural DmEnvelopeCodec decode.
                val result = nodeB.dmSessionManager.handleOfflineEnvelope(callSignalEnvelope)

                result shouldBe true // final - MailboxPoller would mark the pointer resolved, never retry
                callSignalsReceived shouldBe emptyList()

                // Ratchet state unaffected: a SECOND, real TEXT DM over the SAME session still
                // decrypts normally - proof the offline-path rejection never attempted a decrypt (no
                // message-number consumed, no session state touched).
                received.clear()
                val secondDeadline = Instant.now().plus(Duration.ofSeconds(30))
                while (received.isEmpty() && Instant.now().isBefore(secondDeadline)) {
                    runCatching { nodeA.dmSessionManager.send(bPub, DmContent(body = "still works")) }
                    Thread.sleep(1000)
                }
                received.isEmpty() shouldBe false
                received[0].content.body shouldBe "still works"
            } finally {
                nodeA.stop()
                nodeB.stop()
            }
        }
    })
