package net.lapisphilosophorum.lapisnet.call

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerInfo
import net.lapisphilosophorum.lapisnet.dm.DmAcceptanceCheck
import net.lapisphilosophorum.lapisnet.dm.DmContent
import net.lapisphilosophorum.lapisnet.dm.DmInboundMessage
import net.lapisphilosophorum.lapisnet.dm.DmTestNode
import net.lapisphilosophorum.lapisnet.dm.buildDmTestNode
import net.lapisphilosophorum.lapisnet.policy.AcceptanceGate
import net.lapisphilosophorum.lapisnet.policy.KarmaScoreLookup
import net.lapisphilosophorum.lapisnet.trust.TrustGraph
import java.time.Duration
import java.time.Instant
import java.util.concurrent.CopyOnWriteArrayList

/**
 * V0.9.19: the production wiring (real DmSessionManager, FakeCallMediaEngine) where ONLY the callee
 * (B) has published its peer record - the caller (A) is unknown to B's directory, so B can answer
 * (REJECT/ACCEPT/HANGUP) only over the reply route of the connection A's INVITE arrived on.
 */
private class CallerUnknownPair(
    val nodeA: DmTestNode,
    val nodeB: DmTestNode,
    val managerA: CallManager,
    val managerB: CallManager,
    val eventsA: CopyOnWriteArrayList<CallEvent>,
    val eventsB: CopyOnWriteArrayList<CallEvent>,
) {
    val aPub = nodeA.identity.secp256k1KeyPair.publicKey
    val bPub = nodeB.identity.secp256k1KeyPair.publicKey
}

private fun withCallerUnknownToCallee(
    acceptanceB: DmAcceptanceCheck? = null,
    configA: CallConfig = CallConfig(),
    configB: CallConfig = CallConfig(),
    block: (CallerUnknownPair) -> Unit,
) {
    val nodeA = buildDmTestNode()
    val nodeB = buildDmTestNode(acceptance = acceptanceB)
    var managerA: CallManager? = null
    var managerB: CallManager? = null
    try {
        nodeA.node.connect(PeerInfo(nodeB.node.peerId, nodeB.node.listenAddresses()))
        val bPub = nodeB.identity.secp256k1KeyPair.publicKey
        val deadline = Instant.now().plus(Duration.ofSeconds(30))
        // ONLY B publishes: A must stay unknown to B's directory for the whole test.
        while (Instant.now().isBefore(deadline)) {
            nodeB.publishSelf()
            if (nodeA.peerDirectory.lookup(bPub) != null && nodeA.prekeyBundleGossip.lookup(bPub) != null) break
            Thread.sleep(300)
        }
        val received = CopyOnWriteArrayList<DmInboundMessage>()
        nodeB.dmSessionManager.addInboundListener { received.add(it) }
        val textDeadline = Instant.now().plus(Duration.ofSeconds(30))
        while (received.isEmpty() && Instant.now().isBefore(textDeadline)) {
            runCatching { nodeA.dmSessionManager.send(bPub, DmContent(body = "hi")) }
            Thread.sleep(500)
        }
        received.isEmpty() shouldBe false
        nodeB.peerDirectory.lookup(nodeA.identity.secp256k1KeyPair.publicKey) shouldBe null

        val mA = CallManager.attach(nodeA.dmSessionManager, FakeCallMediaEngine(), configA)
        val mB = CallManager.attach(nodeB.dmSessionManager, FakeCallMediaEngine(), configB)
        managerA = mA
        managerB = mB
        val eventsA = CopyOnWriteArrayList<CallEvent>()
        val eventsB = CopyOnWriteArrayList<CallEvent>()
        mA.addCallListener { eventsA.add(it) }
        mB.addCallListener { eventsB.add(it) }
        block(CallerUnknownPair(nodeA, nodeB, mA, mB, eventsA, eventsB))
    } finally {
        runCatching { managerA?.stop() }
        runCatching { managerB?.stop() }
        nodeA.stop()
        nodeB.stop()
    }
}

class CallReplyRouteIntegrationTest :
    FunSpec({
        test("I1: B rejects a call from a caller it has no directory record for; A ends quickly, not at ring timeout") {
            withCallerUnknownToCallee(configA = CallConfig(ringTimeout = Duration.ofSeconds(30))) { p ->
                val callId = p.managerA.placeCall(p.bPub)
                awaitCondition(timeoutMs = 30_000) { p.eventsB.any { it is CallEvent.IncomingCall } }
                val rejectedAt = System.currentTimeMillis()
                p.managerB.rejectCall(callId, CallEndReason.DECLINED)

                awaitCondition(timeoutMs = 10_000, message = "A never saw the REJECT") {
                    p.eventsA.any { it is CallEvent.Ended }
                }
                (System.currentTimeMillis() - rejectedAt < 10_000) shouldBe true
                p.eventsA
                    .filterIsInstance<CallEvent.Ended>()
                    .single()
                    .reason shouldBe CallEndReason.DECLINED
                p.nodeB.peerDirectory.lookup(p.aPub) shouldBe null
                p.managerB.failedSignalSendsForTesting() shouldBe 0L
                p.nodeB.dmSessionManager.callSignalsSentViaReplyRouteCount() shouldBe 1L
            }
        }

        test("I2: B accepts then hangs up; A reaches ACTIVE and then sees REMOTE_HANGUP, all over the reply route") {
            withCallerUnknownToCallee { p ->
                val callId = p.managerA.placeCall(p.bPub)
                awaitCondition(timeoutMs = 30_000) { p.eventsB.any { it is CallEvent.IncomingCall } }
                p.managerB.acceptCall(callId)
                awaitCondition(timeoutMs = 30_000) { p.eventsA.any { it is CallEvent.Active } }
                awaitCondition(timeoutMs = 30_000) { p.eventsB.any { it is CallEvent.Active } }

                p.managerB.hangUp(callId)
                awaitCondition(timeoutMs = 10_000, message = "A never saw the HANGUP") {
                    p.eventsA.any { it is CallEvent.Ended }
                }
                p.eventsA
                    .filterIsInstance<CallEvent.Ended>()
                    .single()
                    .reason shouldBe CallEndReason.REMOTE_HANGUP
                p.nodeB.peerDirectory.lookup(p.aPub) shouldBe null
                p.managerB.failedSignalSendsForTesting() shouldBe 0L
                // ACCEPT + HANGUP
                p.nodeB.dmSessionManager.callSignalsSentViaReplyRouteCount() shouldBe 2L
            }
        }

        test(
            "I3: a quarantined caller's INVITE (autoRejectQuarantined) is dropped silently: nothing is sent, no route used",
        ) {
            val acceptance =
                DmAcceptanceCheck(
                    gates = listOf(AcceptanceGate.VeritasPath),
                    trustGraph = TrustGraph.fromEdges(emptyList()),
                    karmaScoreOf = KarmaScoreLookup { 0.0 },
                )
            withCallerUnknownToCallee(acceptanceB = acceptance) { p ->
                p.managerA.placeCall(p.bPub)
                awaitCondition(timeoutMs = 30_000) { p.eventsB.any { it is CallEvent.IncomingCall } }
                p.eventsB
                    .filterIsInstance<CallEvent.IncomingCall>()
                    .single()
                    .quarantined shouldBe true
                Thread.sleep(1_500)
                p.eventsA.none { it is CallEvent.Ended } shouldBe true
                p.nodeB.dmSessionManager.callSignalsSentViaReplyRouteCount() shouldBe 0L
                p.managerB.failedSignalSendsForTesting() shouldBe 0L
                p.managerB.activeCalls() shouldBe emptyList()
            }
        }
    })
