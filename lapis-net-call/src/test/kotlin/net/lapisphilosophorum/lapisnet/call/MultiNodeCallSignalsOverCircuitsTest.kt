@file:OptIn(net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.call

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.read.ListAppender
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.withClue
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.directory.DirectoryReachability
import net.lapisphilosophorum.lapisnet.dm.DmAcceptanceCheck
import net.lapisphilosophorum.lapisnet.dm.DmContent
import net.lapisphilosophorum.lapisnet.dm.DmInboundCallSignal
import net.lapisphilosophorum.lapisnet.dm.DmInboundMessage
import net.lapisphilosophorum.lapisnet.dmonion.DmOnionNode
import net.lapisphilosophorum.lapisnet.dmonion.RelayHost
import net.lapisphilosophorum.lapisnet.dmonion.SyntheticLocator
import net.lapisphilosophorum.lapisnet.dmonion.awaitCondition
import net.lapisphilosophorum.lapisnet.dmonion.isSeenBehindService
import net.lapisphilosophorum.lapisnet.policy.AcceptanceGate
import net.lapisphilosophorum.lapisnet.policy.KarmaScoreLookup
import net.lapisphilosophorum.lapisnet.trust.TrustGraph
import org.slf4j.LoggerFactory
import java.time.Duration
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.time.Duration.Companion.seconds

private fun contains(
    haystack: ByteArray,
    needle: ByteArray,
): Boolean {
    if (needle.isEmpty() || haystack.size < needle.size) return false
    outer@ for (o in 0..haystack.size - needle.size) {
        for (i in needle.indices) if (haystack[o + i] != needle[i]) continue@outer
        return true
    }
    return false
}

/** One participant: the anonymity-mode DM rig plus a [CallManager] on top of it and its recorded events. */
private class CallNode(
    val rig: DmOnionNode,
    private val policy: CallMediaPolicy,
    private val ringTimeout: Duration,
) {
    val events = CopyOnWriteArrayList<CallEvent>()
    val signals = CopyOnWriteArrayList<DmInboundCallSignal>()
    val engine = FakeCallMediaEngine().also { e -> e.configureSession = { it.sdp = ::fakePublicAudioSdp } }
    lateinit var manager: CallManager

    fun attachCalls() {
        events.clear()
        manager =
            CallManager.attach(
                rig.dm,
                engine,
                CallConfig(
                    mediaPolicy = policy,
                    ringTimeout = ringTimeout,
                    connectTimeout = Duration.ofSeconds(30),
                ),
            )
        manager.addCallListener { events += it }
    }

    fun endedReasons() = events.filterIsInstance<CallEvent.Ended>().map { it.reason }

    fun shape() = events.map { it::class.simpleName + ((it as? CallEvent.Ended)?.let { e -> ":" + e.reason } ?: "") }
}

/**
 * V0.10.0-G: real nodes on loopback in anonymity mode; call signals travel over circuits. Six relays (the path policy
 * needs more than three to build a rendezvous path; the existing F1/F2 rigs use six as well), four nodes:
 * A and B (calls exposed), C (exposed, blocked by B's acceptance rule) and D (calls disabled).
 *
 * Verified here only on loopback with a synthetic network locator and a fake media engine: no real NAT, no real WebRTC
 * media (the exposure filter drops loopback candidates, so real media can not be tested on one host), no load test.
 */
class MultiNodeCallSignalsOverCircuitsTest :
    FunSpec({
        val logRoot = LoggerFactory.getLogger("net.lapisphilosophorum") as Logger
        val logAppender = ListAppender<ILoggingEvent>().also { it.start() }
        val oldLevel = logRoot.level
        logRoot.level = Level.DEBUG
        logRoot.addAppender(logAppender)
        val relays = List(6) { RelayHost() }
        for (i in relays.indices) for (j in i + 1 until relays.size) relays[i].connectTo(relays[j])
        val locator = SyntheticLocator()
        relays.forEachIndexed { i, r -> locator.put(r.key, 10 + i, i) }
        val a = CallNode(DmOnionNode(relays, locator), CallMediaPolicy.EXPOSED, Duration.ofSeconds(25))
        val b = CallNode(DmOnionNode(relays, locator), CallMediaPolicy.EXPOSED, Duration.ofSeconds(25))
        val c = CallNode(DmOnionNode(relays, locator), CallMediaPolicy.EXPOSED, Duration.ofSeconds(8))
        val d = CallNode(DmOnionNode(relays, locator), CallMediaPolicy.DISABLED, Duration.ofSeconds(25))
        val all = listOf(a, b, c, d)
        val received = all.associateWith { CopyOnWriteArrayList<DmInboundMessage>() }

        afterSpec {
            logRoot.detachAppender(logAppender)
            logRoot.level = oldLevel
            all.forEach { runCatching { it.manager.stop() } }
            all.forEach { runCatching { it.rig.stop() } }
            relays.forEach { runCatching { it.close() } }
        }

        fun sees(
            viewer: CallNode,
            other: CallNode,
        ) = viewer.rig.runtime.resolveIdentity(other.rig.key) is DirectoryReachability.Hidden &&
            viewer.rig.bundleGossip.lookup(other.rig.key) != null

        /** Sends DMs until [to] has one (a session in both directions exists afterwards). */
        fun establishSession(
            from: CallNode,
            to: CallNode,
        ) {
            var attempts = 0
            while (received.getValue(to).none { it.sender == from.rig.key } && attempts < 6) {
                attempts++
                runCatching { from.rig.dm.sendAuto(to.rig.key, DmContent(body = "hello")) }
                awaitCondition(Duration.ofSeconds(30)) { received.getValue(to).any { it.sender == from.rig.key } }
            }
            withClue("DM session ${from.rig.key.fingerprint()} -> ${to.rig.key.fingerprint()}") {
                received.getValue(to).any { it.sender == from.rig.key } shouldBe true
            }
        }

        test("four anonymity nodes start, see each other through the relays only and hold DM sessions")
            .config(timeout = 1500.seconds) {
                all.forEach { it.rig.start() }
                all.forEach { it.rig.awaitPublished() shouldBe true }
                // A directory object published while the gossip mesh is still forming is only repeated hourly (by
                // design); the test then restarts the node that is not seen, the way a user would.
                val pairs = listOf(a to b, b to a, c to b, b to c, a to d)
                for (attempt in 1..4) {
                    val converged = awaitCondition(Duration.ofSeconds(75)) { pairs.all { (v, o) -> sees(v, o) } }
                    if (converged) break
                    pairs.filter { (v, o) -> !sees(v, o) }.map { it.second }.distinct().forEach {
                        it.rig.stop()
                        it.rig.start()
                        it.rig.awaitPublished() shouldBe true
                    }
                }
                withClue(pairs.map { (v, o) -> sees(v, o) }.toString()) {
                    pairs.all { (v, o) -> sees(v, o) } shouldBe true
                }
                all.forEach { n -> n.rig.dm.addInboundListener { received.getValue(n) += it } }
                all.forEach { n -> n.rig.dm.addCallSignalListener { n.signals += it } }
                establishSession(a, b)
                establishSession(b, a)
                establishSession(c, b)
                establishSession(a, d)
                // B blocks C (no Veritas path) but knows A as accepted contact: C's signals are quarantined at B
                b.rig.dm.updateAcceptanceCheck(
                    DmAcceptanceCheck(
                        gates = listOf(AcceptanceGate.VeritasPath),
                        trustGraph = TrustGraph.fromEdges(emptyList()),
                        karmaScoreOf = KarmaScoreLookup { 0.0 },
                        isAcceptedContact = { it == a.rig.key },
                    ),
                )
                all.forEach { it.attachCalls() }
            }

        test(
            "A calls B (confirmed): INVITE, ACCEPT and HANGUP over circuits; only the public candidate crosses; observers see only relays",
        ).config(timeout = 600.seconds) {
            val framesBeforeA = a.rig.port.frames.size
            val framesBeforeB = b.rig.port.frames.size
            val callId = a.manager.placeCall(b.rig.key, mediaExposureConfirmed = true)
            withClue("B events: ${b.events}, A events: ${a.events}") {
                awaitCondition(Duration.ofSeconds(60)) { b.events.any { it is CallEvent.IncomingCall } } shouldBe
                    true
            }
            b.events
                .filterIsInstance<CallEvent.IncomingCall>()
                .single()
                .quarantined shouldBe false
            shouldThrow<CallMediaExposureNotConfirmedException> { b.manager.acceptCall(callId) }
            b.manager.acceptCall(callId, mediaExposureConfirmed = true)
            withClue("A: ${a.shape()}, B: ${b.shape()}") {
                awaitCondition(Duration.ofSeconds(60)) {
                    a.events.any { it is CallEvent.Active } && b.events.any { it is CallEvent.Active }
                } shouldBe true
            }
            a.shape() shouldBe listOf("OutgoingRinging", "Connecting", "Active")
            b.shape() shouldBe listOf("IncomingCall", "Connecting", "Active")
            (
                a.rig.dm
                    .routeMode()
                    .wire
            ) shouldBe "circuit"

            // signals travelled over circuits: both rendezvous senders handed more frames to circuits
            (a.rig.port.frames.size > framesBeforeA) shouldBe true
            (b.rig.port.frames.size > framesBeforeB) shouldBe true

            // what reached the media layer: only the public test address, no private or loopback address
            val remoteSdps =
                b.engine.sessions.flatMap { it.remoteSdps } + a.engine.sessions.flatMap { it.remoteSdps }
            remoteSdps.size shouldBe 2
            for (sdp in remoteSdps) {
                sdp.contains("198.51.100.7") shouldBe true
                sdp.contains("192.168.") shouldBe false
                sdp.contains("127.0.0.1") shouldBe false
                sdp.contains("c=IN IP4 0.0.0.0") shouldBe true
            }

            // network observer: A and B are connected to relays only, never to each other
            val relayIds = relays.map { it.node.peerId }.toSet()
            (a.rig.connectedPeers.contains(b.rig.node.peerId)) shouldBe false
            (b.rig.connectedPeers.contains(a.rig.node.peerId)) shouldBe false
            a.rig.connectedPeers.all { it in relayIds } shouldBe true
            b.rig.connectedPeers.all { it in relayIds } shouldBe true
            // no SDP plaintext, no address needle and no identity needle in anything handed to circuits
            val sent =
                a.rig.port.frames
                    .toList() +
                    b.rig.port.frames
                        .toList()
            val needles =
                listOf("198.51.100.7", "a=fingerprint", "192.168.").map { it.toByteArray() } +
                    a.rig.node
                        .listenAddresses()
                        .map { it.toString().toByteArray() } +
                    listOf(a.rig.node.peerId.bytes, b.rig.node.peerId.bytes)
            needles.none { n -> sent.any { contains(it, n) } } shouldBe true
            // positive control: the scanner does find the needle in the plain SDP
            contains(fakePublicAudioSdp().toByteArray(), "198.51.100.7".toByteArray()) shouldBe true

            a.manager.hangUp(callId)
            awaitCondition(Duration.ofSeconds(60)) {
                a.events.any { it is CallEvent.Ended } && b.events.any { it is CallEvent.Ended }
            } shouldBe true
            a.endedReasons() shouldBe listOf(CallEndReason.LOCAL_HANGUP)
            b.endedReasons() shouldBe listOf(CallEndReason.REMOTE_HANGUP)
        }

        test("C (blocked by B) calls B: C gets silence until RING_TIMEOUT, B never replies and never rings")
            .config(timeout = 300.seconds) {
                val bFrames = b.rig.port.frames.size
                c.manager.placeCall(b.rig.key, mediaExposureConfirmed = true)
                withClue("B: ${b.events}") {
                    awaitCondition(Duration.ofSeconds(60)) {
                        b.events.any { it is CallEvent.IncomingCall && it.quarantined }
                    } shouldBe true
                }
                b.manager.activeCalls() shouldBe emptyList()
                awaitCondition(Duration.ofSeconds(40)) { c.events.any { it is CallEvent.Ended } } shouldBe true
                c.endedReasons() shouldBe listOf(CallEndReason.RING_TIMEOUT)
                c.shape() shouldBe listOf("OutgoingRinging", "Ended:RING_TIMEOUT")
                c.signals.size shouldBe 0 // not one call signal came back from B
                b.rig.port.frames.size shouldBe bFrames // B sent nothing at all
                b.engine.sessions.size shouldBe 1 // only the earlier A call ever created a media session at B
            }

        test(
            "A calls D (calls disabled): A observes exactly what C observed, D never replies and records IncomingSuppressed",
        ).config(timeout = 300.seconds) {
            val dFrames = d.rig.port.frames.size
            a.events.clear()
            val aSignals = a.signals.size
            a.manager.placeCall(d.rig.key, mediaExposureConfirmed = true)
            withClue("D: ${d.events}") {
                awaitCondition(Duration.ofSeconds(60)) {
                    d.events.any { it is CallEvent.IncomingSuppressed }
                } shouldBe true
            }
            (d.events.single { it is CallEvent.IncomingSuppressed } as CallEvent.IncomingSuppressed).cause shouldBe
                CallSuppressCause.ANONYMITY_MODE
            awaitCondition(Duration.ofSeconds(60)) { a.events.any { it is CallEvent.Ended } } shouldBe true
            a.shape() shouldBe c.shape() // the same observation as against a blocking recipient
            a.signals.size shouldBe aSignals // nothing at all came back from D
            d.rig.port.frames.size shouldBe dFrames
            d.engine.sessions.size shouldBe 0
            d.manager.activeCalls() shouldBe emptyList()
        }

        test("D tries to call: placeCall throws synchronously and D produces no network traffic")
            .config(timeout = 120.seconds) {
                val frames = d.rig.port.frames.size
                val topics = d.rig.publishedTopics.size
                val circuits =
                    d.rig.runtime
                        .status()
                        .activeCircuits
                shouldThrow<CallMediaDisabledException> {
                    d.manager.placeCall(
                        a.rig.key,
                        mediaExposureConfirmed = true,
                    )
                }
                Thread.sleep(500)
                d.rig.port.frames.size shouldBe frames
                d.rig.publishedTopics.size shouldBe topics
                d.rig.runtime
                    .status()
                    .activeCircuits shouldBe circuits
                d.events.count { it is CallEvent.OutgoingRinging } shouldBe 0
            }

        test("stopping both call managers during an active call neither hangs nor leaks a media session")
            .config(timeout = 600.seconds) {
                a.events.clear()
                b.events.clear()
                val callId = a.manager.placeCall(b.rig.key, mediaExposureConfirmed = true)
                awaitCondition(Duration.ofSeconds(60)) { b.events.any { it is CallEvent.IncomingCall } } shouldBe true
                b.manager.acceptCall(callId, mediaExposureConfirmed = true)
                awaitCondition(Duration.ofSeconds(60)) {
                    a.events.any { it is CallEvent.Active } && b.events.any { it is CallEvent.Active }
                } shouldBe true
                val started = System.currentTimeMillis()
                a.manager.stop()
                b.manager.stop()
                ((System.currentTimeMillis() - started) < 40_000) shouldBe true
                a.manager.liveMediaSessionCountForTesting() shouldBe 0
                b.manager.liveMediaSessionCountForTesting() shouldBe 0
                a.engine.sessions.all { it.closed.get() } shouldBe true
                b.engine.sessions.all { it.closed.get() } shouldBe true
                a.attachCalls()
                b.attachCalls()
            }

        test(
            "B restarts with a NEW onion address: A's call reaches the new descriptor, INVITE, ACCEPT and HANGUP over circuits, no session leaks",
        ).config(timeout = 900.seconds) {
            fun restart(n: CallNode) {
                n.manager.stop()
                n.rig.stop()
                n.rig.freshServiceKeyPerStart = true
                n.rig.start()
                n.rig.dm.addInboundListener { received.getValue(n) += it }
                n.rig.dm.addCallSignalListener { n.signals += it }
                n.attachCalls()
                n.rig.awaitPublished() shouldBe true
            }
            val oldService = b.rig.serviceKey.publicKey
            restart(b)
            (b.rig.serviceKey.publicKey == oldService) shouldBe false
            val newService = b.rig.serviceKey.publicKey
            var lastTick = 0L

            fun tick() {
                if (System.currentTimeMillis() - lastTick > 3_000) {
                    a.rig.runtime.maintainNow()
                    b.rig.runtime.maintainNow()
                    lastTick = System.currentTimeMillis()
                }
            }
            // A restarted node is a late subscriber and gets no catch-up: it only sees the long-running A after A's next
            // publication (hourly, by design). Like the other multi-node tests, the node that is not seen is restarted too.
            val bSeesA =
                awaitCondition(Duration.ofSeconds(25)) {
                    tick()
                    sees(b, a)
                }
            if (!bSeesA) {
                println("TIMELINE call-restart: B did not see A after its restart; A restarts as well")
                restart(a)
            }
            withClue("A does not see B behind the new service, or B does not see A") {
                awaitCondition(Duration.ofSeconds(360)) {
                    tick()
                    b.rig.isSeenBehindService(a.rig, newService) && sees(a, b) && sees(b, a)
                } shouldBe true
            }
            a.events.clear()
            val failuresBefore = a.rig.port.connectFailures.size
            val framesBefore = b.rig.port.frames.size
            val callId = a.manager.placeCall(b.rig.key, mediaExposureConfirmed = true)
            withClue(
                "B events: ${b.events}, A events: ${a.events}, A connect failures: ${a.rig.port.connectFailures}",
            ) {
                awaitCondition(Duration.ofSeconds(90)) { b.events.any { it is CallEvent.IncomingCall } } shouldBe true
            }
            b.manager.acceptCall(callId, mediaExposureConfirmed = true)
            withClue("A: ${a.shape()}, B: ${b.shape()}") {
                awaitCondition(Duration.ofSeconds(60)) {
                    a.events.any { it is CallEvent.Active } && b.events.any { it is CallEvent.Active }
                } shouldBe true
            }
            (b.rig.port.frames.size > framesBefore) shouldBe true // B's ACCEPT went over a circuit
            // observers see only relays
            val relayIds = relays.map { it.node.peerId }.toSet()
            (a.rig.connectedPeers.contains(b.rig.node.peerId)) shouldBe false
            (b.rig.connectedPeers.contains(a.rig.node.peerId)) shouldBe false
            a.rig.connectedPeers.all { it in relayIds } shouldBe true
            b.rig.connectedPeers.all { it in relayIds } shouldBe true
            a.manager.hangUp(callId)
            awaitCondition(Duration.ofSeconds(60)) {
                a.events.any { it is CallEvent.Ended } && b.events.any { it is CallEvent.Ended }
            } shouldBe true
            a.endedReasons() shouldBe listOf(CallEndReason.LOCAL_HANGUP)
            b.endedReasons() shouldBe listOf(CallEndReason.REMOTE_HANGUP)
            // A never failed to connect to anything of B's old descriptor, and nothing is left running
            a.rig.port.connectFailures.size shouldBe failuresBefore
            awaitCondition(Duration.ofSeconds(60)) {
                a.manager.liveMediaSessionCountForTesting() == 0 && b.manager.liveMediaSessionCountForTesting() == 0
            } shouldBe true
            a.manager.activeCalls() shouldBe emptyList()
            b.manager.activeCalls() shouldBe emptyList()
            // the next test reads the events from a clean slate
            a.events.clear()
            b.events.clear()
        }

        test("the circuits die while B is ringing: B ends with CIRCUIT_LOST, A rings out, no session leaks")
            .config(timeout = 600.seconds) {
                val callId = a.manager.placeCall(b.rig.key, mediaExposureConfirmed = true)
                withClue("B: ${b.events}") {
                    awaitCondition(Duration.ofSeconds(60)) { b.events.any { it is CallEvent.IncomingCall } } shouldBe
                        true
                }
                relays.forEach { runCatching { it.close() } }
                b.manager.acceptCall(callId, mediaExposureConfirmed = true)
                val t0 = System.currentTimeMillis()
                withClue("B: ${b.shape()}") {
                    awaitCondition(Duration.ofSeconds(60)) { b.events.any { it is CallEvent.Ended } } shouldBe true
                }
                ((System.currentTimeMillis() - t0) < 45_000) shouldBe true
                b.endedReasons() shouldBe listOf(CallEndReason.CIRCUIT_LOST)
                awaitCondition(Duration.ofSeconds(60)) { a.events.any { it is CallEvent.Ended } } shouldBe true
                // Since wave H a cover cell written to a dead link can reveal the loss before the ring timeout; the call
                // then ends as CIRCUIT_LOST (with A on padding off it rings out as before, verified once by running the test that way).
                a.endedReasons().size shouldBe 1
                (a.endedReasons().single() in listOf(CallEndReason.RING_TIMEOUT, CallEndReason.CIRCUIT_LOST)) shouldBe
                    true
                // generous: under the load of a full parallel build the close tasks queue behind slow media-thread work
                withClue(
                    "live sessions A=${a.manager.liveMediaSessionCountForTesting()} B=${b.manager.liveMediaSessionCountForTesting()}",
                ) {
                    awaitCondition(Duration.ofSeconds(90)) {
                        a.manager.liveMediaSessionCountForTesting() == 0 &&
                            b.manager.liveMediaSessionCountForTesting() == 0
                    } shouldBe true
                }
            }

        test("no log line of the whole run carries a fingerprint, an address or an SDP of the call path")
            .config(timeout = 60.seconds) {
                val callRelated =
                    logAppender.list
                        .toList()
                        .filter { it.loggerName.startsWith("net.lapisphilosophorum.lapisnet.call") }
                        .map { it.formattedMessage + (it.throwableProxy?.message ?: "") }
                callRelated.isNotEmpty() shouldBe true
                val peers = all.map { it.rig.key.fingerprint() }
                for (line in callRelated) {
                    for (fp in peers) (line.contains(fp)) shouldBe false
                    line.contains("198.51.100.7") shouldBe false
                    line.contains("192.168.") shouldBe false
                    line.contains("a=fingerprint") shouldBe false
                }
            }
    })
