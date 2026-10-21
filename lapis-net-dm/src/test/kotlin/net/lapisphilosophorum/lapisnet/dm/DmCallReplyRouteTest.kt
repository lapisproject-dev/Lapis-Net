package net.lapisphilosophorum.lapisnet.dm

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.libp2p.core.PeerId
import io.libp2p.core.PeerInfo
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import java.time.Instant
import java.util.Collections

/**
 * V0.9.19: answering a call signal over the connection it arrived on, when the answerer (B) has no
 * directory record for the caller (A). Real two-node loopback; ONLY B publishes its record.
 */
private class Pair2(
    val a: DmTestNode,
    val b: DmTestNode,
    val sessionDirA: Path,
    val sessionDirB: Path,
) {
    val aPub = a.identity.secp256k1KeyPair.publicKey
    val bPub = b.identity.secp256k1KeyPair.publicKey
    val signalsAtB = Collections.synchronizedList(mutableListOf<DmInboundCallSignal>())
    val signalsAtA = Collections.synchronizedList(mutableListOf<DmInboundCallSignal>())

    fun stop() {
        a.stop()
        b.stop()
    }
}

private fun awaitTrue(
    timeout: Duration = Duration.ofSeconds(30),
    condition: () -> Boolean,
): Boolean {
    val deadline = Instant.now().plus(timeout)
    while (Instant.now().isBefore(deadline)) {
        if (condition()) return true
        Thread.sleep(100)
    }
    return condition()
}

/** A knows B (B published); B does NOT know A. A->B TEXT establishes the session, then A sends one
 * CALL_SIGNAL so B holds a reply route. */
private fun establishCallerUnknownToCallee(): Pair2 {
    val dirA = Files.createTempDirectory("dm-rr-a")
    val dirB = Files.createTempDirectory("dm-rr-b")
    val a = buildDmTestNode(sessionStoreDirectory = dirA)
    val b = buildDmTestNode(sessionStoreDirectory = dirB)
    val p = Pair2(a, b, dirA, dirB)
    try {
        a.node.connect(PeerInfo(b.node.peerId, b.node.listenAddresses()))
        val converged =
            awaitTrue {
                b.publishSelf()
                a.peerDirectory.lookup(p.bPub) != null && a.prekeyBundleGossip.lookup(p.bPub) != null
            }
        check(converged) { "A did not learn B's records" }
        val texts = Collections.synchronizedList(mutableListOf<DmInboundMessage>())
        b.dmSessionManager.addInboundListener { texts.add(it) }
        val got =
            awaitTrue {
                if (texts.isEmpty()) runCatching { a.dmSessionManager.send(p.bPub, DmContent(body = "hi")) }
                texts.isNotEmpty()
            }
        check(got) { "session was not established" }
        b.dmSessionManager.addCallSignalListener { p.signalsAtB.add(it) }
        a.dmSessionManager.addCallSignalListener { p.signalsAtA.add(it) }
        a.dmSessionManager.sendCallSignal(p.bPub, "invite".toByteArray(), marksAcceptance = true)
        check(awaitTrue { p.signalsAtB.isNotEmpty() }) { "call signal not received" }
        return p
    } catch (e: Throwable) {
        p.stop()
        throw e
    }
}

private fun sessionFileBytes(dir: Path): Map<String, List<Byte>> =
    Files.list(dir).use { s -> s.filter { Files.isRegularFile(it) }.toList() }.associate {
        it.fileName.toString() to Files.readAllBytes(it).toList()
    }

class DmCallReplyRouteTest :
    FunSpec({
        test("H1: B answers A over the reply route although B has no directory record for A") {
            val p = establishCallerUnknownToCallee()
            try {
                p.b.peerDirectory.lookup(p.aPub) shouldBe null
                val route = p.signalsAtB[0].replyRoute
                route shouldNotBe null
                p.b.dmSessionManager.sendCallSignal(p.aPub, "reply".toByteArray(), false, route)
                awaitTrue { p.signalsAtA.isNotEmpty() } shouldBe true
                String(p.signalsAtA[0].payload) shouldBe "reply"
                p.signalsAtA[0].sender shouldBe p.bPub
                p.b.dmSessionManager.callSignalsSentViaReplyRouteCount() shouldBe 1L
                p.b.peerDirectory.lookup(p.aPub) shouldBe null
            } finally {
                p.stop()
            }
        }

        test("H2: with a directory record the directory path wins and the reply route is not used") {
            val p = establishCallerUnknownToCallee()
            try {
                val route = p.signalsAtB[0].replyRoute
                awaitTrue {
                    p.a.publishSelf()
                    p.b.peerDirectory.lookup(p.aPub) != null
                } shouldBe true
                p.b.dmSessionManager.sendCallSignal(p.aPub, "reply".toByteArray(), false, route)
                awaitTrue { p.signalsAtA.isNotEmpty() } shouldBe true
                p.b.dmSessionManager.callSignalsSentViaReplyRouteCount() shouldBe 0L
            } finally {
                p.stop()
            }
        }

        test("N1: no route and no directory record -> DmUnknownRecipientException, ratchet state untouched") {
            val p = establishCallerUnknownToCallee()
            try {
                val before = sessionFileBytes(p.sessionDirB)
                shouldThrow<DmUnknownRecipientException> {
                    p.b.dmSessionManager.sendCallSignal(p.aPub, "x".toByteArray(), false, null)
                }
                sessionFileBytes(p.sessionDirB) shouldBe before
            } finally {
                p.stop()
            }
        }

        test("N2: a forged (random) token is not resolved") {
            val p = establishCallerUnknownToCallee()
            try {
                shouldThrow<DmUnknownRecipientException> {
                    p.b.dmSessionManager.sendCallSignal(
                        p.aPub,
                        "x".toByteArray(),
                        false,
                        DmCallReplyRoute(ByteArray(DmCallReplyRoute.TOKEN_SIZE) { it.toByte() }),
                    )
                }
                p.b.dmSessionManager.callSignalsSentViaReplyRouteCount() shouldBe 0L
            } finally {
                p.stop()
            }
        }

        test("N3: a token issued for A cannot be used to reach another recipient") {
            val p = establishCallerUnknownToCallee()
            try {
                val route = p.signalsAtB[0].replyRoute
                val other = DualKeyIdentity.generate().secp256k1KeyPair.publicKey
                val ex =
                    shouldThrow<DmSessionException> {
                        p.b.dmSessionManager.sendCallSignal(other, "x".toByteArray(), false, route)
                    }
                val text = ex.message.orEmpty()
                text.contains(route!!.token.joinToString("") { "%02x".format(it) }) shouldBe false
                text.contains(
                    p.a.node.peerId
                        .toString(),
                ) shouldBe false
            } finally {
                p.stop()
            }
        }

        test("N4: an expired token is rejected") {
            val p = establishCallerUnknownToCallee()
            try {
                val route = p.signalsAtB[0].replyRoute
                p.b.dmSessionManager.nanoClock = {
                    System.nanoTime() + DmSessionManager.CALL_REPLY_ROUTE_MAX_AGE.toNanos() + 1_000_000_000L
                }
                shouldThrow<DmUnknownRecipientException> {
                    p.b.dmSessionManager.sendCallSignal(p.aPub, "x".toByteArray(), false, route)
                }
                p.b.dmSessionManager.replyRouteCountForTesting() shouldBe 0
            } finally {
                p.stop()
            }
        }

        test("N5: after the connection closed the send fails and NO new connection is opened") {
            val p = establishCallerUnknownToCallee()
            try {
                val route = p.signalsAtB[0].replyRoute
                p.b.node.host.network.connections
                    .toList()
                    .forEach { it.close().get(5, java.util.concurrent.TimeUnit.SECONDS) }
                awaitTrue {
                    p.b.node.host.network.connections
                        .none { !it.closeFuture().isDone }
                } shouldBe true
                shouldThrow<DmUnknownRecipientException> {
                    p.b.dmSessionManager.sendCallSignal(p.aPub, "x".toByteArray(), false, route)
                }
                p.b.node.host.network.connections
                    .none { !it.closeFuture().isDone } shouldBe true
            } finally {
                p.stop()
            }
        }

        test("N7: send() to a caller without directory record never uses the reply route") {
            val p = establishCallerUnknownToCallee()
            try {
                shouldThrow<DmUnknownRecipientException> {
                    p.b.dmSessionManager.send(p.aPub, DmContent(body = "text"))
                }
                p.b.dmSessionManager.callSignalsSentViaReplyRouteCount() shouldBe 0L
            } finally {
                p.stop()
            }
        }

        test("R2 + R1 + T1 + T2: token reuse per connection, replay and tamper never issue a route") {
            val p = establishCallerUnknownToCallee()
            try {
                val first = p.signalsAtB[0].replyRoute
                p.b.dmSessionManager.replyRouteCountForTesting() shouldBe 1

                val aSession = p.a.dmSessionManager.liveSessionForTest(p.bPub)!!
                val ratchet1 = aSession.encrypt("second".toByteArray())
                val env1 = DmEnvelope(DmMessageType.CALL_SIGNAL, p.aPub, null, ratchet1)
                val bytes1 = DmEnvelopeCodec.encode(env1)
                val aPeer = p.a.node.peerId
                p.b.dmSessionManager.handleInboundEnvelope(aPeer, bytes1)
                p.signalsAtB.size shouldBe 2
                // R2: same connection -> same token
                p.signalsAtB[1].replyRoute shouldBe first
                p.b.dmSessionManager.replyRouteCountForTesting() shouldBe 1

                // R1: byte-identical replay (even from a different connection / attacker peer) -> no
                // second delivery, no route for the attacker's peer id (T2).
                val attackerPeer = PeerId.random()
                p.b.dmSessionManager.handleInboundEnvelope(attackerPeer, bytes1)
                p.b.dmSessionManager.handleInboundEnvelope(aPeer, bytes1)
                p.signalsAtB.size shouldBe 2
                p.b.dmSessionManager.replyRouteCountForTesting() shouldBe 1

                // T1: flipped ciphertext byte -> no delivery, no registry entry.
                val ratchet2 = aSession.encrypt("third".toByteArray())
                val bytes2 = DmEnvelopeCodec.encode(DmEnvelope(DmMessageType.CALL_SIGNAL, p.aPub, null, ratchet2))
                val tampered = bytes2.copyOf()
                tampered[tampered.size - 1] = (tampered[tampered.size - 1].toInt() xor 0x01).toByte()
                p.b.dmSessionManager.handleInboundEnvelope(attackerPeer, tampered)
                p.signalsAtB.size shouldBe 2
                p.b.dmSessionManager.replyRouteCountForTesting() shouldBe 1
            } finally {
                p.stop()
            }
        }

        test("L1: per-identity and global registry caps evict the oldest route") {
            val p = establishCallerUnknownToCallee()
            try {
                val aSession = p.a.dmSessionManager.liveSessionForTest(p.bPub)!!

                fun deliverVia(peer: PeerId) {
                    val r = aSession.encrypt("x".toByteArray())
                    val bytes = DmEnvelopeCodec.encode(DmEnvelope(DmMessageType.CALL_SIGNAL, p.aPub, null, r))
                    p.b.dmSessionManager.handleInboundEnvelope(peer, bytes)
                }
                // per identity: first route (real connection) + 5 more distinct connections -> capped at 4
                repeat(5) { deliverVia(PeerId.random()) }
                p.b.dmSessionManager.replyRouteCountForTesting() shouldBe
                    DmSessionManager.MAX_CALL_REPLY_ROUTES_PER_IDENTITY

                // oldest (the real one) evicted: the first token no longer resolves
                val firstRoute = p.signalsAtB[0].replyRoute
                shouldThrow<DmUnknownRecipientException> {
                    p.b.dmSessionManager.sendCallSignal(p.aPub, "x".toByteArray(), false, firstRoute)
                }

                // global cap
                p.b.dmSessionManager.replyRouteCapacity = 2
                deliverVia(PeerId.random())
                p.b.dmSessionManager.replyRouteCountForTesting() shouldBe 2
            } finally {
                p.stop()
            }
        }
    })
