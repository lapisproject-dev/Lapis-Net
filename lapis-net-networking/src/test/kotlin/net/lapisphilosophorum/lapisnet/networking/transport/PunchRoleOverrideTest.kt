package net.lapisphilosophorum.lapisnet.networking.transport

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.protocol.IdentifyController
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.networking.awaitTrue
import java.time.Duration
import java.time.Instant
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

private fun LapisNode.expect(
    peer: LapisNode,
    initiatorRole: Boolean,
) = punchRoles!!.register(
    PunchRoleRegistry.Expectation(peer.peerId, listenAddress(peer), initiatorRole, Instant.now().plusSeconds(30)),
)!!

private fun identifyOver(
    from: LapisNode,
    to: LapisNode,
): Boolean {
    val connection = directTo(from, to.peerId) ?: return false
    return runCatching {
        from.host
            .newStream<IdentifyController>(listOf("/ipfs/id/1.0.0"), connection)
            .controller
            .get(10, TimeUnit.SECONDS)
            .id()
            .get(10, TimeUnit.SECONDS)
        true
    }.getOrDefault(false)
}

/**
 * The Noise/muxer role of a punched connection is decided by the hole-punch state machine, not by "who
 * dialled": a connection accepted by A's listener must still be built with A as the client.
 */
class PunchRoleOverrideTest :
    FunSpec({
        test("(a) B dials A, A accepts and takes the client role: the connection works in both directions") {
            if (!ReusePortSupport.available) return@test
            val a = punchNode()
            val b = punchNode()
            try {
                a.start()
                b.start()
                a.expect(b, initiatorRole = true).use {
                    b.expect(a, initiatorRole = false).use {
                        b.punchTransport!!.punchDial(listenAddress(a), a.peerId, false).get(15, TimeUnit.SECONDS)
                        awaitTrue(Duration.ofSeconds(10)) { directTo(a, b.peerId) != null } shouldBe true
                        identifyOver(b, a) shouldBe true
                        identifyOver(a, b) shouldBe true
                    }
                }
            } finally {
                runCatching { a.stop() }
                runCatching { b.stop() }
            }
        }

        test("(b) A dials B as the client, B accepts as the server") {
            if (!ReusePortSupport.available) return@test
            val a = punchNode()
            val b = punchNode()
            try {
                a.start()
                b.start()
                b.expect(a, initiatorRole = false).use {
                    a.punchTransport!!.punchDial(listenAddress(b), b.peerId, true).get(15, TimeUnit.SECONDS)
                    awaitTrue(Duration.ofSeconds(10)) { directTo(b, a.peerId) != null } shouldBe true
                    identifyOver(a, b) shouldBe true
                    identifyOver(b, a) shouldBe true
                }
            } finally {
                runCatching { a.stop() }
                runCatching { b.stop() }
            }
        }

        test("(c) twenty simultaneous punches always end in a working connection with consistent roles") {
            if (!ReusePortSupport.available) return@test
            var singleConnectionRounds = 0
            repeat(20) { round ->
                val a = punchNode()
                val b = punchNode()
                try {
                    a.start()
                    b.start()
                    val ra = a.expect(b, initiatorRole = true)
                    val rb = b.expect(a, initiatorRole = false)
                    val go = CountDownLatch(1)
                    val dialA =
                        Thread {
                            go.await()
                            runCatching {
                                a.punchTransport!!
                                    .punchDial(
                                        listenAddress(b),
                                        b.peerId,
                                        true,
                                    ).get(15, TimeUnit.SECONDS)
                            }
                        }
                    val dialB =
                        Thread {
                            go.await()
                            runCatching {
                                b.punchTransport!!
                                    .punchDial(
                                        listenAddress(a),
                                        a.peerId,
                                        false,
                                    ).get(15, TimeUnit.SECONDS)
                            }
                        }
                    dialA.start()
                    dialB.start()
                    go.countDown()
                    dialA.join(20_000)
                    dialB.join(20_000)
                    awaitTrue(
                        Duration.ofSeconds(10),
                    ) { directTo(a, b.peerId) != null && directTo(b, a.peerId) != null } shouldBe
                        true
                    identifyOver(a, b) shouldBe true
                    identifyOver(b, a) shouldBe true
                    if (a.host.network.connections.size == 1 &&
                        b.host.network.connections.size == 1
                    ) {
                        singleConnectionRounds++
                    }
                    ra.close()
                    rb.close()
                } finally {
                    runCatching { a.stop() }
                    runCatching { b.stop() }
                }
                round
            }
            // Not asserted: how often the kernel produced a true simultaneous open is not deterministic.
            println(
                "rounds ending in exactly one connection per side (simultaneous open or one lost dial): $singleConnectionRounds",
            )
        }
    })
