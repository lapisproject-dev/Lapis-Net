package net.lapisphilosophorum.lapisnet.networking.transport

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.Connection
import io.libp2p.core.PeerId
import io.libp2p.core.multiformats.Multiaddr
import io.libp2p.protocol.IdentifyController
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.networking.awaitTrue
import net.lapisphilosophorum.lapisnet.networking.dcutr.HolePunchConfig
import net.lapisphilosophorum.lapisnet.networking.dcutr.HolePunchMode
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.time.Duration
import java.util.concurrent.TimeUnit

internal fun punchNode(): LapisNode =
    LapisNode.create(
        DualKeyIdentity.generate(),
        holePunchConfig = HolePunchConfig(mode = HolePunchMode.ON, allowNonPublicAddresses = true),
    )

internal fun listenPort(node: LapisNode): Int =
    node.punchTransport!!
        .boundListenAddresses()
        .first()
        .port

internal fun listenAddress(node: LapisNode): InetSocketAddress =
    InetSocketAddress(InetAddress.getByName("127.0.0.1"), listenPort(node))

internal fun directTo(
    node: LapisNode,
    peer: PeerId,
): Connection? =
    node.host.network.connections
        .firstOrNull { it.secureSession().remoteId == peer && !it.closeFuture().isDone }

class ReusePortTcpTransportTest :
    FunSpec({
        test("an ordinary dial and listen between two nodes works with the reuse-port transport") {
            if (!ReusePortSupport.available) return@test
            val a = punchNode()
            val b = punchNode()
            try {
                a.start()
                b.start()
                val connection = a.connect(io.libp2p.core.PeerInfo(b.peerId, b.directListenAddresses()))
                connection.secureSession().remoteId shouldBe b.peerId
                awaitTrue(Duration.ofSeconds(10)) { directTo(b, a.peerId) != null } shouldBe true
                val id =
                    a.host
                        .newStream<IdentifyController>(listOf("/ipfs/id/1.0.0"), connection)
                        .controller
                        .get(10, TimeUnit.SECONDS)
                        .id()
                        .get(10, TimeUnit.SECONDS)
                (id != null) shouldBe true
            } finally {
                runCatching { a.stop() }
                runCatching { b.stop() }
            }
        }

        test("an outgoing dial leaves from the listener port") {
            if (!ReusePortSupport.available) return@test
            val a = punchNode()
            val b = punchNode()
            try {
                a.start()
                b.start()
                a.connect(io.libp2p.core.PeerInfo(b.peerId, b.directListenAddresses()))
                awaitTrue(Duration.ofSeconds(10)) { directTo(b, a.peerId) != null } shouldBe true
                val seenByB = directTo(b, a.peerId)!!.remoteAddress().toString()
                seenByB.contains("/tcp/${listenPort(a)}") shouldBe true
            } finally {
                runCatching { a.stop() }
                runCatching { b.stop() }
            }
        }

        test("a second dial to the same target falls back to an ephemeral port instead of failing") {
            if (!ReusePortSupport.available) return@test
            val a = punchNode()
            val b = punchNode()
            try {
                a.start()
                b.start()
                val transport = a.punchTransport!!
                val target = b.directListenAddresses().first().withP2P(b.peerId)
                val handler = a.host.network.connectionHandler
                val first = transport.dial(target, handler, null).get(10, TimeUnit.SECONDS)
                val second = transport.dial(target, handler, null).get(10, TimeUnit.SECONDS)
                first.secureSession().remoteId shouldBe b.peerId
                second.secureSession().remoteId shouldBe b.peerId
                (first !== second) shouldBe true
            } finally {
                runCatching { a.stop() }
                runCatching { b.stop() }
            }
        }

        test("a strict punch dial does not fall back: the bind collision is reported as a lost race") {
            if (!ReusePortSupport.available) return@test
            val a = punchNode()
            val b = punchNode()
            try {
                a.start()
                b.start()
                val transport = a.punchTransport!!
                val first = transport.punchDial(listenAddress(b), b.peerId, true).get(10, TimeUnit.SECONDS)
                first.secureSession().remoteId shouldBe b.peerId
                val second =
                    runCatching { transport.punchDial(listenAddress(b), b.peerId, true).get(10, TimeUnit.SECONDS) }
                (second.exceptionOrNull()?.cause is PunchDialLost) shouldBe true
            } finally {
                runCatching { a.stop() }
                runCatching { b.stop() }
            }
        }

        test("stop releases the listener port and is idempotent") {
            if (!ReusePortSupport.available) return@test
            val a = punchNode()
            a.start()
            val port = listenPort(a)
            val transport = a.punchTransport!!
            a.stop()
            transport.close().get(10, TimeUnit.SECONDS)
            transport.close().get(10, TimeUnit.SECONDS)
            transport.activeListeners shouldBe 0
            // Rebinding the port without any reuse option proves nobody holds it any more.
            ServerSocket(port, 1, InetAddress.getByName("127.0.0.1")).use { it.localPort shouldBe port }
        }

        test("handles(): tcp over ip or dns, but not websocket, udp or circuit addresses") {
            if (!ReusePortSupport.available) return@test
            val a = punchNode()
            try {
                val t = a.punchTransport!!
                t.handles(Multiaddr("/ip4/1.2.3.4/tcp/1")) shouldBe true
                t.handles(Multiaddr("/ip6/::1/tcp/1")) shouldBe true
                t.handles(Multiaddr("/dns4/example.com/tcp/1")) shouldBe true
                t.handles(Multiaddr("/ip4/1.2.3.4/tcp/1/ws")) shouldBe false
                t.handles(Multiaddr("/ip4/1.2.3.4/udp/1")) shouldBe false
                t.handles(Multiaddr("/ip4/1.2.3.4/tcp/1/p2p-circuit")) shouldBe false
            } finally {
                runCatching { a.stop() }
            }
        }
    })
