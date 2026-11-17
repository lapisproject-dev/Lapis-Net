package net.lapisphilosophorum.lapisnet.onionwire

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.libp2p.core.PeerInfo
import net.lapisphilosophorum.lapisnet.directory.DirectoryAnonymityMode
import net.lapisphilosophorum.lapisnet.directory.ONION_RELAY_DIRECTORY_PROTOCOL_ID
import net.lapisphilosophorum.lapisnet.directory.OnionRelayDirectoryClient
import net.lapisphilosophorum.lapisnet.directory.RelayDirectoryFetchResult
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import java.time.Duration
import java.util.concurrent.TimeUnit

/** Wave V0.10.0-J1b: `/lapis/onion-relay-directory/1.0.0` between real loopback nodes. */
class RelayDirectoryProtocolTest :
    FunSpec({
        val all = ArrayList<AutoCloseable>()
        afterSpec { all.asReversed().forEach { runCatching { it.close() } } }

        val relay = WireTestNode(relay = true).also { all += it }
        val server = WireTestNode(relay = false).also { all += it }
        server.connectTo(relay)
        val asker = LapisNode.create(DualKeyIdentity.generate(), mdnsEnabled = false).also { it.start() }
        all += AutoCloseable { asker.stop() }

        test("mode off answers exactly one protocol more than before (Q10); anonymity mode answers none of it") {
            val ids =
                server.node.host
                    .getProtocols()
                    .flatMap { it.protocolDescriptor.announceProtocols }
                    .toSet()
            (ONION_RELAY_DIRECTORY_PROTOCOL_ID in ids) shouldBe true
            val anonymous = WireTestNode(relay = false, directoryMode = DirectoryAnonymityMode.ON).also { all += it }
            val anonIds =
                anonymous.node.host
                    .getProtocols()
                    .flatMap { it.protocolDescriptor.announceProtocols }
                    .toSet()
            (ONION_RELAY_DIRECTORY_PROTOCOL_ID in anonIds) shouldBe false
            // the only difference between the two protocol sets of the wire is the snapshot server (and the anonymous
            // mailbox topic is gossip, not a protocol id)
            (ids - anonIds) shouldBe setOf(ONION_RELAY_DIRECTORY_PROTOCOL_ID)
        }

        test("a fetch returns the relay descriptor the serving node holds") {
            awaitTrue(Duration.ofSeconds(60)) { server.wire.descriptors.size() >= 1 } shouldBe true
            val conn = asker.connect(PeerInfo(server.node.peerId, server.node.listenAddresses()))
            val result = OnionRelayDirectoryClient().fetch(conn).get(20, TimeUnit.SECONDS)
            val ok = result.shouldBeInstanceOf<RelayDirectoryFetchResult.Ok>()
            ok.snapshot.entries.map { it.descriptor.identity } shouldBe listOf(relay.key)
        }

        test("a node without the server answers Unsupported") {
            val anonymous = WireTestNode(relay = false, directoryMode = DirectoryAnonymityMode.ON).also { all += it }
            val conn = anonymous.node.connect(PeerInfo(server.node.peerId, server.node.listenAddresses()))
            conn.secureSession().remoteId shouldBe server.node.peerId
            val back = asker.connect(PeerInfo(anonymous.node.peerId, anonymous.node.listenAddresses()))
            OnionRelayDirectoryClient().fetch(back).get(20, TimeUnit.SECONDS) shouldBe
                RelayDirectoryFetchResult.Unsupported
        }

        test("the per-peer limit refuses the third request within ten minutes, without an answer") {
            val conn = asker.connect(PeerInfo(server.node.peerId, server.node.listenAddresses()))
            // the second test already used one of the two
            OnionRelayDirectoryClient()
                .fetch(
                    conn,
                ).get(20, TimeUnit.SECONDS)
                .shouldBeInstanceOf<RelayDirectoryFetchResult.Ok>()
            val third = OnionRelayDirectoryClient().fetch(conn).get(20, TimeUnit.SECONDS)
            (third is RelayDirectoryFetchResult.Ok) shouldBe false
            (server.wire.relayDirectoryServer!!.refusedCount >= 1) shouldBe true
        }
    })
