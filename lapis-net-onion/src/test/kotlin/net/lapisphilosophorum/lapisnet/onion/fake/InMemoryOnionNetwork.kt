package net.lapisphilosophorum.lapisnet.onion.fake

import net.lapisphilosophorum.lapisnet.onion.BuilderStep
import net.lapisphilosophorum.lapisnet.onion.Cell
import net.lapisphilosophorum.lapisnet.onion.ClientCircuit
import net.lapisphilosophorum.lapisnet.onion.ClientCircuitBuilder
import net.lapisphilosophorum.lapisnet.onion.DestroyReason
import net.lapisphilosophorum.lapisnet.onion.LinkId
import net.lapisphilosophorum.lapisnet.onion.RelayAction
import net.lapisphilosophorum.lapisnet.onion.RelayMessage
import java.security.SecureRandom
import java.time.Clock

/** A synchronous, FIFO, deterministic in-memory "network" of [OnionRelay]s plus one client. */
class InMemoryOnionNetwork(
    val relays: List<TestRelay>,
) {
    /** A cell in transit; `null` for [fromRelay]/[toRelay] means the client. */
    class Transit(
        val fromRelay: Int?,
        val toRelay: Int?,
        val cell: Cell,
    )

    class Delivered(
        val relayIndex: Int,
        val circuitHandle: Long,
        val message: RelayMessage,
    )

    class PublishDelivered(
        val relayIndex: Int,
        val circuitHandle: Long,
        val type: net.lapisphilosophorum.lapisnet.onion.DirectoryObjectType,
        val objectBytes: ByteArray,
    )

    class Closed(
        val relayIndex: Int,
        val circuitHandle: Long,
        val reason: DestroyReason,
    )

    private class Peer(
        val relay: Int?,
        val link: LinkId?,
        val inbox: ArrayDeque<Cell>? = null,
    )

    /** An additional client with its own inbox (hidden-service tests need several). */
    class TestClient(
        val relayIndex: Int,
        val link: LinkId,
        val inbox: ArrayDeque<Cell>,
    ) {
        var circuitId = 0
    }

    /** Return the cells to actually deliver: empty drops, two duplicates, a modified copy tampers. */
    var filter: (Transit) -> List<Cell> = { listOf(it.cell) }

    val clientInbox = ArrayDeque<Cell>()
    val delivered = mutableListOf<Delivered>()

    /** DIRECTORY_PUBLISH objects handed to the host (wave V0.10.0-D). */
    val publishes = mutableListOf<PublishDelivered>()
    val mailboxItems = mutableListOf<Pair<Long, ByteArray>>()
    val closed = mutableListOf<Closed>()

    private val peers = HashMap<Pair<Int, Long>, Peer>()
    private val queue = ArrayDeque<Triple<Int, LinkId, Cell>>()
    private var nextLink = 1L

    fun connectClient(relayIndex: Int): LinkId {
        val link = LinkId(nextLink++)
        peers[relayIndex to link.value] = Peer(null, null)
        return link
    }

    fun newClient(relayIndex: Int): TestClient {
        val link = LinkId(nextLink++)
        val inbox = ArrayDeque<Cell>()
        peers[relayIndex to link.value] = Peer(null, null, inbox)
        return TestClient(relayIndex, link, inbox)
    }

    /** Builds a circuit for [client] (its first hop must be the client's relay). */
    fun buildCircuitFor(
        client: TestClient,
        path: List<Int>,
        random: SecureRandom = SecureRandom(),
        clock: Clock = FixedClock(),
    ): ClientCircuit {
        require(path[0] == client.relayIndex) { "client is attached to another relay" }
        val builder = ClientCircuitBuilder(path.map { relays[it].binding }, random, clock)
        var step: BuilderStep = BuilderStep.Send(builder.start())
        while (step is BuilderStep.Send) {
            clientSend(client.relayIndex, client.link, step.cell)
            step = builder.onCell(client.inbox.removeFirst())
        }
        check(step is BuilderStep.Built) { "circuit build failed: $step" }
        client.circuitId = builder.firstLinkCircuitId
        return step.circuit
    }

    fun clientSend(
        relayIndex: Int,
        link: LinkId,
        cell: Cell,
    ) {
        filter(Transit(null, relayIndex, cell)).forEach { queue.addLast(Triple(relayIndex, link, it)) }
        drain()
    }

    /** Applies actions produced outside [clientSend] (e.g. [OnionRelay.reply]) and drains. */
    fun apply(
        relayIndex: Int,
        actions: List<RelayAction>,
    ) {
        run(relayIndex, actions)
        drain()
    }

    private fun drain() {
        while (queue.isNotEmpty()) {
            val (to, link, cell) = queue.removeFirst()
            run(to, relays[to].relay.onCell(link, cell))
        }
    }

    private fun run(
        idx: Int,
        actions: List<RelayAction>,
    ) {
        for (a in actions) {
            when (a) {
                is RelayAction.SendCell -> {
                    val peer = peers[idx to a.link.value] ?: continue
                    filter(Transit(idx, peer.relay, a.cell)).forEach {
                        if (peer.relay ==
                            null
                        ) {
                            (peer.inbox ?: clientInbox).addLast(it)
                        } else {
                            queue.addLast(Triple(peer.relay, peer.link!!, it))
                        }
                    }
                }
                is RelayAction.OpenLinkForExtend -> {
                    val target = relays.indexOfFirst { it.binding.relayIdDigest().contentEquals(a.targetRelayIdDigest) }
                    if (target < 0) {
                        run(idx, relays[idx].relay.onExtendResult(a.pendingId, null))
                    } else {
                        val here = LinkId(nextLink++)
                        val there = LinkId(nextLink++)
                        peers[idx to here.value] = Peer(target, there)
                        peers[target to there.value] = Peer(idx, here)
                        run(idx, relays[idx].relay.onExtendResult(a.pendingId, here))
                    }
                }
                is RelayAction.DeliverLocal -> delivered += Delivered(idx, a.circuitHandle, a.message)
                is RelayAction.DeliverDirectoryPublish ->
                    publishes += PublishDelivered(idx, a.circuitHandle, a.type, a.objectBytes)
                is RelayAction.DeliverMailboxItem -> mailboxItems += a.circuitHandle to a.itemBytes
                is RelayAction.CircuitClosed -> closed += Closed(idx, a.circuitHandle, a.reason)
            }
        }
    }

    /** A client circuit built through [path] (relay indices) over this network. */
    inner class BuiltCircuit(
        val circuit: ClientCircuit,
        val entryRelay: Int,
        val link: LinkId,
        val circuitId: Int,
    )

    fun buildCircuit(
        path: List<Int>,
        random: SecureRandom = SecureRandom(),
        clock: Clock = FixedClock(),
    ): BuiltCircuit {
        val builder = ClientCircuitBuilder(path.map { relays[it].binding }, random, clock)
        val link = connectClient(path[0])
        var step: BuilderStep = BuilderStep.Send(builder.start())
        while (step is BuilderStep.Send) {
            clientSend(path[0], link, step.cell)
            step = builder.onCell(clientInbox.removeFirst())
        }
        check(step is BuilderStep.Built) { "circuit build failed: $step" }
        return BuiltCircuit(step.circuit, path[0], link, builder.firstLinkCircuitId)
    }
}
