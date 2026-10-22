package net.lapisphilosophorum.lapisnet.onion.fake

import net.lapisphilosophorum.lapisnet.onion.Cell
import net.lapisphilosophorum.lapisnet.onion.CellCommand
import net.lapisphilosophorum.lapisnet.onion.DestroyBody
import net.lapisphilosophorum.lapisnet.onion.DestroyReason
import net.lapisphilosophorum.lapisnet.onion.RelayCommand
import net.lapisphilosophorum.lapisnet.onion.RelayMessage
import java.security.SecureRandom

/** A one-hop client circuit on relay [idx]: the relay is the LAST hop, so role messages can be sent to it directly. */
class Probe(
    val net: InMemoryOnionNetwork,
    clock: FixedClock,
    val idx: Int = 0,
) {
    val client = net.newClient(idx)
    val circuit = net.buildCircuitFor(client, listOf(idx), SecureRandom(), clock)
    var destroyed = false
        private set
    var destroyReason: DestroyReason? = null
        private set

    fun send(
        cmd: RelayCommand,
        data: ByteArray,
        hop: Int = circuit.hopCount,
    ): List<RelayMessage> {
        net.clientSend(
            idx,
            client.link,
            Cell(client.circuitId, CellCommand.RELAY, circuit.wrapForward(RelayMessage(cmd, 0, data), hop)),
        )
        return drain()
    }

    /** Sends a DESTROY from the client side. */
    fun close() {
        net.clientSend(
            idx,
            client.link,
            Cell(client.circuitId, CellCommand.DESTROY, DestroyBody.encode(DestroyReason.FINISHED)),
        )
    }

    fun drain(): List<RelayMessage> {
        val out = mutableListOf<RelayMessage>()
        while (client.inbox.isNotEmpty()) {
            val cell = client.inbox.removeFirst()
            if (cell.command == CellCommand.DESTROY) {
                destroyed = true
                destroyReason = DestroyBody.decode(cell.body)
            } else if (cell.command == CellCommand.RELAY) {
                out += circuit.unwrapBackward(cell.body).second
            }
        }
        return out
    }
}
