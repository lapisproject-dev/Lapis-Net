package net.lapisphilosophorum.lapisnet.onion.fake

import net.lapisphilosophorum.lapisnet.onion.Cell
import net.lapisphilosophorum.lapisnet.onion.CellCommand
import net.lapisphilosophorum.lapisnet.onion.CircuitRef
import net.lapisphilosophorum.lapisnet.onion.ClientCircuit
import net.lapisphilosophorum.lapisnet.onion.ClientCommand
import net.lapisphilosophorum.lapisnet.onion.DestroyBody
import net.lapisphilosophorum.lapisnet.onion.DestroyReason
import net.lapisphilosophorum.lapisnet.onion.HsEvent
import net.lapisphilosophorum.lapisnet.onion.OnionIntegrityException
import net.lapisphilosophorum.lapisnet.onion.OnionKeyBinding
import net.lapisphilosophorum.lapisnet.onion.OnionServiceStateMachine
import net.lapisphilosophorum.lapisnet.onion.RelayCommand
import net.lapisphilosophorum.lapisnet.onion.RelayMessage
import net.lapisphilosophorum.lapisnet.onion.RendezvousClientStateMachine
import net.lapisphilosophorum.lapisnet.onion.RendezvousEndToEnd
import net.lapisphilosophorum.lapisnet.onion.ServiceCommand
import java.security.SecureRandom

/** One participant (service host or client) of the in-memory hidden-service tests: owns circuits by [CircuitRef]. */
class HsEndpoint(
    val net: InMemoryOnionNetwork,
    private val random: SecureRandom,
    private val clockFor: () -> java.time.Clock,
) {
    class Conn(
        val client: InMemoryOnionNetwork.TestClient,
        val circuit: ClientCircuit,
        val lastHop: Int,
    )

    val conns = HashMap<CircuitRef, Conn>()
    var onEvent: (HsEvent) -> Unit = {}
    val failedBuilds = mutableListOf<CircuitRef>()

    /** Relay indices whose circuits cannot be built (simulates dead relays). */
    val deadRelays = mutableSetOf<Int>()
    private var seq = 0

    fun indexOf(binding: OnionKeyBinding): Int =
        net.relays.indexOfFirst {
            it.binding.relayIdentity ==
                binding.relayIdentity
        }

    fun build(
        ref: CircuitRef,
        endpoint: OnionKeyBinding,
    ) {
        val end = indexOf(endpoint)
        val others = net.relays.indices.filter { it != end && it !in deadRelays }
        if (end in deadRelays || others.size < 2) {
            failedBuilds += ref
            onEvent(HsEvent.CircuitFailed(ref))
            return
        }
        val guard = others[seq++ % others.size]
        val mid = others.first { it != guard }
        val client = net.newClient(guard)
        val circuit = net.buildCircuitFor(client, listOf(guard, mid, end), random, clockFor())
        conns[ref] = Conn(client, circuit, end)
        onEvent(HsEvent.CircuitBuilt(ref))
    }

    fun send(
        ref: CircuitRef,
        msg: RelayMessage,
    ) {
        val c = conns[ref] ?: return
        net.clientSend(
            c.client.relayIndex,
            c.client.link,
            Cell(c.client.circuitId, CellCommand.RELAY, c.circuit.wrapForward(msg, random = random)),
        )
    }

    fun destroy(ref: CircuitRef) {
        val c = conns.remove(ref) ?: return
        net.clientSend(
            c.client.relayIndex,
            c.client.link,
            Cell(c.client.circuitId, CellCommand.DESTROY, DestroyBody.encode(DestroyReason.FINISHED, random)),
        )
        c.circuit.close()
    }

    /** Delivers everything waiting in the inboxes as events; `true` if anything was delivered. */
    fun pump(): Boolean {
        var any = false
        for ((ref, c) in conns.entries.toList()) {
            while (c.client.inbox.isNotEmpty() && conns.containsKey(ref)) {
                val cell = c.client.inbox.removeFirst()
                any = true
                if (cell.command == CellCommand.DESTROY) {
                    conns.remove(ref)
                    c.circuit.close()
                    onEvent(HsEvent.CircuitFailed(ref))
                } else if (cell.command == CellCommand.RELAY) {
                    try {
                        val (origin, msg) = c.circuit.unwrapBackward(cell.body)
                        if (origin == c.circuit.hopCount) onEvent(HsEvent.RelayReceived(ref, msg))
                    } catch (e: OnionIntegrityException) {
                        conns.remove(ref)
                        onEvent(HsEvent.CircuitFailed(ref))
                    }
                }
            }
        }
        return any
    }
}

/** Both ends wired to their machines over the in-memory network. */
class HsFlow(
    val net: InMemoryOnionNetwork,
    val clock: FixedClock,
    val random: SecureRandom,
) {
    val serviceEp = HsEndpoint(net, random) { clock }
    val clientEp = HsEndpoint(net, random) { clock }
    val published = mutableListOf<net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptor>()
    val accepted = mutableListOf<Pair<CircuitRef, RendezvousEndToEnd>>()
    val opened = mutableListOf<Pair<CircuitRef, RendezvousEndToEnd>>()
    val clientFailures = mutableListOf<net.lapisphilosophorum.lapisnet.onion.RendezvousFailure>()
    val neededRelay = mutableListOf<Int>()

    /** Every relay-message body either machine asked to send (for log-hygiene searches). */
    val sent = mutableListOf<ByteArray>()
    lateinit var service: OnionServiceStateMachine
    var client: RendezvousClientStateMachine? = null

    fun runService(cmds: List<ServiceCommand>) {
        for (c in cmds) {
            when (c) {
                is ServiceCommand.BuildCircuit -> serviceEp.build(c.ref, c.endpoint)
                is ServiceCommand.SendRelay -> {
                    sent += c.message.data
                    serviceEp.send(c.ref, c.message)
                }
                is ServiceCommand.Destroy -> serviceEp.destroy(c.ref)
                is ServiceCommand.Publish -> published += c.descriptor
                is ServiceCommand.NeedIntroRelay -> neededRelay += c.slot
                is ServiceCommand.Accepted -> accepted += c.ref to c.e2e
            }
        }
    }

    fun runClient(cmds: List<ClientCommand>) {
        for (c in cmds) {
            when (c) {
                is ClientCommand.BuildCircuit -> clientEp.build(c.ref, c.endpoint)
                is ClientCommand.Send -> {
                    sent += c.message.data
                    clientEp.send(c.ref, c.message)
                }
                is ClientCommand.Destroy -> clientEp.destroy(c.ref)
                is ClientCommand.Opened -> opened += c.ref to c.e2e
                is ClientCommand.Failed -> clientFailures += c.reason
            }
        }
    }

    val serviceData = mutableListOf<Pair<CircuitRef, ByteArray>>()
    val clientData = mutableListOf<Pair<CircuitRef, ByteArray>>()

    fun wire() {
        serviceEp.onEvent = { ev ->
            if (ev is HsEvent.RelayReceived && ev.message.command == RelayCommand.RENDEZVOUS_DATA) {
                serviceData += ev.ref to ev.message.data
            } else {
                runService(service.on(ev))
            }
        }
        clientEp.onEvent = { ev ->
            if (ev is HsEvent.RelayReceived && ev.message.command == RelayCommand.RENDEZVOUS_DATA) {
                clientData += ev.ref to ev.message.data
            } else {
                client?.let { runClient(it.on(ev)) }
            }
        }
    }

    /** Pumps both endpoints until nothing moves any more. */
    fun settle(maxRounds: Int = 200) {
        repeat(maxRounds) {
            val a = serviceEp.pump()
            val b = clientEp.pump()
            if (!a && !b) return
        }
    }

    fun tick(
        millis: Long = 1000,
        times: Int = 1,
    ) {
        repeat(times) {
            clock.advanceMillis(millis)
            runService(service.on(HsEvent.Tick))
            client?.let { runClient(it.on(HsEvent.Tick)) }
            settle()
        }
    }
}
