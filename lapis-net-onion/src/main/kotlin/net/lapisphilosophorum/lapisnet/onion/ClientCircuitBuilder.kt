package net.lapisphilosophorum.lapisnet.onion

import net.lapisphilosophorum.lapisnet.onion.OnionConstants.MAX_HOPS
import net.lapisphilosophorum.lapisnet.onion.OnionConstants.MAX_LINK_SPECIFIER
import java.security.SecureRandom
import java.time.Clock

/** Result of feeding a cell to a [ClientCircuitBuilder]. */
sealed interface BuilderStep {
    /** Send [cell] to the FIRST hop's link. */
    class Send(
        val cell: Cell,
    ) : BuilderStep

    /** The circuit is complete. */
    class Built(
        val circuit: ClientCircuit,
    ) : BuilderStep

    /**
     * Building failed; everything was zeroised. If [destroyCell] is non-null the host MUST send it
     * to the FIRST hop's link so the relays release their circuit state; it is null when the peer
     * itself ended the circuit with DESTROY (nothing to tear down).
     */
    class Failed(
        val reason: DestroyReason,
        val destroyCell: Cell? = null,
    ) : BuilderStep

    /** The cell was not addressed to this build (PADDING or another circuit); nothing changed. */
    data object Ignored : BuilderStep
}

/**
 * Drives CREATE -> EXTEND -> EXTEND ... for a path, purely through cells (no I/O). Usage: call
 * [start], send the cell to hop 1's link, feed every cell received from that link into [onCell]
 * until it returns [BuilderStep.Built] or [BuilderStep.Failed]. Cells that are not for this build
 * (PADDING, other circuits on the same link) yield [BuilderStep.Ignored]. On [BuilderStep.Failed]
 * the host must send its `destroyCell` (if any); after an early [abort] it must send the returned cell.
 *
 * Path rules: 1..[MAX_HOPS] hops; every onion key binding must verify and be unexpired; no relay
 * identity may appear twice (this is the path-level loop/predecessor check - relays cannot do it
 * because they do not know their neighbours' identities).
 */
class ClientCircuitBuilder(
    private val path: List<OnionKeyBinding>,
    private val random: SecureRandom = SecureRandom(),
    clock: Clock = Clock.systemUTC(),
    linkSpecifiers: List<ByteArray> = path.map { ByteArray(0) },
) : AutoCloseable {
    private val specs = linkSpecifiers.map { it.copyOf() }
    private val circuit = ClientCircuit()
    private var state: NtorClientState? = null
    private var circuitId = 0
    private var started = false
    private var finished = false

    init {
        require(path.size in 1..MAX_HOPS) { "path must have 1..$MAX_HOPS hops" }
        require(specs.size == path.size) { "one link specifier per hop is required" }
        require(specs.all { it.size <= MAX_LINK_SPECIFIER }) { "link specifier too long" }
        val now = clock.instant().epochSecond
        require(path.all { OnionKeyBinding.verify(it, now) }) { "invalid or expired onion key binding in path" }
        require(path.map { it.relayIdentity }.toSet().size == path.size) { "relay appears twice in path" }
    }

    /** The first CREATE cell. */
    fun start(): Cell {
        check(!started) { "already started" }
        started = true
        while (circuitId == 0) circuitId = random.nextInt()
        val (st, create) = NtorHandshake.clientStart(path[0], 1, random)
        state = st
        return Cell(circuitId, CellCommand.CREATE, create.encode(random))
    }

    fun onCell(cell: Cell): BuilderStep {
        check(started && !finished) { "not building" }
        if (cell.circuitId != circuitId || cell.command == CellCommand.PADDING) return BuilderStep.Ignored
        return try {
            when (cell.command) {
                CellCommand.CREATED -> {
                    if (circuit.hopCount != 0) return fail(DestroyReason.PROTOCOL)
                    complete(CreatedBody.decode(cell.body))
                }
                CellCommand.RELAY -> {
                    if (circuit.hopCount == 0) return fail(DestroyReason.PROTOCOL)
                    val (origin, msg) = circuit.unwrapBackward(cell.body)
                    if (origin != circuit.hopCount || msg.command != RelayCommand.EXTENDED) {
                        return fail(DestroyReason.PROTOCOL)
                    }
                    complete(CreatedBody.fromExtendedPayload(msg.data))
                }
                CellCommand.DESTROY -> fail(DestroyBody.decode(cell.body), notifyPeer = false)
                CellCommand.PADDING -> BuilderStep.Ignored
                CellCommand.CREATE -> fail(DestroyReason.PROTOCOL)
            }
        } catch (e: OnionHandshakeException) {
            fail(DestroyReason.AUTH_FAILED)
        } catch (e: OnionIntegrityException) {
            fail(DestroyReason.AUTH_FAILED)
        } catch (e: CellFormatException) {
            fail(DestroyReason.PROTOCOL)
        }
    }

    private fun complete(created: CreatedBody): BuilderStep {
        val st = state ?: return fail(DestroyReason.PROTOCOL)
        state = null
        val keys = NtorHandshake.clientFinish(st, created)
        circuit.addHop(keys)
        val built = circuit.hopCount
        if (built == path.size) {
            finished = true
            return BuilderStep.Built(circuit)
        }
        // Extend to hop built+1 through the current last hop.
        val next = path[built]
        val (nextState, create) = NtorHandshake.clientStart(next, built + 1, random)
        state = nextState
        val payload =
            ExtendPayload(
                built + 1,
                create.relayIdDigest,
                create.onionKeyFingerprint,
                create.clientEphemeral,
                specs[built],
            )
        val body =
            circuit.wrapForward(
                RelayMessage(RelayCommand.EXTEND, 0, ExtendPayloadCodec.encode(payload)),
                built,
                random,
            )
        return BuilderStep.Send(Cell(circuitId, CellCommand.RELAY, body))
    }

    private fun fail(
        reason: DestroyReason,
        notifyPeer: Boolean = true,
    ): BuilderStep {
        finished = true
        state?.close()
        state = null
        circuit.close()
        val destroy =
            if (notifyPeer) Cell(circuitId, CellCommand.DESTROY, DestroyBody.encode(reason, random)) else null
        return BuilderStep.Failed(reason, destroy)
    }

    /**
     * Aborts an unfinished build, zeroises everything and returns the DESTROY cell the host must
     * send to the first hop's link (null if nothing was started or the build already ended).
     */
    fun abort(): Cell? {
        if (!started || finished) {
            close()
            return null
        }
        return (fail(DestroyReason.FINISHED) as BuilderStep.Failed).destroyCell
    }

    override fun close() {
        state?.close()
        state = null
        if (!finished) circuit.close()
    }

    /** Circuit id on the first link (valid after [start]). */
    val firstLinkCircuitId: Int get() = circuitId
}
