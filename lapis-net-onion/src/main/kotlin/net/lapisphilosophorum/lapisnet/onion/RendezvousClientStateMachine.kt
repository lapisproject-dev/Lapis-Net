package net.lapisphilosophorum.lapisnet.onion

import io.github.oshai.kotlinlogging.KotlinLogging
import java.security.SecureRandom
import java.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

private val logger = KotlinLogging.logger {}

/** Timeouts of the sender side of a rendezvous. */
data class RendezvousClientConfig(
    val rendezvousBuildTimeout: Duration = 30.seconds,
    val rendezvousEstablishTimeout: Duration = 15.seconds,
    val introBuildTimeout: Duration = 30.seconds,
    val introduceAckTimeout: Duration = 15.seconds,
    val rendezvous2Timeout: Duration = 30.seconds,
    val overallTimeout: Duration = 60.seconds,
) {
    init {
        require(
            listOf(
                rendezvousBuildTimeout,
                rendezvousEstablishTimeout,
                introBuildTimeout,
                introduceAckTimeout,
                rendezvous2Timeout,
                overallTimeout,
            ).all { it.isPositive() },
        ) { "timeouts must be positive" }
    }
}

enum class RendezvousClientState {
    NEW,
    RDV_BUILDING,
    RDV_ESTABLISHING,
    INTRO_BUILDING,
    INTRODUCING,
    AWAIT_RENDEZVOUS2,
    OPEN,
    CLOSED,
    FAILED,
}

enum class RendezvousFailure { INVALID_DESCRIPTOR, RENDEZVOUS_POINT, NO_INTRODUCTION, AUTHENTICATION, TIMEOUT }

sealed interface ClientCommand {
    class BuildCircuit(
        val ref: CircuitRef,
        val endpoint: OnionKeyBinding,
        val purpose: CircuitPurpose,
    ) : ClientCommand

    class Send(
        val ref: CircuitRef,
        val message: RelayMessage,
    ) : ClientCommand

    class Destroy(
        val ref: CircuitRef,
    ) : ClientCommand

    /** The session is open: the host owns the rendezvous circuit [ref] and [e2e] from now on. */
    class Opened(
        val ref: CircuitRef,
        val e2e: RendezvousEndToEnd,
    ) : ClientCommand

    class Failed(
        val reason: RendezvousFailure,
    ) : ClientCommand
}

/**
 * The sender side of a rendezvous as a PURE state machine:
 * `RDV_BUILDING -> RDV_ESTABLISHING -> INTRO_BUILDING -> INTRODUCING -> AWAIT_RENDEZVOUS2 -> OPEN | FAILED`.
 * On a negative INTRODUCE_ACK, a failed intro circuit or a timeout it moves on to the next introduction point
 * of the descriptor (each at most once); when all are used up, or on any other error, EVERY circuit it owns is
 * destroyed ([ClientCommand.Destroy]) and the keys are zeroised: no failure path leaves a half-open state.
 * No backoff is applied between introduction attempts in this wave (the next point is tried at once).
 */
class RendezvousClientStateMachine(
    private val address: OnionServiceAddress,
    private val descriptor: OnionServiceDescriptor,
    private val rendezvousPoint: OnionKeyBinding,
    private val config: RendezvousClientConfig,
    private val clock: Clock,
    private val random: SecureRandom,
) {
    var state = RendezvousClientState.NEW
        private set

    private var rdvRef: CircuitRef? = null
    private var introRef: CircuitRef? = null
    private var senderState: RendezvousSenderState? = null
    private val cookie = ByteArray(HsConstants.COOKIE_SIZE).also { random.nextBytes(it) }
    private var order: List<IntroPointEntry> = emptyList()
    private var nextIntro = 0
    private var nextRef = 1L
    private var deadlineMillis = 0L
    private var overallDeadlineMillis = 0L

    private fun now() = clock.millis()

    private fun ref() = CircuitRef(nextRef++)

    @Synchronized
    fun start(): List<ClientCommand> {
        check(state == RendezvousClientState.NEW) { "already started" }
        val nowSec = now() / 1000
        if (descriptor.serviceKey != address.serviceKey || !OnionServiceDescriptor.verify(descriptor, nowSec)) {
            return fail(RendezvousFailure.INVALID_DESCRIPTOR)
        }
        order = descriptor.introPoints.shuffled(random)
        senderState = RendezvousHandshake.senderStart(address, descriptor.encKey, random)
        overallDeadlineMillis = now() + config.overallTimeout.inWholeMilliseconds
        val ref = ref()
        rdvRef = ref
        state = RendezvousClientState.RDV_BUILDING
        deadlineMillis = now() + config.rendezvousBuildTimeout.inWholeMilliseconds
        return listOf(ClientCommand.BuildCircuit(ref, rendezvousPoint, CircuitPurpose.RENDEZVOUS_SENDER))
    }

    @Synchronized
    fun on(event: HsEvent): List<ClientCommand> {
        if (state == RendezvousClientState.NEW || state.isTerminal()) return emptyList()
        return when (event) {
            is HsEvent.CircuitBuilt -> onBuilt(event.ref)
            is HsEvent.CircuitFailed -> onFailed(event.ref)
            is HsEvent.RelayReceived -> onReceived(event.ref, event.message)
            HsEvent.Tick -> onTick()
        }
    }

    private fun RendezvousClientState.isTerminal() =
        this == RendezvousClientState.OPEN ||
            this == RendezvousClientState.CLOSED ||
            this == RendezvousClientState.FAILED

    private fun onBuilt(ref: CircuitRef): List<ClientCommand> {
        if (ref == rdvRef && state == RendezvousClientState.RDV_BUILDING) {
            state = RendezvousClientState.RDV_ESTABLISHING
            deadlineMillis = now() + config.rendezvousEstablishTimeout.inWholeMilliseconds
            return listOf(
                ClientCommand.Send(ref, RelayMessage(RelayCommand.ESTABLISH_RENDEZVOUS, 0, cookie.copyOf())),
            )
        }
        if (ref == introRef && state == RendezvousClientState.INTRO_BUILDING) {
            val ip = order[nextIntro - 1]
            val sender = senderState ?: return fail(RendezvousFailure.INVALID_DESCRIPTOR)
            val plaintext =
                IntroducePlaintext(
                    rendezvousPoint.relayIdDigest(),
                    rendezvousPoint.onionKeyFingerprint(),
                    cookie,
                    sender.clientEphemeral,
                ).encode(random)
            val body =
                try {
                    val (enc, ct) =
                        IntroduceCrypto.seal(
                            address.serviceIdDigest(),
                            descriptor.encKey,
                            ip.authKey,
                            plaintext,
                        )
                    IntroduceBody(ip.authKey.bytes, enc, ct).encode()
                } catch (e: OnionHandshakeException) {
                    return fail(RendezvousFailure.INVALID_DESCRIPTOR)
                } finally {
                    plaintext.fill(0)
                }
            state = RendezvousClientState.INTRODUCING
            deadlineMillis = now() + config.introduceAckTimeout.inWholeMilliseconds
            return listOf(ClientCommand.Send(ref, RelayMessage(RelayCommand.INTRODUCE1, 0, body)))
        }
        return emptyList()
    }

    private fun onFailed(ref: CircuitRef): List<ClientCommand> {
        if (ref == rdvRef) return fail(RendezvousFailure.RENDEZVOUS_POINT)
        if (ref == introRef) return nextIntroPoint()
        return emptyList()
    }

    private fun onReceived(
        ref: CircuitRef,
        msg: RelayMessage,
    ): List<ClientCommand> {
        if (ref == rdvRef) {
            val established = state == RendezvousClientState.RDV_ESTABLISHING
            val introduced = state.ordinal >= RendezvousClientState.INTRO_BUILDING.ordinal
            return when {
                msg.command == RelayCommand.RENDEZVOUS_ESTABLISHED && established -> {
                    val ok =
                        try {
                            StatusBody.decode(msg.data) == 0.toByte()
                        } catch (e: CellFormatException) {
                            false
                        }
                    if (ok) nextIntroPoint() else fail(RendezvousFailure.RENDEZVOUS_POINT)
                }
                msg.command == RelayCommand.RENDEZVOUS2 && introduced -> finish(msg.data)
                else -> fail(RendezvousFailure.RENDEZVOUS_POINT)
            }
        }
        if (ref == introRef &&
            state == RendezvousClientState.INTRODUCING &&
            msg.command == RelayCommand.INTRODUCE_ACK
        ) {
            val status =
                try {
                    StatusBody.decode(msg.data)
                } catch (e: CellFormatException) {
                    IntroduceStatus.MALFORMED
                }
            if (status == IntroduceStatus.FORWARDED) {
                val destroy = ClientCommand.Destroy(ref)
                introRef = null
                state = RendezvousClientState.AWAIT_RENDEZVOUS2
                deadlineMillis = now() + config.rendezvous2Timeout.inWholeMilliseconds
                return listOf(destroy)
            }
            return nextIntroPoint()
        }
        return emptyList()
    }

    private fun finish(payload: ByteArray): List<ClientCommand> {
        val sender = senderState ?: return fail(RendezvousFailure.AUTHENTICATION)
        senderState = null
        val e2e =
            try {
                RendezvousHandshake.senderFinish(sender, payload)
            } catch (e: OnionHandshakeException) {
                senderState = null
                return fail(RendezvousFailure.AUTHENTICATION)
            }
        val out = ArrayList<ClientCommand>()
        introRef?.let { out += ClientCommand.Destroy(it) }
        introRef = null
        state = RendezvousClientState.OPEN
        out += ClientCommand.Opened(checkNotNull(rdvRef), e2e)
        return out
    }

    private fun nextIntroPoint(): List<ClientCommand> {
        val out = ArrayList<ClientCommand>()
        introRef?.let { out += ClientCommand.Destroy(it) }
        introRef = null
        if (nextIntro >= order.size) return out + fail(RendezvousFailure.NO_INTRODUCTION)
        val ip = order[nextIntro++]
        val ref = ref()
        introRef = ref
        state = RendezvousClientState.INTRO_BUILDING
        deadlineMillis = now() + config.introBuildTimeout.inWholeMilliseconds
        out += ClientCommand.BuildCircuit(ref, ip.relayOnionKeyBinding, CircuitPurpose.INTRODUCE)
        return out
    }

    private fun onTick(): List<ClientCommand> {
        val t = now()
        if (t >= overallDeadlineMillis) return fail(RendezvousFailure.TIMEOUT)
        if (t < deadlineMillis) return emptyList()
        return when (state) {
            RendezvousClientState.RDV_BUILDING, RendezvousClientState.RDV_ESTABLISHING,
            RendezvousClientState.AWAIT_RENDEZVOUS2,
            -> fail(RendezvousFailure.TIMEOUT)
            RendezvousClientState.INTRO_BUILDING, RendezvousClientState.INTRODUCING -> nextIntroPoint()
            else -> emptyList()
        }
    }

    private fun destroyAll(): MutableList<ClientCommand> {
        val out = ArrayList<ClientCommand>()
        rdvRef?.let { out += ClientCommand.Destroy(it) }
        introRef?.let { out += ClientCommand.Destroy(it) }
        rdvRef = null
        introRef = null
        senderState?.close()
        senderState = null
        return out
    }

    private fun fail(reason: RendezvousFailure): List<ClientCommand> {
        logger.debug { "rendezvous attempt failed: $reason" }
        val out = destroyAll()
        state = RendezvousClientState.FAILED
        out += ClientCommand.Failed(reason)
        return out
    }

    /** Aborts the attempt in any state, destroying everything. Safe to call repeatedly. */
    @Synchronized
    fun cancel(): List<ClientCommand> {
        if (state.isTerminal()) return emptyList()
        val out = destroyAll()
        state = RendezvousClientState.CLOSED
        return out
    }

    /** Test seam. */
    @get:Synchronized
    internal val liveCircuitCount: Int get() = listOfNotNull(rdvRef, introRef).size
}
