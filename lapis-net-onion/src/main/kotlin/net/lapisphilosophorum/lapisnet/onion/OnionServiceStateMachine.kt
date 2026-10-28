package net.lapisphilosophorum.lapisnet.onion

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

private val logger = KotlinLogging.logger {}

/** Tunables of an onion service (receiver side). Defaults are assumptions awaiting confirmation. */
data class OnionServiceConfig(
    val introPoints: Int = 3,
    val descriptorTtl: Duration = 3.hours,
    val republishInterval: Duration = 1.hours,
    /** Intro circuits are replaced before the relays' circuit lifetime sweep (10 minutes) closes them. */
    val introCircuitRefreshAfter: Duration = 8.minutes,
    val buildTimeout: Duration = 30.seconds,
    val establishTimeout: Duration = 15.seconds,
    val backoffInitial: Duration = 1.seconds,
    val backoffMax: Duration = 60.seconds,
    val maxConsecutiveFailuresPerSlot: Int = 5,
    val maxConcurrentRendezvous: Int = 16,
    /** Upper bound on simultaneously open (accepted) rendezvous sessions; further accepted sessions are closed at once. */
    val maxOpenSessions: Int = 256,
    val introduce2PerSecond: Int = 5,
    val replayCacheEntries: Int = 8192,
    val encKeyRotation: Duration = 24.hours,
    /** Validity window of an ESTABLISH_INTRO signature (the relay accepts at most one hour). */
    val establishWindow: Duration = 15.minutes,
) {
    init {
        require(introPoints in 1..OnionServiceDescriptor.MAX_INTRO_POINTS) { "introPoints out of range" }
        require(descriptorTtl.isPositive() && republishInterval.isPositive() && republishInterval < descriptorTtl) {
            "descriptor times inconsistent"
        }
        require(
            descriptorTtl.inWholeSeconds <= OnionServiceDescriptor.MAX_TTL_WINDOW_SECONDS,
        ) { "descriptorTtl too long" }
        require(introCircuitRefreshAfter.isPositive() && buildTimeout.isPositive() && establishTimeout.isPositive()) {
            "timeouts must be positive"
        }
        require(backoffInitial.isPositive() && backoffMax >= backoffInitial) { "backoff inconsistent" }
        require(maxConsecutiveFailuresPerSlot > 0 && maxConcurrentRendezvous > 0) { "limits must be positive" }
        require(introduce2PerSecond > 0 && replayCacheEntries > 0 && maxOpenSessions > 0) { "limits must be positive" }
        require(encKeyRotation.isPositive() && encKeyRotation >= descriptorTtl) { "rotation must be at least the TTL" }
        require(
            establishWindow.isPositive() && establishWindow.inWholeSeconds <= HsConstants.MAX_ESTABLISH_WINDOW_SECONDS,
        ) {
            "establishWindow out of range"
        }
    }
}

/** Output of [OnionServiceStateMachine]; the host performs the effects. */
sealed interface ServiceCommand {
    class BuildCircuit(
        val ref: CircuitRef,
        val endpoint: OnionKeyBinding,
        val purpose: CircuitPurpose,
    ) : ServiceCommand

    /** Send [message] to the LAST hop of the circuit [ref]. */
    class SendRelay(
        val ref: CircuitRef,
        val message: RelayMessage,
    ) : ServiceCommand

    class Destroy(
        val ref: CircuitRef,
    ) : ServiceCommand

    class Publish(
        val descriptor: OnionServiceDescriptor,
    ) : ServiceCommand

    /** The slot failed repeatedly: the host must supply another introduction relay via [OnionServiceStateMachine.supplyIntroRelay]. */
    class NeedIntroRelay(
        val slot: Int,
    ) : ServiceCommand

    /** The rendezvous circuit [ref] has sent RENDEZVOUS1; the host owns the circuit and [e2e] from now on. */
    class Accepted(
        val ref: CircuitRef,
        val e2e: RendezvousEndToEnd,
    ) : ServiceCommand
}

/** Counters of dropped work, for tests and diagnostics. Never contains identifiers. */
class ServiceStats {
    @Volatile var rateLimited = 0

    @Volatile var concurrencyLimited = 0

    @Volatile var malformed = 0

    @Volatile var replays = 0

    @Volatile var cacheFull = 0

    @Volatile var unknownRendezvousPoint = 0

    @Volatile var accepted = 0
}

/**
 * The receiver side of an onion service as a PURE state machine (no I/O, injected clock and randomness).
 * The host builds the circuits the machine asks for and feeds it [HsEvent]s; every call returns the
 * [ServiceCommand]s to execute. Thread-safe by monitor.
 *
 * Per introduction slot: `build -> ESTABLISH_INTRO -> INTRO_ESTABLISHED`, proactive refresh before the
 * relay's circuit lifetime ends (a NEW circuit registers the SAME auth key with a larger `establishSeq`,
 * then the old one is destroyed: make-before-break), exponential backoff with jitter on failure, and a
 * replacement relay after repeated failures. The descriptor is published once every slot is established
 * and again on every change of the set of introduction points and every `republishInterval`.
 *
 * INTRODUCE2 handling order (cheapest first, nothing expensive before the rate limit): token bucket,
 * concurrency cap, replay-cache lookup, HPKE open, cache insert (only after a successful open, so garbage
 * cannot fill the cache), resolution of the rendezvous point, ntor response. Anything wrong is dropped
 * silently (counted) so no oracle exists.
 */
class OnionServiceStateMachine(
    private val serviceKey: Ed25519KeyPair,
    private val config: OnionServiceConfig,
    private val clock: Clock,
    private val random: SecureRandom,
    /** Resolves the rendezvous point named in an INTRODUCE from the local relay index; `null` means unknown. */
    private val resolveRelay: (relayIdDigest: ByteArray, onionKeyFingerprint: ByteArray) -> OnionKeyBinding?,
) : AutoCloseable {
    private enum class Phase { BUILDING, ESTABLISHING }

    private class Slot(
        val index: Int,
    ) {
        var relay: OnionKeyBinding? = null
        var authKey: Ed25519KeyPair? = null
        var seq = 0L
        var ref: CircuitRef? = null
        var establishedAtMillis = 0L
        var buildRef: CircuitRef? = null
        var buildPhase = Phase.BUILDING
        var buildDeadlineMillis = 0L
        var failures = 0
        var backoffUntilMillis = 0L
        var needsRelayAnnounced = false
    }

    private class EncKeyGeneration(
        val pair: X25519KeyPair,
        val createdAtMillis: Long,
        capacity: Int,
    ) {
        val cache = HashSet<ByteBuffer>()
        val capacity = capacity
        var acceptUntilMillis = Long.MAX_VALUE
    }

    private class PendingRendezvous(
        val cookie: ByteArray,
        val reply: RendezvousReply,
        val e2e: RendezvousEndToEnd,
        val deadlineMillis: Long,
    )

    val stats = ServiceStats()
    private val address = OnionServiceAddress(serviceKey.publicKey)
    private val serviceId = address.serviceIdDigest()
    private val slots = List(config.introPoints) { Slot(it) }
    private var current = newGeneration()
    private var previous: EncKeyGeneration? = null
    private val pending = HashMap<CircuitRef, PendingRendezvous>()
    private val introduceBucket = TokenBucket(config.introduce2PerSecond, clock)
    private var nextRef = 1L
    private var lastDescriptorSeq = -1L
    private var lastPublishMillis = Long.MIN_VALUE
    private var dirty = true
    private var started = false
    private var stopped = false

    val onionAddress: OnionServiceAddress get() = address

    private fun now() = clock.millis()

    private fun newRef() = CircuitRef(nextRef++)

    private fun newGeneration() = EncKeyGeneration(X25519KeyPair.generate(random), now(), config.replayCacheEntries)

    /** Starts building the introduction circuits to (at most `introPoints` of) [introRelays]. */
    @Synchronized
    fun start(introRelays: List<OnionKeyBinding>): List<ServiceCommand> {
        check(!started && !stopped) { "already started" }
        require(introRelays.size >= slots.size) { "not enough introduction relays" }
        require(
            introRelays.map { it.relayIdentity }.toSet().size == introRelays.size,
        ) { "duplicate introduction relay" }
        started = true
        val out = ArrayList<ServiceCommand>()
        slots.forEachIndexed { i, s ->
            assignRelay(s, introRelays[i])
            startBuild(s, out)
        }
        return out
    }

    /** Provides the replacement relay requested by [ServiceCommand.NeedIntroRelay]. */
    @Synchronized
    fun supplyIntroRelay(
        slot: Int,
        relay: OnionKeyBinding,
    ): List<ServiceCommand> {
        if (stopped) return emptyList()
        val s = slots[slot]
        if (slots.any { it !== s && it.relay?.relayIdentity == relay.relayIdentity }) return emptyList()
        val out = ArrayList<ServiceCommand>()
        s.ref?.let { out += ServiceCommand.Destroy(it) }
        s.ref = null
        s.buildRef?.let { out += ServiceCommand.Destroy(it) }
        s.buildRef = null
        assignRelay(s, relay)
        s.failures = 0
        s.backoffUntilMillis = 0
        s.needsRelayAnnounced = false
        dirty = true
        startBuild(s, out)
        return out
    }

    private fun assignRelay(
        s: Slot,
        relay: OnionKeyBinding,
    ) {
        s.relay = relay
        s.authKey = Ed25519KeyPair.generate(random)
        s.seq = 0
    }

    private fun startBuild(
        s: Slot,
        out: MutableList<ServiceCommand>,
    ) {
        val relay = s.relay ?: return
        val ref = newRef()
        s.buildRef = ref
        s.buildPhase = Phase.BUILDING
        s.buildDeadlineMillis = now() + config.buildTimeout.inWholeMilliseconds
        out += ServiceCommand.BuildCircuit(ref, relay, CircuitPurpose.INTRO)
    }

    @Synchronized
    fun on(event: HsEvent): List<ServiceCommand> {
        if (stopped || !started) return emptyList()
        val out = ArrayList<ServiceCommand>()
        when (event) {
            is HsEvent.CircuitBuilt -> onBuilt(event.ref, out)
            is HsEvent.CircuitFailed -> onFailed(event.ref, out)
            is HsEvent.RelayReceived -> onReceived(event.ref, event.message, out)
            HsEvent.Tick -> onTick(out)
        }
        return out
    }

    private fun slotOfBuild(ref: CircuitRef) = slots.firstOrNull { it.buildRef == ref }

    private fun slotOfRef(ref: CircuitRef) = slots.firstOrNull { it.ref == ref }

    private fun onBuilt(
        ref: CircuitRef,
        out: MutableList<ServiceCommand>,
    ) {
        val s = slotOfBuild(ref)
        if (s != null && s.buildPhase == Phase.BUILDING) {
            val relay = s.relay
            val auth = s.authKey
            if (relay == null || auth == null) {
                out += ServiceCommand.Destroy(ref)
                s.buildRef = null
                return
            }
            s.seq += 1
            val nva = now() / 1000 + config.establishWindow.inWholeSeconds
            val body = EstablishIntroBody.create(auth, relay.relayIdDigest(), nva, s.seq)
            s.buildPhase = Phase.ESTABLISHING
            s.buildDeadlineMillis = now() + config.establishTimeout.inWholeMilliseconds
            out += ServiceCommand.SendRelay(ref, RelayMessage(RelayCommand.ESTABLISH_INTRO, 0, body.encode()))
            return
        }
        val p = pending[ref]
        if (p != null) {
            pending.remove(ref)
            val body = Rendezvous1Body(p.cookie, p.reply.serverEphemeral, p.reply.auth)
            stats.accepted++
            out += ServiceCommand.SendRelay(ref, RelayMessage(RelayCommand.RENDEZVOUS1, 0, body.encode()))
            out += ServiceCommand.Accepted(ref, p.e2e)
        }
    }

    private fun onFailed(
        ref: CircuitRef,
        out: MutableList<ServiceCommand>,
    ) {
        val p = pending.remove(ref)
        if (p != null) {
            p.e2e.close()
            out += ServiceCommand.Destroy(ref)
            return
        }
        val b = slotOfBuild(ref)
        if (b != null) {
            failBuild(b, out)
            return
        }
        val s = slotOfRef(ref) ?: return
        out += ServiceCommand.Destroy(ref)
        s.ref = null
        dirty = true
        if (s.buildRef == null) s.backoffUntilMillis = now()
    }

    private fun failBuild(
        s: Slot,
        out: MutableList<ServiceCommand>,
    ) {
        s.buildRef?.let { out += ServiceCommand.Destroy(it) }
        s.buildRef = null
        s.failures++
        s.backoffUntilMillis = now() + backoffMillis(s.failures)
        if (s.failures >= config.maxConsecutiveFailuresPerSlot && s.ref == null && !s.needsRelayAnnounced) {
            s.needsRelayAnnounced = true
            s.relay = null
            out += ServiceCommand.NeedIntroRelay(s.index)
        }
    }

    /** Exponential backoff with jitter in `[base/2, base]`. */
    internal fun backoffMillis(failures: Int): Long {
        val initial = config.backoffInitial.inWholeMilliseconds
        val max = config.backoffMax.inWholeMilliseconds
        val shift = (failures - 1).coerceIn(0, 30)
        val base = minOf(max, initial shl shift)
        return base / 2 + (random.nextDouble() * (base - base / 2 + 1)).toLong().coerceAtMost(base - base / 2)
    }

    private fun onReceived(
        ref: CircuitRef,
        msg: RelayMessage,
        out: MutableList<ServiceCommand>,
    ) {
        val building = slotOfBuild(ref)
        if (building != null) {
            if (building.buildPhase == Phase.ESTABLISHING && msg.command == RelayCommand.INTRO_ESTABLISHED) {
                val ok =
                    try {
                        StatusBody.decode(msg.data) == 0.toByte()
                    } catch (e: CellFormatException) {
                        false
                    }
                if (ok) established(building, ref, out) else failBuild(building, out)
            } else {
                failBuild(building, out)
            }
            return
        }
        val s = slotOfRef(ref) ?: return
        if (msg.command == RelayCommand.INTRODUCE2) {
            onIntroduce2(s, msg.data, out)
        } else if (msg.command != RelayCommand.DROP) {
            logger.debug { "unexpected message on an introduction circuit" }
        }
    }

    private fun established(
        s: Slot,
        ref: CircuitRef,
        out: MutableList<ServiceCommand>,
    ) {
        val old = s.ref
        if (old != null) out += ServiceCommand.Destroy(old) else dirty = true
        s.ref = ref
        s.buildRef = null
        s.establishedAtMillis = now()
        s.failures = 0
        s.backoffUntilMillis = 0
    }

    private fun onIntroduce2(
        s: Slot,
        data: ByteArray,
        out: MutableList<ServiceCommand>,
    ) {
        if (!introduceBucket.tryAcquire()) {
            stats.rateLimited++
            return
        }
        if (pending.size >= config.maxConcurrentRendezvous) {
            stats.concurrencyLimited++
            return
        }
        val body =
            try {
                IntroduceBody.decode(data)
            } catch (e: CellFormatException) {
                stats.malformed++
                return
            }
        val auth = s.authKey ?: return
        if (!body.authKeyBytes.contentEquals(auth.publicKey.bytes)) {
            stats.malformed++
            return
        }
        val enc = ByteBuffer.wrap(body.hpkeEnc)
        var plaintext: ByteArray? = null
        var used: EncKeyGeneration? = null
        for (gen in listOfNotNull(current, previous)) {
            if (gen.cache.contains(enc)) {
                stats.replays++
                return
            }
            if (gen.cache.size >= gen.capacity) {
                stats.cacheFull++
                return
            }
            try {
                plaintext =
                    IntroduceCrypto.open(
                        serviceId,
                        gen.pair.privateKey,
                        gen.pair.publicKey,
                        auth.publicKey,
                        body.hpkeEnc,
                        body.hpkeCiphertext,
                    )
                used = gen
                break
            } catch (e: OnionHandshakeException) {
                // try the previous key
            }
        }
        if (plaintext == null || used == null) {
            stats.malformed++
            return
        }
        used.cache.add(enc)
        try {
            val pt =
                try {
                    IntroducePlaintext.decode(plaintext)
                } catch (e: CellFormatException) {
                    stats.malformed++
                    return
                }
            val rp = resolveRelay(pt.rendezvousRelayIdDigest, pt.rendezvousOnionKeyFingerprint)
            if (rp == null) {
                stats.unknownRendezvousPoint++
                return
            }
            val (reply, e2e) =
                try {
                    RendezvousHandshake.receiverRespond(
                        serviceId,
                        used.pair.privateKey,
                        used.pair.publicKey,
                        pt.clientEphemeral,
                        random,
                    )
                } catch (e: OnionHandshakeException) {
                    stats.malformed++
                    return
                }
            val ref = newRef()
            pending[ref] = PendingRendezvous(pt.cookie, reply, e2e, now() + config.buildTimeout.inWholeMilliseconds)
            out += ServiceCommand.BuildCircuit(ref, rp, CircuitPurpose.RENDEZVOUS_RECEIVER)
        } finally {
            plaintext.fill(0)
        }
    }

    private fun onTick(out: MutableList<ServiceCommand>) {
        val t = now()
        // expire pending rendezvous builds
        val expired = pending.entries.filter { t >= it.value.deadlineMillis }
        for ((ref, p) in expired) {
            pending.remove(ref)
            p.e2e.close()
            out += ServiceCommand.Destroy(ref)
        }
        for (s in slots) {
            if (s.buildRef != null && t >= s.buildDeadlineMillis) failBuild(s, out)
            if (s.relay == null && s.buildRef == null && s.needsRelayAnnounced && t >= s.backoffUntilMillis) {
                // the host had no candidate (or the replacement vanished): ask again, with backoff
                s.failures++
                s.backoffUntilMillis = t + backoffMillis(s.failures)
                out += ServiceCommand.NeedIntroRelay(s.index)
            }
            if (s.buildRef == null && s.relay != null && t >= s.backoffUntilMillis) {
                if (s.ref == null) {
                    startBuild(s, out)
                } else if (t - s.establishedAtMillis >= config.introCircuitRefreshAfter.inWholeMilliseconds) {
                    startBuild(s, out)
                }
            }
        }
        // encryption key rotation
        // a full replay cache also forces an early rotation, otherwise the service stays unreachable until the next one
        if (t - current.createdAtMillis >= config.encKeyRotation.inWholeMilliseconds ||
            current.cache.size >= current.capacity
        ) {
            previous?.pair?.privateKey?.destroy()
            current.acceptUntilMillis = t + config.descriptorTtl.inWholeMilliseconds
            previous = current
            current = newGeneration()
            dirty = true
        }
        previous?.let {
            if (t > it.acceptUntilMillis) {
                it.pair.privateKey.destroy()
                previous = null
            }
        }
        val allReady = slots.all { it.ref != null }
        val due =
            lastPublishMillis == Long.MIN_VALUE || t - lastPublishMillis >= config.republishInterval.inWholeMilliseconds
        if (allReady && (dirty || due)) {
            publish(out)
        }
    }

    /**
     * Re-signs the current descriptor content as a NEW version (higher sequence number) if all introduction slots are
     * ready: same introduction points, authentication keys and encryption key; only the sequence number, the
     * `notValidAfter` and the signature change. Used by the early republication: a byte-identical repeat is ignored
     * (not forwarded) by every node that already holds it, a fresh version is forwarded over several hops.
     * Does not touch the hourly publication clock.
     *
     * @return the [ServiceCommand.Publish], or an empty list if not all slots are ready (nothing to refresh) or the
     * service is stopped
     */
    @Synchronized
    fun refreshDescriptor(): List<ServiceCommand> {
        if (stopped || !started || !slots.all { it.ref != null }) return emptyList()
        val out = ArrayList<ServiceCommand>(1)
        val before = lastPublishMillis
        val wasDirty = dirty
        publish(out)
        // the hourly clock and a pending change publication stay as they were
        lastPublishMillis = before
        dirty = wasDirty
        return out
    }

    private fun publish(out: MutableList<ServiceCommand>) {
        val nowSec = now() / 1000
        val entries = slots.map { IntroPointEntry(checkNotNull(it.relay), checkNotNull(it.authKey).publicKey) }
        val nva =
            minOf(
                nowSec + config.descriptorTtl.inWholeSeconds,
                entries.minOf { it.relayOnionKeyBinding.notValidAfterEpochSecond },
            )
        // milliseconds, so that a restart with the same service key (which loses this counter) still increases
        lastDescriptorSeq = maxOf(lastDescriptorSeq + 1, now())
        val descriptor =
            try {
                OnionServiceDescriptor.create(
                    serviceKey,
                    current.pair.publicKey,
                    entries,
                    lastDescriptorSeq,
                    nva,
                    nowSec,
                )
            } catch (e: IllegalArgumentException) {
                logger.debug { "descriptor could not be created" }
                return
            }
        lastPublishMillis = now()
        dirty = false
        out += ServiceCommand.Publish(descriptor)
    }

    /** Test seam: forces an encryption key rotation now. */
    @Synchronized
    internal fun rotateEncKeyNow() {
        previous?.pair?.privateKey?.destroy()
        current.acceptUntilMillis = now() + config.descriptorTtl.inWholeMilliseconds
        previous = current
        current = newGeneration()
        dirty = true
    }

    /** Destroys every circuit and zeroises all keys. The machine is unusable afterwards. */
    @Synchronized
    fun stop(): List<ServiceCommand> {
        if (stopped) return emptyList()
        stopped = true
        val out = ArrayList<ServiceCommand>()
        for (s in slots) {
            s.ref?.let { out += ServiceCommand.Destroy(it) }
            s.buildRef?.let { out += ServiceCommand.Destroy(it) }
            s.ref = null
            s.buildRef = null
        }
        for ((ref, p) in pending) {
            p.e2e.close()
            out += ServiceCommand.Destroy(ref)
        }
        pending.clear()
        current.pair.privateKey.destroy()
        previous?.pair?.privateKey?.destroy()
        previous = null
        return out
    }

    override fun close() {
        stop()
    }

    /** Test seams. */
    @get:Synchronized
    internal val pendingRendezvousCount: Int get() = pending.size

    @Synchronized
    internal fun slotRef(index: Int): CircuitRef? = slots[index].ref

    @Synchronized
    internal fun slotBuildRef(index: Int): CircuitRef? = slots[index].buildRef

    @Synchronized
    internal fun slotAuthKey(index: Int): Ed25519KeyPair? = slots[index].authKey

    @Synchronized
    internal fun currentEncKeyPair(): X25519KeyPair = current.pair

    @Synchronized
    internal fun slotSeq(index: Int): Long = slots[index].seq
}
