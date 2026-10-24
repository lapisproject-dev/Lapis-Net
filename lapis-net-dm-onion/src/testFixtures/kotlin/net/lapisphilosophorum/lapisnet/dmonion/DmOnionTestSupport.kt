package net.lapisphilosophorum.lapisnet.dmonion

import net.lapisphilosophorum.lapisnet.directory.AnonymousCapability
import net.lapisphilosophorum.lapisnet.directory.AnonymousPeerRecord
import net.lapisphilosophorum.lapisnet.directory.DirectoryReachability
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.onion.IntroPointEntry
import net.lapisphilosophorum.lapisnet.onion.OnionKeyBinding
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptor
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundle
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyStore
import java.nio.file.Files
import java.time.Duration
import java.time.Instant
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger

/** One end of an in-memory channel pair; sends are delivered synchronously to the peer's receiver. */
class FakeChannel(
    override val maxPayload: Int = 910,
) : FrameChannel {
    @Volatile var peer: FakeChannel? = null

    @Volatile private var receiver: ((ByteArray) -> Unit)? = null

    @Volatile private var closeListener: () -> Unit = {}
    private val closedFlag =
        java.util.concurrent.atomic
            .AtomicBoolean(false)
    val sent = CopyOnWriteArrayList<ByteArray>()

    @Volatile var dropSends = false

    override val isClosed: Boolean get() = closedFlag.get()

    override fun send(data: ByteArray): Boolean {
        if (isClosed) return false
        sent += data
        if (dropSends) return true
        peer?.receiver?.invoke(data)
        return true
    }

    override fun onReceive(callback: (ByteArray) -> Unit) {
        receiver = callback
    }

    override fun onClose(callback: () -> Unit) {
        closeListener = callback
        if (isClosed) callback()
    }

    override fun close() {
        if (!closedFlag.compareAndSet(false, true)) return
        runCatching { closeListener() }
        peer?.close()
    }

    companion object {
        fun pair(maxPayload: Int = 910): Pair<FakeChannel, FakeChannel> {
            val a = FakeChannel(maxPayload)
            val b = FakeChannel(maxPayload)
            a.peer = b
            b.peer = a
            return a to b
        }
    }
}

/** A scripted runtime port. */
class FakePort : OnionDmRuntimePort {
    @Volatile var ready = true

    @Volatile var reachability: (Secp256k1PublicKey) -> DirectoryReachability = { DirectoryReachability.Unknown }
    val connects = AtomicInteger(0)
    val unreachable = AtomicInteger(0)
    val published = CopyOnWriteArrayList<List<ByteArray>>()

    @Volatile var publishResult: CompletableFuture<Boolean> = CompletableFuture.completedFuture(true)

    /** Called with the client end of every new pair; returns whether the connect succeeds. */
    @Volatile var onConnect: (FakeChannel) -> Unit = {}

    @Volatile var connectFails = false
    val clientEnds = CopyOnWriteArrayList<FakeChannel>()

    override fun ready(): Boolean = ready

    override fun resolveIdentity(identity: Secp256k1PublicKey): DirectoryReachability = reachability(identity)

    override fun connect(
        descriptor: OnionServiceDescriptor,
        timeout: Duration,
    ): CompletableFuture<FrameChannel> {
        connects.incrementAndGet()
        if (connectFails) return CompletableFuture.failedFuture(IllegalStateException("no route"))
        val (client, server) = FakeChannel.pair()
        clientEnds += client
        onConnect(server)
        return CompletableFuture.completedFuture(client)
    }

    override fun publishMailboxItems(items: List<ByteArray>): CompletableFuture<Boolean> {
        published += items
        return publishResult
    }

    override fun recordRecipientUnreachable() {
        unreachable.incrementAndGet()
    }
}

class Peer(
    val identity: DualKeyIdentity = DualKeyIdentity.generate(),
) {
    val key: Secp256k1PublicKey get() = identity.secp256k1KeyPair.publicKey
    val serviceKey: Ed25519KeyPair = Ed25519KeyPair.generate()
    val prekeys: PrekeyStore =
        PrekeyStore.create(
            Files.createTempDirectory("dm-onion-prekeys"),
            identity,
            oneTimePrekeyCount = 3,
        )
    val bundle: PrekeyBundle = prekeys.publishBundle(identity, Instant.now().epochSecond + 3600)

    fun record(capabilities: Set<AnonymousCapability> = setOf(AnonymousCapability.DM)): AnonymousPeerRecord =
        AnonymousPeerRecord.create(identity, serviceKey, capabilities, null, 1, Instant.now().epochSecond + 600)

    fun descriptor(): OnionServiceDescriptor {
        val relay = DualKeyIdentity.generate()
        val binding =
            OnionKeyBinding.create(
                relay.secp256k1KeyPair,
                X25519KeyPair.generate().publicKey,
                Instant.now().epochSecond + 3600,
            )
        return OnionServiceDescriptor.create(
            serviceKey,
            X25519KeyPair.generate().publicKey,
            listOf(IntroPointEntry(binding, Ed25519KeyPair.generate().publicKey)),
            1,
            Instant.now().epochSecond + 600,
            Instant.now().epochSecond,
        )
    }
}
