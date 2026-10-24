package net.lapisphilosophorum.lapisnet.mailonion

import net.lapisphilosophorum.lapisnet.directory.DirectoryReachability
import net.lapisphilosophorum.lapisnet.dmonion.FakeChannel
import net.lapisphilosophorum.lapisnet.dmonion.FrameChannel
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.mail.AnonymousMailInboundSink
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptor
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/** A scripted mail runtime port. */
class FakeMailPort : OnionMailRuntimePort {
    @Volatile var ready = true

    @Volatile var reachability: (Secp256k1PublicKey) -> DirectoryReachability = { DirectoryReachability.Unknown }
    val connects = AtomicInteger(0)
    val unreachable = AtomicInteger(0)

    /** Called with the server end of every new pair. */
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

    override fun recordRecipientUnreachable() {
        unreachable.incrementAndGet()
    }
}

class CollectingMailSink : AnonymousMailInboundSink {
    class Received(
        val frame: ByteArray,
        val blobs: List<ByteArray>,
    )

    val received = CopyOnWriteArrayList<Received>()

    @Volatile var gate: CountDownLatch? = null

    override fun acceptAnonymousMail(
        frameBytes: ByteArray,
        attachmentBlobs: List<ByteArray>,
    ) {
        gate?.await(20, TimeUnit.SECONDS)
        // copies: the caller may wipe its buffers as soon as this returns
        received += Received(frameBytes.copyOf(), attachmentBlobs.map { it.copyOf() })
    }
}

class SteppingClock(
    @Volatile var millis: Long = 1_000_000L,
) : Clock() {
    override fun getZone() = ZoneOffset.UTC

    override fun withZone(zone: java.time.ZoneId?) = this

    override fun instant(): Instant = Instant.ofEpochMilli(millis)

    override fun millis(): Long = millis
}

fun waitFor(condition: () -> Boolean): Boolean {
    val end = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
    while (System.nanoTime() < end) {
        if (condition()) return true
        Thread.sleep(10)
    }
    return condition()
}
