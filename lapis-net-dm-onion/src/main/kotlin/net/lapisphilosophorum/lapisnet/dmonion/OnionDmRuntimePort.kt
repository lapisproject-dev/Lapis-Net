@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.dmonion

import net.lapisphilosophorum.lapisnet.directory.DirectoryReachability
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptor
import net.lapisphilosophorum.lapisnet.onionwire.OnionRendezvousStream
import net.lapisphilosophorum.lapisnet.onionwire.OnionServiceApp
import net.lapisphilosophorum.lapisnet.onionwire.anonymity.AnonymityRuntime
import java.time.Duration
import java.util.concurrent.CompletableFuture
import kotlin.time.toKotlinDuration

/** A bidirectional message channel to the other end of a rendezvous stream (what the framing needs of it). */
interface FrameChannel : AutoCloseable {
    val maxPayload: Int
    val isClosed: Boolean

    fun send(data: ByteArray): Boolean

    fun onReceive(callback: (ByteArray) -> Unit)

    fun onClose(callback: () -> Unit)
}

/** The narrow view of the anonymity runtime that the DM adapter uses; a seam so the adapter can be tested with fakes. */
interface OnionDmRuntimePort {
    fun ready(): Boolean

    fun resolveIdentity(identity: Secp256k1PublicKey): DirectoryReachability

    fun connect(
        descriptor: OnionServiceDescriptor,
        timeout: Duration,
    ): CompletableFuture<FrameChannel>

    fun publishMailboxItems(items: List<ByteArray>): CompletableFuture<Boolean>

    fun recordRecipientUnreachable()
}

/** Wraps a rendezvous stream as a [FrameChannel]. */
class StreamFrameChannel(
    private val stream: OnionRendezvousStream,
) : FrameChannel {
    override val maxPayload: Int get() = stream.maxPayload
    override val isClosed: Boolean get() = stream.isClosed

    override fun send(data: ByteArray): Boolean = stream.send(data)

    override fun onReceive(callback: (ByteArray) -> Unit) = stream.onReceive(callback)

    override fun onClose(callback: () -> Unit) = stream.onClose(callback)

    override fun close() = stream.close()

    override fun toString(): String = "StreamFrameChannel(REDACTED)"
}

/** The production port over [AnonymityRuntime]. */
class AnonymityRuntimePort(
    private val runtime: AnonymityRuntime,
) : OnionDmRuntimePort {
    override fun ready(): Boolean = runtime.ready()

    override fun resolveIdentity(identity: Secp256k1PublicKey): DirectoryReachability =
        runtime.resolveIdentity(identity)

    override fun connect(
        descriptor: OnionServiceDescriptor,
        timeout: Duration,
    ): CompletableFuture<FrameChannel> =
        runtime
            .connectToService(descriptor, OnionServiceApp.DM, timeout.toKotlinDuration())
            .thenApply { StreamFrameChannel(it) as FrameChannel }

    override fun publishMailboxItems(items: List<ByteArray>): CompletableFuture<Boolean> =
        runtime.publishMailboxItems(items)

    override fun recordRecipientUnreachable() = runtime.recordRecipientUnreachable()
}
