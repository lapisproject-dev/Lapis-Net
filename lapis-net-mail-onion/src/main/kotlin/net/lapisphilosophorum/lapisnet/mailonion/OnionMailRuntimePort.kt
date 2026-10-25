@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.mailonion

import net.lapisphilosophorum.lapisnet.directory.DirectoryReachability
import net.lapisphilosophorum.lapisnet.dmonion.FrameChannel
import net.lapisphilosophorum.lapisnet.dmonion.StreamFrameChannel
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptor
import net.lapisphilosophorum.lapisnet.onionwire.OnionServiceApp
import net.lapisphilosophorum.lapisnet.onionwire.anonymity.AnonymityRuntime
import java.time.Duration
import java.util.concurrent.CompletableFuture
import kotlin.time.toKotlinDuration

/** The narrow view of the anonymity runtime that the mail adapter uses; a seam so the adapter can be tested with fakes. */
interface OnionMailRuntimePort {
    /** `true` if bundle frames are padded to size classes (wave V0.10.0-H); the receiver accepts both forms. */
    val paddingEnabled: Boolean get() = false

    fun ready(): Boolean

    fun resolveIdentity(identity: Secp256k1PublicKey): DirectoryReachability

    fun connect(
        descriptor: OnionServiceDescriptor,
        timeout: Duration,
    ): CompletableFuture<FrameChannel>

    fun recordRecipientUnreachable()
}

/** The production port over [AnonymityRuntime]; streams are opened for the MAIL application. */
class AnonymityRuntimeMailPort(
    private val runtime: AnonymityRuntime,
) : OnionMailRuntimePort {
    override val paddingEnabled: Boolean get() = runtime.padding.sizeClasses

    override fun ready(): Boolean = runtime.ready()

    override fun resolveIdentity(identity: Secp256k1PublicKey): DirectoryReachability =
        runtime.resolveIdentity(identity)

    override fun connect(
        descriptor: OnionServiceDescriptor,
        timeout: Duration,
    ): CompletableFuture<FrameChannel> =
        runtime
            .connectToService(descriptor, OnionServiceApp.MAIL, timeout.toKotlinDuration())
            .thenApply { StreamFrameChannel(it) as FrameChannel }

    override fun recordRecipientUnreachable() = runtime.recordRecipientUnreachable()

    override fun toString(): String = "AnonymityRuntimeMailPort(REDACTED)"
}
