package net.lapisphilosophorum.lapisnet.directory

import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptor
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundle
import java.util.concurrent.CompletableFuture

/**
 * How a node in anonymity mode gets its directory objects (anonymous record, prekey bundle, service descriptor) into
 * the network (wave V0.10.0-D). All objects are address-free and public by nature; the channel decides WHO appears as
 * their publisher. A future that completes with `false` or exceptionally means "not published": the caller retries
 * with a different path and never falls back to a more revealing channel in mode ON.
 *
 * Implementations: [DirectGossipChannel] (the own node gossips: reveals the origin, for mode OFF and tests only) and
 * `OnionDirectoryPublisher` in `lapis-net-onion-wire` (through a circuit, a relay publishes on the node's behalf).
 * This is an open interface instead of a sealed type because the circuit implementation lives in a module above.
 */
interface DirectoryPublicationChannel {
    /** `true` when the own node is the gossip publisher, i.e. publication reveals this node's peer ID and IP. */
    val exposesOrigin: Boolean

    fun publishAnonymousPeerRecord(record: AnonymousPeerRecord): CompletableFuture<Boolean>

    fun publishPrekeyBundle(bundle: PrekeyBundle): CompletableFuture<Boolean>

    fun publishServiceDescriptor(descriptor: OnionServiceDescriptor): CompletableFuture<Boolean>
}

/** Publishes from the own node through the gossip classes. REVEALS THE ORIGIN: never use it in mode ON in production. */
class DirectGossipChannel(
    private val anonymous: AnonymousPeerRecordGossip,
    private val prekeys: PrekeyBundleGossip?,
    private val services: OnionServiceDescriptorGossip?,
) : DirectoryPublicationChannel {
    override val exposesOrigin: Boolean get() = true

    override fun publishAnonymousPeerRecord(record: AnonymousPeerRecord): CompletableFuture<Boolean> =
        attempt {
            val outcome = anonymous.announce(record)
            outcome == AnonymousIngestOutcome.ACCEPTED || outcome == AnonymousIngestOutcome.DUPLICATE
        }

    override fun publishPrekeyBundle(bundle: PrekeyBundle): CompletableFuture<Boolean> =
        attempt {
            prekeys?.announce(bundle) ?: return@attempt false
            true
        }

    override fun publishServiceDescriptor(descriptor: OnionServiceDescriptor): CompletableFuture<Boolean> =
        attempt {
            services?.announce(descriptor) ?: return@attempt false
            true
        }

    private fun attempt(block: () -> Boolean): CompletableFuture<Boolean> =
        try {
            CompletableFuture.completedFuture(block())
        } catch (e: RuntimeException) {
            CompletableFuture.completedFuture(false)
        }
}
