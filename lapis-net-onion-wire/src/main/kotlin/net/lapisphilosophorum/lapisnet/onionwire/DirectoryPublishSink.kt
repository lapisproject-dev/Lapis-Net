package net.lapisphilosophorum.lapisnet.onionwire

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.directory.AnonymousIngestOutcome
import net.lapisphilosophorum.lapisnet.directory.AnonymousPeerRecordCodec
import net.lapisphilosophorum.lapisnet.directory.AnonymousPeerRecordGossip
import net.lapisphilosophorum.lapisnet.directory.DescriptorIngestOutcome
import net.lapisphilosophorum.lapisnet.directory.MalformedAnonymousPeerRecordException
import net.lapisphilosophorum.lapisnet.directory.OnionServiceDescriptorGossip
import net.lapisphilosophorum.lapisnet.directory.OnionServiceDescriptorIndex
import net.lapisphilosophorum.lapisnet.directory.PrekeyBundleGossip
import net.lapisphilosophorum.lapisnet.directory.PrekeyBundleIndex
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.onion.CellFormatException
import net.lapisphilosophorum.lapisnet.onion.DirectoryObjectType
import net.lapisphilosophorum.lapisnet.onion.DirectoryPublishStatus
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptor
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptorCodec
import net.lapisphilosophorum.lapisnet.ratchet.MalformedPrekeyBundleException
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundle
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundleCodec
import net.lapisphilosophorum.lapisnet.ratchet.verifyEncryptionBinding
import net.lapisphilosophorum.lapisnet.ratchet.verifySignedPrekey
import java.time.Clock

private val logger = KotlinLogging.logger {}

/**
 * What a relay does with a directory object that a client handed to it through a circuit (wave V0.10.0-D). Returns the
 * DIRECTORY_PUBLISHED status byte ([DirectoryPublishStatus]). Runs on a pool thread, never on a link event loop.
 */
fun interface DirectoryPublishSink {
    fun publish(
        type: DirectoryObjectType,
        objectBytes: ByteArray,
    ): Byte
}

/**
 * The production sink: validates the object completely with the same functions as the gossip validators and only then
 * publishes it on its gossip topic, so that the relay (not the client) is the publisher seen by the mesh. No oracle:
 * an object that is valid but already known, superseded or stale is answered with the same status as a new one.
 * Logs carry the object type and a reason class only.
 */
internal class GossipDirectoryPublishSink(
    private val anonymousGossip: AnonymousPeerRecordGossip,
    private val serviceGossip: OnionServiceDescriptorGossip,
    private val serviceIndex: OnionServiceDescriptorIndex,
    private val pubsub: GossipPubSub,
    private val clock: Clock,
    /** The node's own prekey-bundle gossip, so bundles already received over the topic are not republished. */
    private val nodeBundles: PrekeyBundleGossip? = null,
) : DirectoryPublishSink {
    /** Relay-local dedupe for prekey bundles, so duplicate or stale bundles are not put on the topic again. */
    private val seenBundles = PrekeyBundleIndex()

    override fun publish(
        type: DirectoryObjectType,
        objectBytes: ByteArray,
    ): Byte =
        try {
            when (type) {
                DirectoryObjectType.ANONYMOUS_PEER_RECORD -> anonymousRecord(objectBytes)
                DirectoryObjectType.ONION_SERVICE_DESCRIPTOR -> serviceDescriptor(objectBytes)
                DirectoryObjectType.PREKEY_BUNDLE -> prekeyBundle(objectBytes)
            }
        } catch (e: RuntimeException) {
            logger.debug { "directory publish failed (${e.javaClass.simpleName}) for $type" }
            DirectoryPublishStatus.RATE_LIMITED
        }

    private fun anonymousRecord(bytes: ByteArray): Byte {
        val record =
            try {
                AnonymousPeerRecordCodec.decode(bytes)
            } catch (e: MalformedAnonymousPeerRecordException) {
                return DirectoryPublishStatus.MALFORMED
            }
        return when (anonymousGossip.announce(record)) {
            AnonymousIngestOutcome.ACCEPTED,
            AnonymousIngestOutcome.DUPLICATE,
            AnonymousIngestOutcome.REPLAYED_OR_STALE,
            -> DirectoryPublishStatus.ACCEPTED
            AnonymousIngestOutcome.INVALID,
            AnonymousIngestOutcome.EXPIRED,
            -> DirectoryPublishStatus.INVALID
            AnonymousIngestOutcome.CAPACITY -> DirectoryPublishStatus.RATE_LIMITED
        }
    }

    private fun serviceDescriptor(bytes: ByteArray): Byte {
        val descriptor =
            try {
                OnionServiceDescriptorCodec.decode(bytes)
            } catch (e: CellFormatException) {
                return DirectoryPublishStatus.MALFORMED
            }
        val now = clock.millis() / 1000
        if (!OnionServiceDescriptor.verify(descriptor, now)) return DirectoryPublishStatus.INVALID
        return when (serviceIndex.precheck(descriptor, now)) {
            // a retry through the same relay may follow a first publish that found no mesh peer: announce again
            DescriptorIngestOutcome.DUPLICATE -> {
                serviceGossip.announce(descriptor)
                DirectoryPublishStatus.ACCEPTED
            }
            // superseded: nothing to publish again, same answer as for a new one
            DescriptorIngestOutcome.REPLAYED_OR_STALE -> DirectoryPublishStatus.ACCEPTED
            DescriptorIngestOutcome.EXPIRED -> DirectoryPublishStatus.INVALID
            else -> {
                serviceGossip.announce(descriptor)
                DirectoryPublishStatus.ACCEPTED
            }
        }
    }

    private fun prekeyBundle(bytes: ByteArray): Byte {
        val bundle =
            try {
                PrekeyBundleCodec.decode(bytes)
            } catch (e: MalformedPrekeyBundleException) {
                return DirectoryPublishStatus.MALFORMED
            }
        val now = clock.millis() / 1000
        if (!PrekeyBundle.verify(bundle) || !bundle.verifyEncryptionBinding() || !bundle.verifySignedPrekey()) {
            return DirectoryPublishStatus.INVALID
        }
        if (bundle.notValidAfterEpochSecond < now ||
            bundle.notValidAfterEpochSecond > now + PrekeyBundle.MAX_TTL_WINDOW_SECONDS
        ) {
            return DirectoryPublishStatus.INVALID
        }
        // Duplicate or stale: same answer as for a new one, but not published again (receivers would rate it Invalid).
        val knownToNode = nodeBundles?.canAccept(bundle) == false
        if (knownToNode || !seenBundles.canAccept(bundle)) return DirectoryPublishStatus.ACCEPTED
        seenBundles.add(bundle)
        pubsub.publish(PrekeyBundleGossip.PREKEY_BUNDLE_GOSSIP_TOPIC, bytes)
        return DirectoryPublishStatus.ACCEPTED
    }
}
