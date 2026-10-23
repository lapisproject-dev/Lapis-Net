package net.lapisphilosophorum.lapisnet.onionwire

import net.lapisphilosophorum.lapisnet.directory.AnonymousPeerRecord
import net.lapisphilosophorum.lapisnet.directory.AnonymousPeerRecordCodec
import net.lapisphilosophorum.lapisnet.directory.DirectoryPublicationChannel
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptor
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptorCodec
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundle
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundleCodec
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CopyOnWriteArrayList

internal fun contains(
    haystack: ByteArray,
    needle: ByteArray,
): Boolean {
    if (needle.isEmpty() || haystack.size < needle.size) return false
    outer@ for (o in 0..haystack.size - needle.size) {
        for (i in needle.indices) if (haystack[o + i] != needle[i]) continue@outer
        return true
    }
    return false
}

/** Records the plaintext of every directory object that leaves through [delegate] (what the publish relay sees). */
internal class CapturingChannel(
    private val delegate: DirectoryPublicationChannel,
) : DirectoryPublicationChannel {
    val objects = CopyOnWriteArrayList<ByteArray>()

    override val exposesOrigin: Boolean get() = delegate.exposesOrigin

    override fun publishAnonymousPeerRecord(record: AnonymousPeerRecord): CompletableFuture<Boolean> {
        objects += AnonymousPeerRecordCodec.encode(record)
        return delegate.publishAnonymousPeerRecord(record)
    }

    override fun publishPrekeyBundle(bundle: PrekeyBundle): CompletableFuture<Boolean> {
        objects += PrekeyBundleCodec.encode(bundle)
        return delegate.publishPrekeyBundle(bundle)
    }

    override fun publishServiceDescriptor(descriptor: OnionServiceDescriptor): CompletableFuture<Boolean> {
        objects += OnionServiceDescriptorCodec.encode(descriptor)
        return delegate.publishServiceDescriptor(descriptor)
    }
}

/**
 * Everything one node sends out on its own: its gossip publications (through [net.lapisphilosophorum.lapisnet.networking.GossipPubSub.outboundTap])
 * and the plaintext objects it hands to circuits. Searches them for the node's addresses and transport identity.
 */
internal class AnonymityLeakScanner(
    private val node: WireTestNode,
) {
    val gossip = CopyOnWriteArrayList<Pair<String, ByteArray>>()

    init {
        node.pubsub.outboundTap = { topic, bytes -> gossip += topic to bytes }
    }

    /** Binary multiaddrs, their text, and the `06 <port>` TCP component of every listen address. */
    fun addressNeedles(): List<ByteArray> =
        node.node.listenAddresses().flatMap { ma ->
            val text = ma.toString()
            val port = Regex("/tcp/(\\d+)").find(text)!!.groupValues[1].toInt()
            listOf(
                ma.serialize(),
                text.toByteArray(),
                byteArrayOf(0x06, (port ushr 8).toByte(), port.toByte()),
            )
        }

    /** The libp2p peer id, the Ed25519 transport key and the binding signature. */
    fun identityNeedles(): List<ByteArray> =
        listOf(
            node.node.peerId.bytes,
            node.identity.ed25519KeyPair.publicKey.bytes,
            node.identity.binding.signature,
        )

    fun leaks(
        objects: List<ByteArray>,
        needles: List<ByteArray>,
    ): List<Int> = needles.indices.filter { n -> objects.any { contains(it, needles[n]) } }
}
