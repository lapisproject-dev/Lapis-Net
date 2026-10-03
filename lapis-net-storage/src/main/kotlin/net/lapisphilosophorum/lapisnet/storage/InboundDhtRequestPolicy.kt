package net.lapisphilosophorum.lapisnet.storage

import com.google.protobuf.ByteString
import net.lapisphilosophorum.lapisnet.core.cid.CidBytesValidation
import org.peergos.protocol.dht.pb.Dht

/**
 * Pre-flight check for an INBOUND Kademlia request, run before Nabu's `KademliaEngine.receiveRequest`
 * sees it. Pure function, allocates nothing proportional to the declared lengths in the message.
 *
 * Why it exists: `receiveRequest` runs on the Netty event loop and feeds the request's key
 * bytes straight into `Multihash.deserialize` (`ADD_PROVIDER`, `GET_PROVIDERS`, `PUT_VALUE` via
 * the IPNS parser) or `Cid.cast` (`GET_VALUE`). Both allocate `new byte[declaredLength]` BEFORE
 * any bound check (see [CidBytesValidation]), so any connected peer can make this node attempt a
 * multi-gigabyte allocation with a 10-byte key. An unknown message type makes the base class throw
 * an `IllegalStateException` on the event loop instead of just ignoring the message.
 */
internal object InboundDhtRequestPolicy {
    private val IPNS_PREFIX: ByteArray = "/ipns/".toByteArray(Charsets.US_ASCII)

    fun isAcceptable(msg: Dht.Message): Boolean =
        when (msg.type) {
            Dht.Message.MessageType.ADD_PROVIDER ->
                isSafeMultihash(msg.key) &&
                    msg.providerPeersList.all { CidBytesValidation.isSafeToDeserializeMultihash(it.id.toByteArray()) }
            Dht.Message.MessageType.GET_PROVIDERS -> isSafeMultihash(msg.key)
            Dht.Message.MessageType.GET_VALUE ->
                ipnsSuffix(msg.key)?.let { CidBytesValidation.isSafeToCast(it) } ?: false
            Dht.Message.MessageType.PUT_VALUE ->
                ipnsSuffix(msg.key)?.let { CidBytesValidation.isSafeToDeserializeMultihash(it) } == true &&
                    msg.hasRecord() &&
                    msg.record.key == msg.key
            // The key is only hashed; the source peer is authenticated by Noise.
            Dht.Message.MessageType.FIND_NODE -> true
            Dht.Message.MessageType.PING -> true
            else -> false
        }

    private fun isSafeMultihash(key: ByteString): Boolean =
        CidBytesValidation.isSafeToDeserializeMultihash(key.toByteArray())

    /** The bytes after the `/ipns/` prefix, or `null` if [key] is not an IPNS key with a non-empty suffix. */
    private fun ipnsSuffix(key: ByteString): ByteArray? {
        if (key.size() <= IPNS_PREFIX.size) return null
        val bytes = key.toByteArray()
        for (i in IPNS_PREFIX.indices) if (bytes[i] != IPNS_PREFIX[i]) return null
        return bytes.copyOfRange(IPNS_PREFIX.size, bytes.size)
    }
}
