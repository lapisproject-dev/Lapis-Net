package net.lapisphilosophorum.lapisnet.storage

import com.google.protobuf.ByteString
import net.lapisphilosophorum.lapisnet.core.cid.CidBytesValidation
import org.peergos.protocol.dht.pb.Dht

/**
 * Pre-flight check for an INBOUND Kademlia request, run before Nabu's `KademliaEngine.receiveRequest`
 * sees it. Pure function, allocates nothing proportional to the declared lengths in the message.
 *
 * Why it exists: `receiveRequest` runs on the Netty event loop and feeds the request's key
 * bytes straight into `Multihash.deserialize` (`ADD_PROVIDER`, `GET_PROVIDERS`). Both that and the parsers
 * Nabu uses for IPNS keys (`Cid.cast`, V0.9.11 view) allocate `new byte[declaredLength]` BEFORE
 * any bound check (see [CidBytesValidation]), so any connected peer can make this node attempt a
 * multi-gigabyte allocation with a 10-byte key. Since V0.9.13 `PUT_VALUE` / `GET_VALUE` keys are not
 * parsed by Nabu at all: they must be exactly `/ipns/` + an Ed25519 identity multihash (one fixed size,
 * checked first), and a `PUT_VALUE` record may not exceed [DhtLimits.maxIpnsRecordBytes]. An unknown message type makes the base class throw
 * an `IllegalStateException` on the event loop instead of just ignoring the message.
 */
internal object InboundDhtRequestPolicy {
    fun isAcceptable(
        msg: Dht.Message,
        limits: DhtLimits = DhtLimits(),
    ): Boolean =
        when (msg.type) {
            Dht.Message.MessageType.ADD_PROVIDER ->
                isSafeMultihash(msg.key) &&
                    msg.providerPeersList.all { CidBytesValidation.isSafeToDeserializeMultihash(it.id.toByteArray()) }
            Dht.Message.MessageType.GET_PROVIDERS -> isSafeMultihash(msg.key)
            // Only Ed25519 names (V0.9.13); the key has one exact size, checked before any copy.
            Dht.Message.MessageType.GET_VALUE -> isIpnsKey(msg.key)
            Dht.Message.MessageType.PUT_VALUE ->
                isIpnsKey(msg.key) &&
                    msg.hasRecord() &&
                    msg.record.key == msg.key &&
                    msg.record.value.size() <= limits.maxIpnsRecordBytes
            // The key is only hashed; the source peer is authenticated by Noise.
            Dht.Message.MessageType.FIND_NODE -> true
            Dht.Message.MessageType.PING -> true
            else -> false
        }

    private fun isSafeMultihash(key: ByteString): Boolean =
        CidBytesValidation.isSafeToDeserializeMultihash(key.toByteArray())

    private fun isIpnsKey(key: ByteString): Boolean =
        key.size() == IPNS_KEY_SIZE && parseIpnsKey(key.toByteArray()) != null
}
