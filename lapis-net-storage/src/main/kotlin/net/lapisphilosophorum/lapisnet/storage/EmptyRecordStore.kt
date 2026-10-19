package net.lapisphilosophorum.lapisnet.storage

import io.ipfs.multihash.Multihash
import org.peergos.protocol.dht.RecordStore
import org.peergos.protocol.ipns.IpnsRecord
import java.util.Optional

/**
 * The [RecordStore] handed to Nabu's `KademliaEngine`: it stores nothing and finds nothing.
 * `PUT_VALUE` and `GET_VALUE` are answered by [IpnsValueResponder] (V0.9.13) and never reach the base
 * class, so this is the structural guarantee that Nabu's own IPNS handling - which cannot serve
 * Ed25519 names and parses CBOR without a depth limit - is not used even by accident.
 */
internal object EmptyRecordStore : RecordStore {
    override fun put(
        publisher: Multihash,
        record: IpnsRecord,
    ) {}

    override fun get(publisher: Multihash): Optional<IpnsRecord> = Optional.empty()

    override fun remove(publisher: Multihash) {}

    override fun close() {}
}
