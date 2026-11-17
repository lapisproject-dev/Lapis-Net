package net.lapisphilosophorum.lapisnet.storage

/**
 * Whether a [NabuStorage] takes part in the network (wave V0.10.0-J1a).
 *
 * - [NETWORK] (the default): Bitswap and Kademlia are registered on the host, the node serves blocks and answers DHT
 *   requests, and [NabuStorage.get], [NabuStorage.provide], [NabuStorage.findProviders] and the IPNS functions reach
 *   other peers directly. Unchanged behaviour.
 * - [LOCAL_ONLY] (anonymity mode): neither protocol is registered, so no peer can ask this node for a block or a DHT
 *   entry (no "does this node hold CID X" probe, no place in foreign routing tables); the node's own addresses are not
 *   put into its address book either. Every function that would reach the network throws
 *   [AnonymousStorageRefusedException]; [NabuStorage.get] without peers answers from the local stores and from a
 *   [RemoteContentSource], if one is attached (circuit lookups, wave V0.10.0-J2), otherwise `null`.
 */
enum class StorageNetworkMode {
    NETWORK,
    LOCAL_ONLY,
}

/** Thrown by [NabuStorage] in [StorageNetworkMode.LOCAL_ONLY] for every operation that would reach the network. */
class AnonymousStorageRefusedException(
    message: String,
) : NabuStorageException(message)
