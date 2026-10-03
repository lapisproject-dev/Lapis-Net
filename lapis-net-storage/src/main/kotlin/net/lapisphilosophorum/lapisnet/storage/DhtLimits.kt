package net.lapisphilosophorum.lapisnet.storage

import java.time.Duration

/**
 * Every bound the DHT layer of [NabuStorage] enforces, in one place (V0.9.11). Nabu's own
 * Kademlia code has none of these: its lookups block without a deadline, its responder echoes
 * and stores unbounded address lists, and a single `provide` fans out over whatever the routing
 * table and the answers of untrusted peers happen to contain. The defaults are chosen for a
 * small LAN-scale network; the constructor validates them so a misconfiguration fails fast
 * instead of silently disabling a bound.
 *
 * @property provideFanout how many of the closest peers a `provide` announces to (also the
 * candidate window of a walk).
 * @property walkParallelism Kademlia's alpha: how many peers one walk round queries at once.
 * @property maxWalkRounds hard cap on walk rounds, independent of the deadline.
 * @property perRpcTimeout upper bound for one dial-plus-request-response exchange.
 * @property maxCloserPeersPerResponse how many `closerPeers` / `providerPeers` entries of one
 * response are looked at; the rest is dropped before any of it is parsed.
 * @property maxAddressesPerPeer how many addresses are kept per peer, wherever an address list
 * is stored, answered or dialled.
 * @property maxAddressesPerIp how many of those may point at the same IP (a circuit address
 * counts against the relay's IP) - the bound that keeps one peer entry from being turned into a
 * port scan of a single host.
 * @property maxAddressBytes serialized size above which a single address is discarded unparsed.
 * @property maxProvidersPerKey provider records kept per DHT key (and the cap on how many
 * providers one lookup or fetch attempts).
 * @property providerStoreKeyCapacity DHT keys the provider store keeps before evicting the least
 * recently used one.
 * @property maxConcurrentDhtOperations simultaneous `provide` / `findProviders` / lookup-driven
 * `get` calls; further callers fail fast with "DHT busy" instead of queueing without bound.
 * @property maxConcurrentFetches simultaneous Bitswap fetch attempts.
 * @property fetchConnectTimeout how long one Bitswap fetch attempt may spend connecting to one
 * provider before that provider is given up on (the fetch slot is held meanwhile).
 * @property streamCloseGrace how long an initiator waits for the responder to close a stream
 * after `closeWrite` before it resets the stream itself.
 */
data class DhtLimits(
    val provideFanout: Int = 20,
    val walkParallelism: Int = 3,
    val maxWalkRounds: Int = 8,
    val perRpcTimeout: Duration = Duration.ofSeconds(2),
    val maxCloserPeersPerResponse: Int = 20,
    val maxAddressesPerPeer: Int = 8,
    val maxAddressesPerIp: Int = 2,
    val maxAddressBytes: Int = 256,
    val maxProvidersPerKey: Int = 8,
    val providerStoreKeyCapacity: Int = 1024,
    val maxConcurrentDhtOperations: Int = 8,
    val maxConcurrentFetches: Int = 4,
    val fetchConnectTimeout: Duration = Duration.ofSeconds(5),
    val streamCloseGrace: Duration = Duration.ofSeconds(1),
) {
    init {
        require(provideFanout in 1..MAX_PROVIDE_FANOUT) { "provideFanout must be in 1..$MAX_PROVIDE_FANOUT" }
        require(walkParallelism > 0) { "walkParallelism must be positive" }
        require(walkParallelism <= provideFanout) { "walkParallelism must not exceed provideFanout" }
        require(maxWalkRounds in 1..MAX_WALK_ROUNDS) { "maxWalkRounds must be in 1..$MAX_WALK_ROUNDS" }
        require(!perRpcTimeout.isNegative && !perRpcTimeout.isZero) { "perRpcTimeout must be positive" }
        require(maxCloserPeersPerResponse > 0) { "maxCloserPeersPerResponse must be positive" }
        require(maxAddressesPerPeer in 1..MAX_ADDRESSES_PER_PEER) {
            "maxAddressesPerPeer must be in 1..$MAX_ADDRESSES_PER_PEER"
        }
        require(maxAddressesPerIp > 0) { "maxAddressesPerIp must be positive" }
        require(maxAddressesPerIp <= maxAddressesPerPeer) { "maxAddressesPerIp must not exceed maxAddressesPerPeer" }
        require(maxAddressBytes >= MIN_ADDRESS_BYTES) { "maxAddressBytes must be at least $MIN_ADDRESS_BYTES" }
        require(maxProvidersPerKey > 0) { "maxProvidersPerKey must be positive" }
        require(providerStoreKeyCapacity > 0) { "providerStoreKeyCapacity must be positive" }
        require(maxConcurrentDhtOperations > 0) { "maxConcurrentDhtOperations must be positive" }
        require(maxConcurrentFetches > 0) { "maxConcurrentFetches must be positive" }
        require(!fetchConnectTimeout.isNegative && !fetchConnectTimeout.isZero) {
            "fetchConnectTimeout must be positive"
        }
        require(!streamCloseGrace.isNegative && !streamCloseGrace.isZero) { "streamCloseGrace must be positive" }
    }

    private companion object {
        const val MAX_PROVIDE_FANOUT = 64
        const val MAX_WALK_ROUNDS = 32
        const val MAX_ADDRESSES_PER_PEER = 64
        const val MIN_ADDRESS_BYTES = 32
    }
}
