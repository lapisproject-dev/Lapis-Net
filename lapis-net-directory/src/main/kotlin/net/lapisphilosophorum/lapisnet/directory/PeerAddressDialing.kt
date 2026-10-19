package net.lapisphilosophorum.lapisnet.directory

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.storage.NabuStorage

private val logger = KotlinLogging.logger {}

/**
 * The one place that turns the addresses of a (gossip- or DHT-supplied, hence attacker-influenced)
 * [PeerRecord] into dialable address-book entries of a [NabuStorage] - shared by the mailbox poller
 * (lapis-net-dm) and the DHT mail fetcher (lapis-net-mail), so both apply [MultiaddrHygiene] identically.
 */
object PeerAddressDialing {
    /**
     * Registers every address of [record] that [MultiaddrHygiene] does not block, each with the `/p2p/` component
     * of `record.peerId`. An address that already carries a conflicting `/p2p` component is skipped alone
     * (`Multiaddr.withP2P` throws `IllegalArgumentException` for it) - one malformed address must not make an
     * otherwise reachable sender unfetchable.
     *
     * @return `false` if [MultiaddrHygiene] blocked every address (nothing was registered, nothing should be dialed);
     * `true` otherwise, also when single addresses were skipped for a conflicting `/p2p` component (the peer may
     * still be reachable over an existing connection).
     * @throws net.lapisphilosophorum.lapisnet.storage.NabuStorageException if the storage layer fails.
     */
    fun registerSafeAddresses(
        storage: NabuStorage,
        record: PeerRecord,
    ): Boolean {
        val safe = record.addresses.filterNot { MultiaddrHygiene.isBlockedPrivateOrLocal(it) }
        if (safe.isEmpty()) return false
        for (address in safe) {
            val withP2P = runCatching { address.withP2P(record.peerId) }.getOrNull()
            if (withP2P == null) {
                logger.debug { "skipping one address that carries a conflicting /p2p component" }
            } else {
                storage.registerPeerAddress(withP2P)
            }
        }
        return true
    }
}
