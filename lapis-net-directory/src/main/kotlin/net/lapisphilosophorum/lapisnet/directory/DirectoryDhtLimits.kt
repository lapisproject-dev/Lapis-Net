package net.lapisphilosophorum.lapisnet.directory

import java.time.Duration

/**
 * Every bound of [DirectoryDht], in one place; the constructor validates them so a misconfiguration
 * fails fast.
 *
 * @property maxIdentitiesPerCatchUp identities one [DirectoryDht.catchUp] call looks at; the rest is
 * skipped (a caller feeds this from untrusted-adjacent sources such as a contact list).
 * @property minResolveInterval how long after a lookup for an identity the next network lookup for the same
 * identity is refused as throttled.
 * @property negativeCacheTtl the same for a lookup that found nothing valid - longer, because asking again
 * for something that is not there only leaks interest.
 * @property resolveTrackerCapacity identities the two timers above remember (LRU).
 * @property minRepublishInterval minimum monotonic time between two [DirectoryDht.publishOwn] network
 * publications, as [PeerPresenceAnnouncer] does for gossip.
 * @property defaultTimeout deadline of a publish or lookup when the caller gives none.
 * @property maxRecordValidity cap on how far ahead a published IPNS record is valid, whatever the inner
 * records' own expiry; matches `DhtLimits.maxRecordValidity` of the storage layer's defaults.
 * @property maxOutboxEntriesPerValue outbox entries (V0.9.14) one published value carries at most.
 * @property maxOutboxBytes byte budget of the outbox part of one value.
 * @property maxTrackedOutboxEntries default capacity of a [DhtOutbox].
 * @property rendezvousEnabled whether [DirectoryDht.publishOwn] announces recipients and
 * [DirectoryDht.discoverInbox] may be used.
 * @property maxRendezvousAnnouncesPerPublish distinct recipients announced per publication.
 * @property rendezvousReannounceInterval a recipient is announced again no earlier than this (monotonic).
 * @property rendezvousTrackerCapacity recipients the announcement timer remembers (LRU).
 * @property maxRendezvousProviders providers one [DirectoryDht.discoverInbox] asks for and resolves.
 * @property minDiscoveryInterval minimum monotonic time between two network discoveries.
 * @property maxDispatchedEntriesPerResolve outbox entries one resolve hands to consumers at most.
 */
data class DirectoryDhtLimits(
    val maxIdentitiesPerCatchUp: Int = 32,
    val minResolveInterval: Duration = Duration.ofSeconds(30),
    val negativeCacheTtl: Duration = Duration.ofSeconds(60),
    val resolveTrackerCapacity: Int = 1024,
    val minRepublishInterval: Duration = Duration.ofSeconds(300),
    val defaultTimeout: Duration = Duration.ofSeconds(10),
    val maxRecordValidity: Duration = Duration.ofDays(7),
    val maxOutboxEntriesPerValue: Int = 24,
    val maxOutboxBytes: Int = DirectoryDhtValueCodec.MAX_OUTBOX_BYTES,
    val maxTrackedOutboxEntries: Int = 256,
    val rendezvousEnabled: Boolean = true,
    val maxRendezvousAnnouncesPerPublish: Int = 8,
    val rendezvousReannounceInterval: Duration = Duration.ofHours(1),
    val rendezvousTrackerCapacity: Int = 1024,
    val maxRendezvousProviders: Int = 8,
    val minDiscoveryInterval: Duration = Duration.ofSeconds(300),
    val maxDispatchedEntriesPerResolve: Int = 24,
) {
    init {
        require(maxIdentitiesPerCatchUp > 0) { "maxIdentitiesPerCatchUp must be positive" }
        require(!minResolveInterval.isNegative) { "minResolveInterval must not be negative" }
        require(!negativeCacheTtl.isNegative) { "negativeCacheTtl must not be negative" }
        require(
            negativeCacheTtl >= minResolveInterval,
        ) { "negativeCacheTtl must not be shorter than minResolveInterval" }
        require(resolveTrackerCapacity > 0) { "resolveTrackerCapacity must be positive" }
        require(!minRepublishInterval.isNegative) { "minRepublishInterval must not be negative" }
        require(!defaultTimeout.isNegative && !defaultTimeout.isZero) { "defaultTimeout must be positive" }
        require(!maxRecordValidity.isNegative && !maxRecordValidity.isZero) { "maxRecordValidity must be positive" }
        require(maxOutboxEntriesPerValue in 1..DirectoryDhtValueCodec.MAX_OUTBOX_ENTRIES_PER_VALUE) {
            "maxOutboxEntriesPerValue must be in 1..${DirectoryDhtValueCodec.MAX_OUTBOX_ENTRIES_PER_VALUE}"
        }
        require(maxOutboxBytes in 1..DirectoryDhtValueCodec.MAX_OUTBOX_BYTES) {
            "maxOutboxBytes must be in 1..${DirectoryDhtValueCodec.MAX_OUTBOX_BYTES}"
        }
        require(maxTrackedOutboxEntries > 0) { "maxTrackedOutboxEntries must be positive" }
        require(maxRendezvousAnnouncesPerPublish > 0) { "maxRendezvousAnnouncesPerPublish must be positive" }
        require(!rendezvousReannounceInterval.isNegative) { "rendezvousReannounceInterval must not be negative" }
        require(rendezvousTrackerCapacity > 0) { "rendezvousTrackerCapacity must be positive" }
        require(maxRendezvousProviders in 1..MAX_PROVIDERS_PER_KEY) {
            "maxRendezvousProviders must be in 1..$MAX_PROVIDERS_PER_KEY"
        }
        require(!minDiscoveryInterval.isNegative) { "minDiscoveryInterval must not be negative" }
        require(maxDispatchedEntriesPerResolve > 0) { "maxDispatchedEntriesPerResolve must be positive" }
    }

    companion object {
        /** `DhtLimits.maxProvidersPerKey` default of the storage layer; one lookup never gets more. */
        const val MAX_PROVIDERS_PER_KEY: Int = 8
    }
}
