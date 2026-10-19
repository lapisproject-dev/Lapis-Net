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
 */
data class DirectoryDhtLimits(
    val maxIdentitiesPerCatchUp: Int = 32,
    val minResolveInterval: Duration = Duration.ofSeconds(30),
    val negativeCacheTtl: Duration = Duration.ofSeconds(60),
    val resolveTrackerCapacity: Int = 1024,
    val minRepublishInterval: Duration = Duration.ofSeconds(300),
    val defaultTimeout: Duration = Duration.ofSeconds(10),
    val maxRecordValidity: Duration = Duration.ofDays(7),
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
    }
}
