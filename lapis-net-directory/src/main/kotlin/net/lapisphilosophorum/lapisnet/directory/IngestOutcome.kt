package net.lapisphilosophorum.lapisnet.directory

/**
 * What [PeerDirectoryGossip.ingestVerified] / [PrekeyBundleGossip.ingestVerified] did with an
 * already cryptographically verified record or bundle - shared by the gossip validators (which map it to
 * a pubsub verdict) and the DHT fallback (which only cares whether the value ended up in the index).
 */
internal enum class IngestOutcome {
    /** Persisted (or the persistence cap was reached) and added to the index. */
    ACCEPTED,

    /** Persisted, but [add][PeerRecordIndex.add] declined: a duplicate or an even newer record won a race. */
    LOST_RACE,

    /** Exact duplicate or stale (sequence-number-superseded): nothing was persisted or indexed. */
    DECLINED,

    /** `NabuStorage.put` failed; the persistence reservation was released again. */
    PERSIST_FAILED,
}
