package net.lapisphilosophorum.lapisnet.madli

import io.ipfs.cid.Cid

/**
 * The signals a replication policy consumes for one candidate [Cid]. [currentProviderCount] comes
 * from DHT `findProviders`, which did not work end-to-end until V0.9.8 (see
 * `docs/architecture.adoc`'s Storage section; it now does, but no caller feeds this policy from it
 * yet) - callers supply a best-effort/`0` value. [authorVeritasMicros] is the observer's own Veritas
 * standing of the content's author; [socialResonance] folds Karma/LTR standing (higher = more
 * likely to be requested by others).
 */
data class ReplicationCandidate(
    val cid: Cid,
    val authorVeritasMicros: Int,
    val socialResonance: Double,
    val currentProviderCount: Int,
)

/**
 * A pluggable, purely local replication policy - the protocol itself does not mandate replication;
 * this is view-local policy consuming Veritas/Karma-LTR/DHT-provider-count signals, per the
 * vault's three replication criteria (author standing, social resonance, current under-service).
 */
fun interface MadliReplicationPolicy {
    fun shouldReplicate(candidate: ReplicationCandidate): Boolean
}

object MadliReplicationPolicies {
    /** Default: the protocol never mandates replication. */
    val NEVER = MadliReplicationPolicy { false }

    /**
     * Reference implementation per the vault's three criteria: replicate high-Veritas-author OR
     * high-resonance content that is ALSO under-served (few current DHT holders). Pure; thresholds
     * are policy parameters, not hardcoded protocol constants.
     */
    fun underServedImportant(
        minAuthorVeritasMicros: Int,
        minSocialResonance: Double,
        maxProviderCount: Int,
    ): MadliReplicationPolicy =
        MadliReplicationPolicy { candidate ->
            val isImportant =
                candidate.authorVeritasMicros >= minAuthorVeritasMicros ||
                    candidate.socialResonance >= minSocialResonance
            val isUnderServed = candidate.currentProviderCount <= maxProviderCount
            isImportant && isUnderServed
        }
}
