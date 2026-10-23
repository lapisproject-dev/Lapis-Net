package net.lapisphilosophorum.lapisnet.directory

import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity

/** What a mode switch requires before the new mode's own record can be published. */
sealed interface DirectoryTransitionPlan {
    /** Same mode as before, a first start without any state, or a start in ON without a persisted OFF: nothing to retire. */
    data object None : DirectoryTransitionPlan

    /**
     * OFF to ON: publish this address-free [PeerRecord] (`addresses = []`, a sequence number above every earlier
     * record) so that v0.12.0 and older nodes drop the address entry too. It is sent from the own node, once, and only
     * after a persisted OFF state (the node demonstrably ran in normal mode, so the identity-to-IP link is public
     * up to this moment anyway). Never built for a first start or a damaged state file.
     */
    class Tombstone(
        val record: PeerRecord,
    ) : DirectoryTransitionPlan

    /** ON to OFF: publish this revocation so that it covers every still-valid anonymous record. */
    class Revocation(
        val record: AnonymousPeerRecord,
    ) : DirectoryTransitionPlan
}

/**
 * Detects a switch of the [DirectoryAnonymityMode] across restarts (wave V0.10.0-D) and builds the record that
 * retires the other mode's entry. Sequence numbers are `max(lastSequence + 1, nowMillis)`, i.e. the same epoch
 * millisecond scale as [PeerRecord], persisted through a [DirectoryModeStore] so they never repeat or regress.
 */
class DirectoryModeTransition(
    private val identity: DualKeyIdentity,
    private val store: DirectoryModeStore,
    private val clockMillis: () -> Long = System::currentTimeMillis,
) {
    /**
     * The mode of the previous run; [DirectoryAnonymityMode.OFF] when the store has no (valid) state. Use
     * [hasPersistedState] to tell "no state" apart from a persisted OFF.
     */
    fun previousMode(): DirectoryAnonymityMode = store.load()?.mode ?: DirectoryAnonymityMode.OFF

    /** Whether a previous run left (valid) state behind; `false` for a brand-new identity or a damaged state file. */
    fun hasPersistedState(): Boolean = store.load() != null

    /** Allocates (and persists) the next sequence number for a record of [mode]. */
    @Synchronized
    fun nextSequence(mode: DirectoryAnonymityMode): Long {
        val seq = maxOf((store.load()?.lastSequence ?: -1L) + 1, clockMillis())
        store.save(DirectoryModeState(mode, seq))
        return seq
    }

    /**
     * Builds the retiring record for a switch from [previousMode] to [target]. The caller publishes it and then calls
     * [nextSequence] with [target] for the first record of the new mode (so its sequence number is above the retiring
     * record's). If the process dies in between, the next start sees the old mode again and builds a fresh,
     * higher-numbered retiring record.
     */
    @Synchronized
    fun prepare(target: DirectoryAnonymityMode): DirectoryTransitionPlan {
        val state = store.load()
        // No (valid) state: the node was never known to run in normal mode, so there is nothing to retire. In
        // particular no identity-bound tombstone may be sent from this node (it would create the identity-to-IP link).
        if (state == null && target == DirectoryAnonymityMode.ON) return DirectoryTransitionPlan.None
        val previous = state?.mode ?: DirectoryAnonymityMode.OFF
        if (previous == target) return DirectoryTransitionPlan.None
        val nowSeconds = clockMillis() / 1000
        return when (target) {
            DirectoryAnonymityMode.ON -> {
                val seq = nextSequence(previous)
                DirectoryTransitionPlan.Tombstone(
                    PeerRecord.create(
                        identity,
                        addresses = emptyList(),
                        capabilities = emptySet(),
                        sequenceNumber = seq,
                        notValidAfterEpochSecond = nowSeconds + PeerRecord.MAX_TTL_WINDOW_SECONDS,
                        nowEpochSecond = nowSeconds,
                    ),
                )
            }
            DirectoryAnonymityMode.OFF -> {
                val seq = nextSequence(previous)
                DirectoryTransitionPlan.Revocation(
                    AnonymousPeerRecord.createRevocation(
                        identity,
                        seq,
                        nowSeconds + AnonymousPeerRecord.MAX_TTL_WINDOW_SECONDS,
                        nowSeconds,
                    ),
                )
            }
        }
    }
}
