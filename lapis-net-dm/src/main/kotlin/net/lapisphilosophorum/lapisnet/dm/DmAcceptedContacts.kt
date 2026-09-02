package net.lapisphilosophorum.lapisnet.dm

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey

/**
 * Bounded, IN-MEMORY-ONLY set of peers this node considers a known contact for [DmAcceptancePolicy]
 * purposes - V0.8.6. A peer becomes "accepted" either because a caller explicitly calls [accept]
 * (the intended hook for a future UI's "Accept" action on a quarantined conversation, not yet built
 * this wave), OR because this node itself sent that peer a message - [DmSessionManager] calls
 * [accept] on every outbound send when it is constructed with a non-null accepted-contacts instance
 * (see [DmSessionManager.attach]'s own `acceptedContacts` parameter) - in both cases, a deliberate
 * local decision, never inferred from protocol state alone (see [DmAcceptancePolicy]'s own doc
 * comment for why an existing ratchet session is deliberately NOT treated as evidence of
 * acceptance).
 *
 * **Explicit, deliberate scope cut: not persisted to disk**, mirroring [DmStore]'s own identical cut
 * - a process restart forgets every accept decision. See `docs/roadmap.adoc`'s V0.8.6 section for
 * this alongside [DmStore]'s.
 */
class DmAcceptedContacts(
    private val maxTracked: Int = MAX_TRACKED_ACCEPTED_CONTACTS,
) {
    private val accepted =
        object : LinkedHashMap<Secp256k1PublicKey, Boolean>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Secp256k1PublicKey, Boolean>): Boolean =
                size > maxTracked
        }

    @Synchronized
    fun accept(peer: Secp256k1PublicKey) {
        accepted[peer] = true
    }

    /** **Deliberately `get(peer) != null`, NOT `containsKey(peer)`** (V0.8.6 hardening-pass
     * finding): [accepted] is access-ordered (`LinkedHashMap(16, 0.75f, true)`) for LRU eviction,
     * but `LinkedHashMap.containsKey` does NOT call `afterNodeAccess` the way `get` does - only
     * `get` refreshes an entry's recency. Using `containsKey` here would mean this class's LRU
     * order is driven ENTIRELY by [accept] calls, never by actual read traffic through
     * [isAccepted]: a peer the user explicitly accepted once, and who the local node otherwise
     * only ever *receives from* (never sends to, so [accept] never re-fires for them - see this
     * class's own class doc comment), would silently fall out of [accepted] after
     * [maxTracked] unrelated `accept()` calls even though every one of their messages kept probing
     * [isAccepted] and finding them accepted. `get` fixes this: every successful lookup counts as
     * fresh use and refreshes the entry's position, exactly like [VeritasPathCache]'s identical
     * `cache[key]` (not `containsKey`) read. */
    @Synchronized
    fun isAccepted(peer: Secp256k1PublicKey): Boolean = accepted[peer] != null

    companion object {
        /** Generous headroom, provisional magnitude - same "not derived from pilot data" framing as
         * every sibling numeric cap in this codebase. */
        const val MAX_TRACKED_ACCEPTED_CONTACTS = 4_096
    }
}
