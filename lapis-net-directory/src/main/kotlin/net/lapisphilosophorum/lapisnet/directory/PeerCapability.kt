package net.lapisphilosophorum.lapisnet.directory

/**
 * A [PeerRecord]'s advertised capability set - what this identity's node self-reports supporting
 * at the addresses it publishes. A single-byte bitmask on the wire (see [PeerRecordCodec]'s
 * layout), mirroring `net.lapisphilosophorum.lapisnet.mail.EncryptionMode`'s reserved-wire-value
 * forward-compatibility discipline: reserved bits must be zero, enforced in
 * [PeerRecordCodec.decode].
 *
 * **Self-reported only - never verified.** Mirrors this record's own "no reachability
 * verification of advertised addresses" scope cut (see [PeerRecord]'s class doc comment): a stale
 * node or an attacker can claim any capability bits with no way for a reader of this record to
 * confirm them before actually trying to use one.
 *
 * **Deliberately does NOT include an SFU_CAPABLE flag.** The V0.8 arc was reduced in scope on
 * 2026-08-04 to cut MLS/conferencing/SFU entirely - there is no consumer for such a flag in this
 * reduced arc, so it is not defined here. A future wave that reintroduces group calling can add a
 * new bit (0x08) without touching this codec's version or invalidating any V0.8.1 record already
 * on the wire.
 */
enum class PeerCapability(
    val bit: Int,
) {
    /** Direct 1:1 messaging (X3DH/Double Ratchet, V0.8.2+) is claimed available at this record's
     * addresses. */
    DM(0x01),

    /** Voice/video calling (a later V0.8 sub-wave) is claimed available at this record's
     * addresses. */
    CALL(0x02),

    /** This identity's `lapis-net-mail` inbox gossip topic
     * (`net.lapisphilosophorum.lapisnet.mail.InboxTopics.forRecipient`, V0.9.1) is claimed
     * actively served right now - a self-reported "someone may be listening" signal, not a
     * capability gate: any identity can always be mailed via its gossip topic regardless of this
     * flag, and this bit is never verified (see this enum's class doc comment). */
    MAILBOX(0x04),

    /**
     * This identity's node is willing to act as a **Circuit-Relay-v2 relay** for other peers, so a
     * peer behind NAT may ask it for a reservation
     * (`net.lapisphilosophorum.lapisnet.networking.relay.RelayReservationClient.reserve`).
     *
     * Added in the NAT-traversal wave, using exactly the forward-compatibility path this enum's own
     * doc comment anticipated: a new bit `0x08`, no codec version change, no invalidation of any
     * record already on the wire. Records minted before this wave simply do not set it. Older
     * *readers* reject a record that does set it as a reserved-bits violation - the intended,
     * documented meaning of the reserved-bits rule, and the reason capability bits are the right
     * place for this rather than a new codec field would have been.
     *
     * **Self-reported and unverified like every other bit here** - see this enum's class doc
     * comment. A peer that advertises this and then refuses every reservation costs the asker one
     * refused request, nothing more; a peer that advertises it honestly is simply a *candidate*,
     * and choosing which candidate to actually use stays the caller's decision. Nothing in this
     * codebase auto-reserves on the strength of this flag.
     *
     * **No compensation is implied.** Relay service is, in this wave, purely reputational
     * (Madli, `lapis-net-madli`) - see
     * `net.lapisphilosophorum.lapisnet.networking.relay.RelayConfig`'s doc comment.
     */
    RELAY(0x08),
    ;

    companion object {
        /** Every currently-defined bit OR-ed together - [PeerRecordCodec.decode] rejects any
         * other set bit as a reserved-bits violation. */
        const val KNOWN_BITS_MASK = 0x0F

        fun setFromBits(bits: Int): Set<PeerCapability> = entries.filterTo(mutableSetOf()) { bits and it.bit != 0 }

        fun bitsFrom(capabilities: Set<PeerCapability>): Int =
            capabilities.fold(0) { acc, capability -> acc or capability.bit }
    }
}
