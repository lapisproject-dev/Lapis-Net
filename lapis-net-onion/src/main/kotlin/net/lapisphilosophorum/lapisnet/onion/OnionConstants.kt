package net.lapisphilosophorum.lapisnet.onion

/**
 * Wire and policy constants of the onion-circuit foundation (wave V0.10.0-A). Every cell on a link
 * is exactly [CELL_SIZE] bytes - for every command, in both directions - so that neither length
 * nor command type distinguishes cells to an observer (beyond what the link encryption added by a
 * later wave hides anyway).
 */
object OnionConstants {
    /** Fixed on-wire cell size, every cell, every command. */
    const val CELL_SIZE = 1024

    /** Circuit id is a big-endian 32-bit integer, chosen per link; 0 is reserved for PADDING. */
    const val CIRCUIT_ID_SIZE = 4

    /** circuit id + command byte. */
    const val HEADER_SIZE = CIRCUIT_ID_SIZE + 1

    /** Cell body size: 1019 bytes. */
    const val BODY_SIZE = CELL_SIZE - HEADER_SIZE

    /** Poly1305 tag. */
    const val TAG_SIZE = 16

    /** Per-hop overhead: AEAD tag plus the one-byte layer type inside the sealed plaintext. */
    const val LAYER_OVERHEAD = TAG_SIZE + 1

    /** Default circuit length. Policy minimum (3 in the production path) is enforced in wave B/E. */
    const val DEFAULT_HOPS = 3

    /** Hard technical maximum of hops per circuit. */
    const val MAX_HOPS = 5

    /** Hard rotation bound per hop and direction, far below the 64-bit nonce counter space. */
    const val MAX_CELLS_PER_DIRECTION = 1L shl 32

    /** Size of relay identity digests and onion key fingerprints. */
    const val DIGEST_SIZE = 32

    /** Handshake type 1: ntor over X25519 with SHA-256. */
    const val HANDSHAKE_NTOR = 1

    /** Maximum size of the opaque link specifier inside an EXTEND payload. */
    const val MAX_LINK_SPECIFIER = 128

    const val PROTOCOL_ID = "LapisNet:ntor-x25519-sha256:v1"

    /** The relay-message header and the largest hop count must leave a usable payload. */
    const val MIN_PAYLOAD_AT_MAX_HOPS = 512

    init {
        check(BODY_SIZE - MAX_HOPS * LAYER_OVERHEAD - 5 >= MIN_PAYLOAD_AT_MAX_HOPS) {
            "MAX_HOPS leaves less than $MIN_PAYLOAD_AT_MAX_HOPS bytes of payload"
        }
    }
}
