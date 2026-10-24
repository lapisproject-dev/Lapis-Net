package net.lapisphilosophorum.lapisnet.dm

/**
 * V0.10.0-F1: which transport carries a direct message. [DIRECT] is the classic libp2p stream and
 * Nabu mailbox path; [CIRCUIT] is the anonymity-mode path (onion circuits, no direct dial, no
 * address in the offline pointer). The route is a property of the node's anonymity mode, never of
 * an individual message, and there is deliberately no per-message fallback from one to the other.
 */
enum class DmRoute(
    val wire: String,
) {
    DIRECT("direct"),
    CIRCUIT("circuit"),
}
