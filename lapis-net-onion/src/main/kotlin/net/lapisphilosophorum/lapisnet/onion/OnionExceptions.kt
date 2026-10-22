package net.lapisphilosophorum.lapisnet.onion

/** A cell or body failed structural validation. Deliberately undifferentiated: the message never
 * contains any part of the offending input. */
class CellFormatException(
    message: String,
) : RuntimeException(message)

/** The ntor handshake failed. One undifferentiated type for every cause (bad AUTH, wrong relay id,
 * degenerate DH output, malformed input) so that no failure-reason oracle exists. */
class OnionHandshakeException : RuntimeException("onion handshake failed")

/** An onion layer failed its authentication check (or was structurally invalid after
 * authentication). The affected circuit must be destroyed; there is no retry. */
class OnionIntegrityException : RuntimeException("onion layer integrity check failed")

/** A hard per-direction cell bound or a relay resource limit was reached. */
class OnionResourceLimitException(
    message: String,
) : RuntimeException(message)
