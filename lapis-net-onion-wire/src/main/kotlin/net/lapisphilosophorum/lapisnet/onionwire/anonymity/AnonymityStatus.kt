package net.lapisphilosophorum.lapisnet.onionwire.anonymity

import net.lapisphilosophorum.lapisnet.networking.config.AnonymityPaddingMode

/** Stable, content-free error codes of anonymity mode. Never carries an address, identity or key. */
enum class AnonymityErrorCode(
    val wire: String,
) {
    NONE("none"),
    INSUFFICIENT_RELAYS("insufficient-relays"),
    BUILD_FAILED("build-failed"),
    BUILD_TIMEOUT("build-timeout"),
    RATE_LIMITED("rate-limited"),
    GUARD_STATE_RESET("guard-state-reset"),
    PUBLISH_FAILED("publish-failed"),

    /** A send found no anonymous way to the recipient (a counter and this code only, never the recipient). */
    RECIPIENT_UNREACHABLE("recipient-unreachable"),
}

/** Status of anonymity mode for the node status (CLI start line, browser panel). Enums and numbers only. */
data class AnonymityStatus(
    /** `"off"` or `"on"`. */
    val mode: String,
    /** `true` whenever the mode is on: call media is not anonymised and guards and bootstrap peers see the address. */
    val incomplete: Boolean,
    val guards: Int,
    val activeCircuits: Int,
    val lastError: AnonymityErrorCode,
    val lastErrorAgeSeconds: Long?,
    /** Sends that found no anonymous way to the recipient since start (a number, no target). */
    val recipientUnreachableCount: Long = 0,
    /** V0.10.0-H: `"standard"` or `"off"` (padding and timing protection). */
    val padding: String = "off",
    /** Warm circuits waiting for their one use (a number). */
    val warmCircuits: Int = 0,
    /** Cover cells sent since start (a number). */
    val coverCellsSent: Long = 0,
    /** Cover cells not sent because the cover budget was spent (a number). */
    val coverBudgetExhausted: Long = 0,
    /** V0.10.0-J1b: `"bootstrapping"`, `"guards-only"`, `"unconfined"` (no confinement) or `"off"`. */
    val connectionState: String = "off",
    /** V0.10.0-J1b: live connections to the two guards (a number). */
    val guardConnections: Int = 0,
    /** V0.10.0-J1b: relay directory snapshots requested since start (a number). */
    val snapshotFetches: Long = 0,
    /** V0.10.0-J1b: snapshot entries not taken (invalid, over budget, stale, expired; a number). */
    val snapshotRejectedEntries: Long = 0,
    /** V0.10.0-J1b: the first guard choice relies on a single configured directory source (assumption Q14). */
    val singleDirectorySource: Boolean = false,
    /** V0.10.0-J1b: no bootstrap peer is configured, so a confined node can reach no relay (`no-bootstrap-peers`). */
    val noBootstrapPeers: Boolean = false,
    /** V0.10.0-J1b: no source serves snapshots; the guard choice relies on the gossip view (`gossip-only-relay-view`). */
    val gossipOnlyRelayView: Boolean = false,
    /** V0.10.0-J3: lookup requests of callers (see `LookupStatusCounters` for how the numbers add up). */
    val lookupRequested: Long = 0,
    val lookupFound: Long = 0,
    /** NOT_FOUND confirmed by two relays. */
    val lookupNotFound: Long = 0,
    /** NOT_FOUND from one relay only (the cross-check was impossible or ended without an answer). */
    val lookupNotFoundUnconfirmed: Long = 0,
    val lookupFailed: Long = 0,
    /** Answers that did not verify (the relay goes on a 24-hour backoff). */
    val lookupRejected: Long = 0,
    /** Lookup relays known, usable and on backoff (numbers only, never an identity). */
    val lookupRelaysAvailable: Int = 0,
    val lookupRelaysKnown: Int = 0,
    val lookupRelaysOnBackoff: Int = 0,
) {
    /** This status with the lookup counters of [c] (wave V0.10.0-J3). */
    fun withLookup(c: net.lapisphilosophorum.lapisnet.onionwire.lookup.LookupStatusCounters): AnonymityStatus =
        copy(
            lookupRequested = c.requested,
            lookupFound = c.found,
            lookupNotFound = c.notFound,
            lookupNotFoundUnconfirmed = c.notFoundUnconfirmed,
            lookupFailed = c.failed,
            lookupRejected = c.rejected,
            lookupRelaysAvailable = c.relaysAvailable,
            lookupRelaysKnown = c.relaysKnown,
            lookupRelaysOnBackoff = c.relaysOnBackoff,
        )

    companion object {
        val OFF = AnonymityStatus("off", false, 0, 0, AnonymityErrorCode.NONE, null)
    }
}

/**
 * The warning of waves V0.10.0-H to J3, in four fixed texts (calls off or exposed, padding standard or off). The
 * browser's `app.js` and docs/anonymity.adoc carry the same four character for character, and a test compares them.
 * Wave V0.10.0-J3 replaced "Anonymity mode is incomplete: direct messages, ..." by a head that also says experimental
 * and unreviewed, and split the text into sentences (". " instead of "; " before the calls and padding parts).
 */
private const val WARNING_HEAD =
    "Anonymity mode is experimental and incomplete, and it has had no external security review. " +
        "Direct messages, mail and call signals travel over circuits"
private const val WARNING_PADDED =
    ", padded to size classes with cover cells towards the guard; this does not hide traffic from an observer " +
        "who sees both ends"

/**
 * What is still exposed. Wave V0.10.0-J1a replaced "the network mesh, DHT lookups and fetches still show ..."; wave
 * V0.10.0-J1b replaced "but it still meshes over direct connections that show your address"; wave V0.10.0-J2 replaced
 * "neither serves nor queries the DHT or content"; wave V0.10.0-J3 replaced "the transport key is fresh per run and the
 * node neither serves the DHT or content nor queries them directly (lookups go through circuits to relays that see what
 * is asked), ..." by the text below (no mail or name lookups are claimed: none is wired in this mode); wave Q20 replaced
 * "today such lookups usually find nothing, because nodes do not announce posts in the DHT" (nodes in normal mode now
 * announce the newest post bodies they hold); wave Q21 replaced "Attachments and inbox rendezvous records are not reachable in
 * this mode." (attachments are now fetched from the sender's onion service; that wording, Q21-F, is not yet confirmed by
 * the user).
 */
private const val WARNING_REMAINING =
    "The transport key is fresh per run. The node connects only to its two guards, which see your address, " +
        "when you are online and which topics you receive. At every start, and while it lacks relays or a guard " +
        "connection, it also connects to its bootstrap peers, which see your address. Missing posts are looked up " +
        "through circuits: the last relay of a circuit sees what is asked and when, but not by whom, and up to four " +
        "post lookups on one circuit are linked to each other; such lookups find a post only if a node in normal " +
        "mode announces it in the DHT, which nodes do for the newest posts they hold. Attachments are fetched from " +
        "the sender's onion service while the sender is online (up to 4 MiB each); inbox rendezvous records are not " +
        "reachable in this mode. Posting, votes and trust grants are unavailable."
private const val WARNING_CALLS_OFF_TAIL =
    "Calls are off because call media would reveal your IP address. " + WARNING_REMAINING
private const val WARNING_CALLS_EXPOSED_TAIL =
    "Calls are allowed (--anonymity-allow-call-media=true) and call media connects directly: every call reveals " +
        "your IP address to the other party and to network observers. " + WARNING_REMAINING

/** The sentence that `--anonymity-padding=off` adds: what an observer of the connection can then see. */
const val ANONYMITY_PADDING_OFF_SENTENCE: String =
    "Padding is off (--anonymity-padding=off), so message sizes and timing are visible to an observer of your connection"

/** Logged once at start and shown in the CLI and the browser whenever anonymity mode is on (calls off, padding standard). */
const val ANONYMITY_INCOMPLETE_WARNING: String = WARNING_HEAD + WARNING_PADDED + ". " + WARNING_CALLS_OFF_TAIL

/** Used instead of [ANONYMITY_INCOMPLETE_WARNING] when `--anonymity-allow-call-media=true`. */
const val ANONYMITY_INCOMPLETE_WARNING_CALL_MEDIA_EXPOSED: String =
    WARNING_HEAD + WARNING_PADDED + ". " + WARNING_CALLS_EXPOSED_TAIL

/** Calls off, `--anonymity-padding=off`. */
const val ANONYMITY_INCOMPLETE_WARNING_PADDING_OFF: String =
    WARNING_HEAD + ". " + ANONYMITY_PADDING_OFF_SENTENCE + ". " + WARNING_CALLS_OFF_TAIL

/** Calls allowed, `--anonymity-padding=off`. */
const val ANONYMITY_INCOMPLETE_WARNING_PADDING_OFF_CALL_MEDIA_EXPOSED: String =
    WARNING_HEAD + ". " + ANONYMITY_PADDING_OFF_SENTENCE + ". " + WARNING_CALLS_EXPOSED_TAIL

/** The warning for a combination of the two options. */
fun anonymityIncompleteWarning(
    callMediaAllowed: Boolean,
    padding: AnonymityPaddingMode,
): String =
    when (padding) {
        AnonymityPaddingMode.STANDARD ->
            if (callMediaAllowed) ANONYMITY_INCOMPLETE_WARNING_CALL_MEDIA_EXPOSED else ANONYMITY_INCOMPLETE_WARNING
        AnonymityPaddingMode.OFF ->
            if (callMediaAllowed) {
                ANONYMITY_INCOMPLETE_WARNING_PADDING_OFF_CALL_MEDIA_EXPOSED
            } else {
                ANONYMITY_INCOMPLETE_WARNING_PADDING_OFF
            }
    }
