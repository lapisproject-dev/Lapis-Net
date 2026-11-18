package net.lapisphilosophorum.lapisnet.browser

import io.ipfs.cid.Cid
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import net.lapisphilosophorum.lapisnet.storage.RemoteBlockState

/** `contentState` of a timeline post whose body is here. */
internal const val CONTENT_STATE_LOCAL = "local"

/** A lookup of the body through circuits is running (anonymity mode). */
internal const val CONTENT_STATE_FETCHING = "fetching"

/** Two relays answered that they do not find the body (anonymity mode). */
internal const val CONTENT_STATE_NOT_FOUND = "not-found"

/** The body is not here and no confirmed answer exists. */
internal const val CONTENT_STATE_UNAVAILABLE = "unavailable"

/**
 * Wave V0.10.0-J3: the bodies of the timeline posts for `GET /api/timeline`.
 *
 * - Anonymity mode off: exactly the earlier behaviour, `storage.get(cid)` per post (`"local"`, or the marker text and
 *   `"unavailable"`).
 * - Anonymity mode on: never blocks on the network. Each body comes from the local stores or from the circuit source's
 *   view ([NabuStorage.localOrRemoteState]); a miss starts a background lookup through circuits, newest posts first, at
 *   most [maxNewLookupsPerRequest] new lookups per request (the next request starts the next ones). A post without its
 *   body gets [CONTENT_UNAVAILABLE_MARKER] as text (never server free text) and one of four states: `"fetching"`,
 *   `"not-found"` (confirmed by two relays only), `"unavailable"` (an unconfirmed NOT_FOUND, a failure, or no lookup
 *   started yet). The response keeps the order of the entries.
 */
internal class TimelineBodyResolver(
    private val anonymity: Boolean,
    /** Mode off: the plain storage lookup. */
    private val get: (Cid) -> ByteArray?,
    /** Mode on: the non-blocking local-or-remote view. */
    private val localOrRemote: (Cid, Boolean) -> NabuStorage.LocalOrRemote,
    private val maxNewLookupsPerRequest: Int = MAX_NEW_LOOKUPS_PER_REQUEST,
) {
    constructor(storage: NabuStorage, anonymity: Boolean, maxNewLookupsPerRequest: Int = MAX_NEW_LOOKUPS_PER_REQUEST) :
        this(
            anonymity,
            { cid -> storage.get(cid) },
            { cid, schedule -> storage.localOrRemoteState(cid, schedule) },
            maxNewLookupsPerRequest,
        )

    init {
        require(maxNewLookupsPerRequest >= 0) { "the lookup budget must not be negative" }
    }

    data class Body(
        val text: String,
        val contentState: String,
    )

    fun resolve(entries: List<TimelineEntry>): Map<Cid, Body> =
        if (anonymity) resolveAnonymous(entries) else entries.associate { it.cid to resolvePlain(it.cid) }

    private fun resolvePlain(cid: Cid): Body {
        // A real local fault THROWS (see NabuStorage.get); runCatching degrades that one entry to the marker
        // and never leaks the exception message (it can contain local paths).
        val text = runCatching { get(cid) }.getOrNull()?.toString(Charsets.UTF_8)
        return if (text !=
            null
        ) {
            Body(text, CONTENT_STATE_LOCAL)
        } else {
            Body(CONTENT_UNAVAILABLE_MARKER, CONTENT_STATE_UNAVAILABLE)
        }
    }

    private fun resolveAnonymous(entries: List<TimelineEntry>): Map<Cid, Body> {
        val out = LinkedHashMap<Cid, Body>()
        var scheduled = 0
        // newest first: they get the lookup budget; the response order is not changed (the caller maps by CID)
        for (entry in entries.sortedByDescending { it.publishedAtEpochSeconds }) {
            if (entry.cid in out) continue
            val view = runCatching { localOrRemote(entry.cid, scheduled < maxNewLookupsPerRequest) }.getOrNull()
            if (view?.newlyScheduled == true) scheduled++
            val bytes = view?.bytes
            out[entry.cid] =
                when {
                    view == null -> Body(CONTENT_UNAVAILABLE_MARKER, CONTENT_STATE_UNAVAILABLE)
                    view.state == RemoteBlockState.CACHED && bytes != null ->
                        Body(bytes.toString(Charsets.UTF_8), CONTENT_STATE_LOCAL)
                    view.state == RemoteBlockState.FETCHING -> Body(CONTENT_UNAVAILABLE_MARKER, CONTENT_STATE_FETCHING)
                    view.state == RemoteBlockState.NOT_FOUND ->
                        Body(
                            CONTENT_UNAVAILABLE_MARKER,
                            CONTENT_STATE_NOT_FOUND,
                        )
                    else -> Body(CONTENT_UNAVAILABLE_MARKER, CONTENT_STATE_UNAVAILABLE)
                }
        }
        return out
    }

    companion object {
        /** New background lookups one timeline request may start (wave V0.10.0-J3). */
        const val MAX_NEW_LOOKUPS_PER_REQUEST = 8
    }
}
