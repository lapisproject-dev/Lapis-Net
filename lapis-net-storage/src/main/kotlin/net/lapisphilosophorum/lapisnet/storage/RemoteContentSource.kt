package net.lapisphilosophorum.lapisnet.storage

import io.ipfs.cid.Cid
import java.time.Duration

/**
 * Where a [NabuStorage] in [StorageNetworkMode.LOCAL_ONLY] gets content it does not hold (wave V0.10.0-J1a: the
 * interface only; the circuit-based implementation follows in wave V0.10.0-J2). Lives in this module so that the
 * storage does not depend on the onion layer.
 *
 * Contract for implementations: they must never fall back to a direct connection, and everything they return is
 * untrusted. [NabuStorage] checks a block against its CID and an IPNS record against the requested name before using
 * either.
 */
interface RemoteContentSource {
    /**
     * Fetches the block with [cid] (at most [maxBytes]); `null` when it was not found or the fetch failed. May block up
     * to [timeout]. Callers on a request thread use [blockIfCached] instead.
     */
    fun fetchBlock(
        cid: Cid,
        maxBytes: Int,
        timeout: Duration,
    ): ByteArray?

    /**
     * The raw signed IPNS record stored under [name] (the routing key `/ipns/<multihash>`), or `null`. May block up to
     * [timeout].
     */
    fun resolveIpnsRecord(
        name: ByteArray,
        timeout: Duration,
    ): ByteArray?

    /** A block this source already fetched (never blocks); may schedule a background fetch. Default: none. */
    fun blockIfCached(cid: Cid): ByteArray? = null

    /**
     * Wave V0.10.0-J3: what this source knows about [cid], without blocking. With [schedule] a miss starts at most one
     * background lookup ([RemoteBlockView.newlyScheduled] says whether this call started it); without it nothing is
     * started. The default answers from [blockIfCached] only.
     */
    fun blockState(
        cid: Cid,
        schedule: Boolean,
    ): RemoteBlockView =
        (if (schedule) blockIfCached(cid) else null)
            ?.let { RemoteBlockView(RemoteBlockState.CACHED, it, newlyScheduled = false) }
            ?: RemoteBlockView.NONE
}

/** Wave V0.10.0-J3: the state of a block at a [RemoteContentSource]. */
enum class RemoteBlockState {
    /** Fetched and verified; the bytes are there. */
    CACHED,

    /** A lookup is running. */
    FETCHING,

    /** Two relays answered NOT_FOUND (confirmed). */
    NOT_FOUND,

    /** The last lookup failed or found nothing confirmed. */
    UNAVAILABLE,

    /** Nothing known and nothing started. */
    NONE,
}

/** What [RemoteContentSource.blockState] answers; [bytes] only with [RemoteBlockState.CACHED]. */
class RemoteBlockView(
    val state: RemoteBlockState,
    bytes: ByteArray?,
    /** `true` when this very call started the background lookup. */
    val newlyScheduled: Boolean,
) {
    private val stored = bytes?.copyOf()
    val bytes: ByteArray? get() = stored?.copyOf()

    override fun toString(): String = "RemoteBlockView($state, length=${stored?.size}, newlyScheduled=$newlyScheduled)"

    companion object {
        val NONE = RemoteBlockView(RemoteBlockState.NONE, null, newlyScheduled = false)
    }
}
