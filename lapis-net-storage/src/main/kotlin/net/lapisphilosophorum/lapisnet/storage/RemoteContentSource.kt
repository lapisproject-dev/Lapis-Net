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
}
