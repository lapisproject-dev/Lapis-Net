package net.lapisphilosophorum.lapisnet.storage

import io.ipfs.cid.Cid
import java.time.Duration
import java.util.concurrent.atomic.AtomicReference

/**
 * A [RemoteContentSource] that is bound late (wave V0.10.0-J2): [NabuStorage] is attached before the onion wire and the
 * anonymity runtime exist, so the node hands it this placeholder and [bind]s the circuit-based source once the runtime
 * runs. Fail closed: while nothing is bound (before the start, after [unbind] at the stop) every call answers `null`.
 */
class DeferredRemoteContentSource : RemoteContentSource {
    private val target = AtomicReference<RemoteContentSource?>(null)

    fun bind(source: RemoteContentSource) {
        target.set(source)
    }

    fun unbind() {
        target.set(null)
    }

    val isBound: Boolean get() = target.get() != null

    override fun fetchBlock(
        cid: Cid,
        maxBytes: Int,
        timeout: Duration,
    ): ByteArray? = target.get()?.fetchBlock(cid, maxBytes, timeout)

    override fun resolveIpnsRecord(
        name: ByteArray,
        timeout: Duration,
    ): ByteArray? = target.get()?.resolveIpnsRecord(name, timeout)

    override fun blockIfCached(cid: Cid): ByteArray? = target.get()?.blockIfCached(cid)
}
