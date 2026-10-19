package net.lapisphilosophorum.lapisnet.directory

import io.ipfs.cid.Cid
import io.libp2p.core.PeerId
import io.libp2p.core.crypto.PrivKey
import net.lapisphilosophorum.lapisnet.storage.IpnsPublishResult
import net.lapisphilosophorum.lapisnet.storage.IpnsValue
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.time.Duration
import java.time.Instant

/**
 * The seam between [DirectoryDht] and the DHT: publish a signed value under the signer's IPNS name,
 * resolve the value of a name. The production implementation is [NabuIpnsValueStore]; unit tests of
 * [DirectoryDht] substitute a fake and so need no network.
 */
internal interface IpnsValueStore {
    /** The longest validity the underlying layer accepts for a published record, if it has such a bound. */
    val maxRecordValidity: Duration? get() = null

    fun publish(
        signingKey: PrivKey,
        value: ByteArray,
        sequence: Long,
        notValidAfter: Instant,
        ttl: Duration,
        timeout: Duration,
    ): IpnsPublishResult

    fun resolve(
        publisher: PeerId,
        timeout: Duration,
    ): IpnsValue?
}

internal class NabuIpnsValueStore(
    private val storage: NabuStorage,
) : IpnsValueStore {
    override val maxRecordValidity: Duration get() = storage.maxRecordValidity

    override fun publish(
        signingKey: PrivKey,
        value: ByteArray,
        sequence: Long,
        notValidAfter: Instant,
        ttl: Duration,
        timeout: Duration,
    ): IpnsPublishResult = storage.publishIpnsValue(signingKey, value, sequence, notValidAfter, ttl, timeout)

    override fun resolve(
        publisher: PeerId,
        timeout: Duration,
    ): IpnsValue? = storage.resolveIpnsValue(publisher, timeout)
}

/**
 * The seam for rendezvous provider records (V0.9.14): announce "I can provide this key" and look up who does.
 * The production implementation is [NabuRendezvousStore]; tests of [DirectoryDht] substitute a fake.
 */
internal interface RendezvousStore {
    /** @return the number of peers the provider record was sent to (the protocol has no acknowledgement). */
    fun provide(
        cid: Cid,
        timeout: Duration,
    ): Int

    fun findProviders(
        cid: Cid,
        max: Int,
        timeout: Duration,
    ): Set<PeerId>
}

internal class NabuRendezvousStore(
    private val storage: NabuStorage,
) : RendezvousStore {
    override fun provide(
        cid: Cid,
        timeout: Duration,
    ): Int = storage.provide(cid, timeout)

    override fun findProviders(
        cid: Cid,
        max: Int,
        timeout: Duration,
    ): Set<PeerId> = storage.findProviders(cid, max, timeout)
}
