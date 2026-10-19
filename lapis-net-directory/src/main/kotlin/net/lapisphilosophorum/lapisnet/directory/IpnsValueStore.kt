package net.lapisphilosophorum.lapisnet.directory

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
