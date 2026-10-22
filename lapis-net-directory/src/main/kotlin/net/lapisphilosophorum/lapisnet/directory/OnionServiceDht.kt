package net.lapisphilosophorum.lapisnet.directory

import io.github.oshai.kotlinlogging.KotlinLogging
import io.libp2p.core.PeerId
import io.libp2p.crypto.keys.unmarshalEd25519PrivateKey
import io.libp2p.crypto.keys.unmarshalEd25519PublicKey
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.onion.CellFormatException
import net.lapisphilosophorum.lapisnet.onion.OnionServiceAddress
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptor
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptorCodec
import net.lapisphilosophorum.lapisnet.storage.IpnsValue
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.time.Duration
import java.time.Instant

private val logger = KotlinLogging.logger {}

private val MAGIC = byteArrayOf('L'.code.toByte(), 'N'.code.toByte(), 'H'.code.toByte(), 'S'.code.toByte())
private const val VALUE_VERSION: Byte = 1

/** Checks a value that came out of the DHT for an onion address, completely, before anything of it is used. */
internal object OnionServiceDhtValidator {
    const val MAX_VALUE_BYTES = 5 + OnionServiceDescriptorCodec.MAX_ENCODED_SIZE

    fun validate(
        resolved: IpnsValue,
        address: OnionServiceAddress,
        nowEpochSecond: Long,
    ): OnionServiceDescriptor? {
        val value = resolved.value
        if (value.size < 5 + OnionServiceDescriptorCodec.FIXED_SIZE || value.size > MAX_VALUE_BYTES) return null
        if (!value.copyOfRange(0, 4).contentEquals(MAGIC) || value[4] != VALUE_VERSION) return null
        val descriptor =
            try {
                OnionServiceDescriptorCodec.decode(value.copyOfRange(5, value.size))
            } catch (e: CellFormatException) {
                return null
            }
        // The IPNS record was signed by the key behind `publisher`; it must be the service key the address names,
        // and the descriptor must be signed by that same key.
        val expectedPublisher =
            try {
                PeerId.fromPubKey(unmarshalEd25519PublicKey(address.serviceKey.bytes))
            } catch (e: RuntimeException) {
                return null
            }
        if (resolved.publisher != expectedPublisher) return null
        if (descriptor.serviceKey != address.serviceKey) return null
        if (!OnionServiceDescriptor.verify(descriptor, nowEpochSecond)) return null
        return descriptor
    }
}

/**
 * Publishes and resolves [OnionServiceDescriptor]s through the DHT (wave V0.10.0-C). The record lives under the
 * IPNS name of the SERVICE key itself - never in the node's own [DirectoryDhtValue] - so the value contains no
 * link to the node's peer ID or Lapis identity and does not compete with the node's single directory writer.
 * That separates the contents; it does not hide the network position: the DHT peers that store or serve the
 * record see the publishing node's IP together with the onion address until publication runs through circuits
 * (wave D). Nothing calls this by itself, and it is not wired into the node or the CLI.
 */
class OnionServiceDht internal constructor(
    private val values: IpnsValueStore,
    private val wallClock: () -> Instant = Instant::now,
) {
    /**
     * Publishes [descriptor] under the IPNS name of [serviceKey].
     *
     * @throws IllegalArgumentException if the descriptor is not signed by [serviceKey], does not verify, or its
     * validity is not in the future.
     * @throws net.lapisphilosophorum.lapisnet.storage.NabuStorageException if the DHT layer fails.
     */
    fun publish(
        serviceKey: Ed25519KeyPair,
        descriptor: OnionServiceDescriptor,
        timeout: Duration = Duration.ofSeconds(10),
    ): Int {
        val now = wallClock()
        require(descriptor.serviceKey == serviceKey.publicKey) { "the descriptor belongs to another service key" }
        require(OnionServiceDescriptor.verify(descriptor, now.epochSecond)) { "the descriptor does not verify" }
        val value = MAGIC + byteArrayOf(VALUE_VERSION) + OnionServiceDescriptorCodec.encode(descriptor)
        val maxValidity = values.maxRecordValidity ?: Duration.ofDays(7)
        val notValidAfter =
            minOf(Instant.ofEpochSecond(descriptor.notValidAfterEpochSecond), now.plus(maxValidity))
        val result =
            values.publish(
                unmarshalEd25519PrivateKey(serviceKey.privateKey.seed),
                value,
                maxOf(descriptor.sequenceNumber, 0),
                notValidAfter,
                Duration.ofMinutes(5),
                timeout,
            )
        return result.acknowledged
    }

    /** The verified descriptor of [address], or `null` (nothing found, invalid, expired, or the lookup failed). */
    fun resolve(
        address: OnionServiceAddress,
        timeout: Duration = Duration.ofSeconds(10),
    ): OnionServiceDescriptor? {
        val publisher =
            try {
                PeerId.fromPubKey(unmarshalEd25519PublicKey(address.serviceKey.bytes))
            } catch (e: RuntimeException) {
                return null
            }
        val resolved =
            try {
                values.resolve(publisher, timeout)
            } catch (e: RuntimeException) {
                logger.debug { "onion service lookup failed: ${e.javaClass.simpleName}" }
                return null
            } ?: return null
        return OnionServiceDhtValidator.validate(resolved, address, wallClock().epochSecond)
    }

    companion object {
        fun attach(storage: NabuStorage): OnionServiceDht = OnionServiceDht(NabuIpnsValueStore(storage))
    }
}
