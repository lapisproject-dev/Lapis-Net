package net.lapisphilosophorum.lapisnet.directory

import io.libp2p.core.PeerId
import io.libp2p.core.crypto.PrivKey
import io.libp2p.core.multiformats.Multiaddr
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.EncryptionKeyBinding
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.networking.deriveLibp2pPeerId
import net.lapisphilosophorum.lapisnet.ratchet.OneTimePrekey
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundle
import net.lapisphilosophorum.lapisnet.storage.IpnsPublishResult
import net.lapisphilosophorum.lapisnet.storage.IpnsValue
import net.lapisphilosophorum.lapisnet.storage.NabuStorageBusyException
import java.time.Duration
import java.time.Instant

/** One test identity with builders for everything it can publish. */
internal class DirectoryPublisher(
    val identity: DualKeyIdentity = DualKeyIdentity.generate(),
) {
    val key: Secp256k1PublicKey = identity.secp256k1KeyPair.publicKey
    val peerId: PeerId = identity.deriveLibp2pPeerId()
    private val x25519 = X25519KeyPair.generate()
    val encryptionBinding: EncryptionKeyBinding =
        EncryptionKeyBinding.create(
            identity.secp256k1KeyPair,
            x25519.publicKey,
        )

    fun peerRecord(
        sequence: Long = 0,
        expiresInSeconds: Long = 3600,
        port: Int = 4001,
    ): PeerRecord =
        PeerRecord.create(
            identity,
            listOf(Multiaddr("/ip4/127.0.0.1/tcp/$port")),
            setOf(PeerCapability.DM),
            sequence,
            Instant.now().epochSecond + expiresInSeconds,
        )

    fun bundle(
        sequence: Long = 0,
        expiresInSeconds: Long = 3600,
        oneTimePrekeys: Int = 1,
    ): PrekeyBundle =
        PrekeyBundle.create(
            identity = identity,
            encryptionBinding = encryptionBinding,
            signedPrekeyId = 0,
            signedPrekey = X25519KeyPair.generate().publicKey,
            oneTimePrekeys = List(oneTimePrekeys) { OneTimePrekey(it, X25519KeyPair.generate().publicKey) },
            sequenceNumber = sequence,
            notValidAfterEpochSecond = Instant.now().epochSecond + expiresInSeconds,
        )

    fun value(
        peerRecord: PeerRecord? = peerRecord(),
        bundle: PrekeyBundle? = bundle(),
    ): DirectoryDhtValue =
        DirectoryDhtValue(
            key,
            identity.binding,
            peerRecord?.let { PeerRecordCodec.encode(it) },
            bundle?.let {
                net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundleCodec
                    .encode(it)
            },
        )
}

/** [bytes] as an [IpnsValue] published by [publisher] (what `resolveIpnsValue` would hand back). */
internal fun ipnsValueOf(
    publisher: PeerId,
    bytes: ByteArray,
    sequence: Long = 1,
): IpnsValue = IpnsValue(publisher, bytes, sequence, Instant.now().plusSeconds(3600), Duration.ofMinutes(5))

/** An in-memory [IpnsValueStore] that behaves like a perfectly reliable DHT, and counts its calls. */
internal class FakeIpnsValueStore : IpnsValueStore {
    val published = mutableListOf<Published>()
    val resolveCalls = mutableListOf<PeerId>()
    private val byPublisher = HashMap<PeerId, IpnsValue>()

    /** When set, [maxRecordValidity] reports this (a store with its own, smaller cap). */
    var maxRecordValidityOverride: Duration? = null

    override val maxRecordValidity: Duration? get() = maxRecordValidityOverride

    /** Runs on every [resolve] call, e.g. to advance an injected clock. */
    var onResolve: (() -> Unit)? = null

    /** When set, [resolve] throws this. */
    var resolveFailure: RuntimeException? = null

    /** When set, [resolve] returns this instead of looking up. */
    var resolveOverride: IpnsValue? = null

    class Published(
        val publisher: PeerId,
        val value: ByteArray,
        val sequence: Long,
        val notValidAfter: Instant,
    )

    override fun publish(
        signingKey: PrivKey,
        value: ByteArray,
        sequence: Long,
        notValidAfter: Instant,
        ttl: Duration,
        timeout: Duration,
    ): IpnsPublishResult {
        val publisher = PeerId.fromPubKey(signingKey.publicKey())
        published += Published(publisher, value, sequence, notValidAfter)
        byPublisher[publisher] = IpnsValue(publisher, value, sequence, notValidAfter, ttl)
        return IpnsPublishResult(1, 1)
    }

    override fun resolve(
        publisher: PeerId,
        timeout: Duration,
    ): IpnsValue? {
        resolveCalls += publisher
        onResolve?.invoke()
        resolveFailure?.let { throw it }
        return resolveOverride ?: byPublisher[publisher]
    }

    fun busy(): FakeIpnsValueStore = also { resolveFailure = NabuStorageBusyException() }
}
