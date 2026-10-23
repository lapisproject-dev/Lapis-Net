package net.lapisphilosophorum.lapisnet.directory

import net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.time.Instant

/** A test identity running in anonymity mode, with builders for its anonymous records. */
internal class AnonymousPublisher(
    val identity: DualKeyIdentity = DualKeyIdentity.generate(),
    val serviceKey: Ed25519KeyPair = Ed25519KeyPair.generate(),
) {
    val key: Secp256k1PublicKey = identity.secp256k1KeyPair.publicKey

    fun record(
        sequence: Long,
        expiresInSeconds: Long = 3600,
        capabilities: Set<AnonymousCapability> = setOf(AnonymousCapability.DM),
        digest: ByteArray? = null,
        now: Long = Instant.now().epochSecond,
        service: Ed25519KeyPair = serviceKey,
    ): AnonymousPeerRecord =
        AnonymousPeerRecord.create(identity, service, capabilities, digest, sequence, now + expiresInSeconds, now)

    fun revocation(
        sequence: Long,
        expiresInSeconds: Long = 3600,
        now: Long = Instant.now().epochSecond,
    ): AnonymousPeerRecord = AnonymousPeerRecord.createRevocation(identity, sequence, now + expiresInSeconds, now)

    /** An address-bearing record of the same identity (sequence numbers on the shared scale). */
    fun peerRecord(
        sequence: Long,
        expiresInSeconds: Long = 3600,
        port: Int = 4001,
    ): PeerRecord =
        PeerRecord.create(
            identity,
            listOf(
                io.libp2p.core.multiformats
                    .Multiaddr("/ip4/127.0.0.1/tcp/$port"),
            ),
            setOf(PeerCapability.DM),
            sequence,
            Instant.now().epochSecond + expiresInSeconds,
        )
}

/** Signs an arbitrary (possibly inconsistent) body the way an honest signer would, for adversarial tests. */
internal fun resign(
    signer: DualKeyIdentity,
    record: AnonymousPeerRecord,
    serviceProof: ByteArray = record.servicePossessionProof,
    sequence: Long = record.sequenceNumber,
    notValidAfter: Long = record.notValidAfterEpochSecond,
    serviceKey: net.lapisphilosophorum.lapisnet.identity.Ed25519PublicKey? = record.serviceKey,
): AnonymousPeerRecord {
    val body =
        AnonymousPeerRecordCodec.encodeSignedBody(
            signer.secp256k1KeyPair.publicKey,
            serviceKey,
            serviceProof,
            record.capabilities,
            record.prekeyBundleDigest,
            sequence,
            notValidAfter,
        )
    val signature =
        signer.secp256k1KeyPair.sign(domainSeparatedDigest("LapisNet:anonymous-peer-record:v1", body))
    return AnonymousPeerRecord.fromDecoded(
        signer.secp256k1KeyPair.publicKey,
        serviceKey,
        serviceProof,
        record.capabilities,
        record.prekeyBundleDigest,
        sequence,
        notValidAfter,
        signature,
    )
}
