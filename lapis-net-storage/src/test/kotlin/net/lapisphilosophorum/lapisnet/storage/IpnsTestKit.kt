package net.lapisphilosophorum.lapisnet.storage

import com.google.protobuf.ByteString
import io.libp2p.core.PeerId
import io.libp2p.core.crypto.KeyType
import io.libp2p.core.crypto.PrivKey
import io.libp2p.core.crypto.generateKeyPair
import org.peergos.protocol.ipns.pb.Ipns
import java.time.Duration
import java.time.Instant

/** An Ed25519 key pair with its peer ID and IPNS key - the publisher side of a test. */
internal class IpnsIdentity(
    val privKey: PrivKey,
) {
    val peerId: PeerId = PeerId.fromPubKey(privKey.publicKey())
    val key: ByteArray = ipnsKeyFor(peerId)

    fun record(
        value: ByteArray = "hello".toByteArray(),
        sequence: Long = 1,
        notValidAfter: Instant = Instant.now().plus(Duration.ofHours(1)),
        ttl: Duration = Duration.ofMinutes(5),
    ): ByteArray = IpnsRecordCodec.create(privKey, value, sequence, notValidAfter, ttl)

    fun validated(
        value: ByteArray = "hello".toByteArray(),
        sequence: Long = 1,
        notValidAfter: Instant = Instant.now().plus(Duration.ofHours(1)),
    ): ValidatedIpnsRecord =
        IpnsRecordCodec.validate(
            key,
            record(value, sequence, notValidAfter),
            Instant.now(),
            DhtLimits(),
        )!!

    companion object {
        fun generate(): IpnsIdentity = IpnsIdentity(generateKeyPair(KeyType.ED25519).first)
    }
}

/** Rebuilds [record] with some protobuf fields replaced; everything else (including the signature) stays. */
internal fun tamper(
    record: ByteArray,
    change: (Ipns.IpnsEntry.Builder) -> Unit,
): ByteArray {
    val builder = Ipns.IpnsEntry.parseFrom(record).toBuilder()
    change(builder)
    return builder.build().toByteArray()
}

/** A record whose `data` is [data], signed correctly by [identity] over exactly that data. */
internal fun signedWithData(
    identity: IpnsIdentity,
    data: ByteArray,
    value: ByteArray = "hello".toByteArray(),
    sequence: Long = 1,
    validity: String = "2099-01-01T00:00:00.0Z",
): ByteArray =
    Ipns.IpnsEntry
        .newBuilder()
        .setSequence(sequence)
        .setTtl(1_000_000_000L)
        .setValue(ByteString.copyFrom(value))
        .setValidityType(Ipns.IpnsEntry.ValidityType.EOL)
        .setValidity(ByteString.copyFromUtf8(validity))
        .setData(ByteString.copyFrom(data))
        .setSignatureV2(
            ByteString.copyFrom(identity.privKey.sign("ipns-signature:".toByteArray() + data)),
        ).build()
        .toByteArray()
