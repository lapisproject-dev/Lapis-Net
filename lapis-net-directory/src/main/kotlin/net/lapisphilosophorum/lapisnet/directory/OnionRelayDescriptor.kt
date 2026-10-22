package net.lapisphilosophorum.lapisnet.directory

import io.libp2p.core.PeerId
import io.libp2p.crypto.keys.unmarshalEd25519PublicKey
import net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.IdentityBinding
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.identity.verify
import net.lapisphilosophorum.lapisnet.onion.OnionKeyBinding
import java.nio.ByteBuffer

private const val DESCRIPTOR_DOMAIN_TAG = "LapisNet:onion-relay-descriptor:v1"
private const val DESCRIPTOR_POSSESSION_DOMAIN_TAG = "LapisNet:onion-relay-descriptor-possession:v1"
private const val SIGNATURE_SIZE = 64

private fun possessionDigest(
    identity: Secp256k1PublicKey,
    onionKeyFingerprint: ByteArray,
    sequenceNumber: Long,
): ByteArray =
    domainSeparatedDigest(
        DESCRIPTOR_POSSESSION_DOMAIN_TAG,
        identity.bytes,
        onionKeyFingerprint,
        ByteBuffer.allocate(8).putLong(sequenceNumber).array(),
    )

/**
 * A relay's signed, publicly enumerable advertisement: "this identity (reachable as this libp2p peer)
 * currently answers onion CREATEs with this onion key" (V0.10.0-B). Distinct from a [PeerRecord] on
 * purpose: a [PeerRecord] says where a node can be reached, a descriptor says that it is willing to
 * be a hop. `PeerCapability` deliberately gets no new bit (v0.12.0 readers reject unknown bits); the
 * descriptor alone signals the relay property.
 *
 * Three independent proofs, none sufficient alone (same discipline as [PeerRecord]):
 * 1. the outer secp256k1 signature over the whole signed body (domain tag
 *    `LapisNet:onion-relay-descriptor:v1`),
 * 2. the [IdentityBinding] (identity vouches for the Ed25519 transport key) PLUS an Ed25519
 *    possession proof that the transport key holder agrees (own domain tag, covers identity, onion key
 *    fingerprint and sequence number), so an identity cannot point at a stranger's peer ID,
 * 3. the [OnionKeyBinding] (identity vouches for the onion key), which must belong to the same identity.
 *
 * Validity: `now <= notValidAfter <= now + MAX_TTL_WINDOW + MAX_CLOCK_SKEW`, and the descriptor never
 * outlives its onion key. The `family` list of the design is not carried in this wave: the wire format
 * keeps a count byte that MUST be zero.
 */
class OnionRelayDescriptor private constructor(
    val identity: Secp256k1PublicKey,
    val binding: IdentityBinding,
    val onionKeyBinding: OnionKeyBinding,
    val sequenceNumber: Long,
    val notValidAfterEpochSecond: Long,
    possessionProof: ByteArray,
    signature: ByteArray,
) {
    private val storedPossessionProof = possessionProof.copyOf()
    private val storedSignature = signature.copyOf()

    val possessionProof: ByteArray get() = storedPossessionProof.copyOf()
    val signature: ByteArray get() = storedSignature.copyOf()

    val peerId: PeerId get() = PeerId.fromPubKey(unmarshalEd25519PublicKey(binding.ed25519PublicKey.bytes))

    init {
        require(storedPossessionProof.size == SIGNATURE_SIZE) { "possession proof must be $SIGNATURE_SIZE bytes" }
        require(storedSignature.size == SIGNATURE_SIZE) { "signature must be $SIGNATURE_SIZE bytes" }
        require(sequenceNumber >= 0) { "sequenceNumber must be >= 0" }
    }

    fun contentId(): ByteArray = OnionRelayDescriptorCodec.contentId(this)

    /** The relay-id digest under which CREATE/EXTEND address this relay. */
    fun relayIdDigest(): ByteArray = onionKeyBinding.relayIdDigest()

    override fun equals(other: Any?): Boolean =
        other is OnionRelayDescriptor &&
            identity == other.identity &&
            binding == other.binding &&
            onionKeyBinding == other.onionKeyBinding &&
            sequenceNumber == other.sequenceNumber &&
            notValidAfterEpochSecond == other.notValidAfterEpochSecond &&
            storedPossessionProof.contentEquals(other.storedPossessionProof) &&
            storedSignature.contentEquals(other.storedSignature)

    override fun hashCode(): Int = 31 * identity.hashCode() + sequenceNumber.hashCode()

    /** Never prints key material or the peer ID. */
    override fun toString(): String = "OnionRelayDescriptor(identity=${identity.fingerprint()}, seq=$sequenceNumber)"

    companion object {
        const val MAX_TTL_WINDOW_SECONDS = 86_400L
        const val MAX_CLOCK_SKEW_SECONDS = 300L

        private fun signingDigest(body: ByteArray): ByteArray = domainSeparatedDigest(DESCRIPTOR_DOMAIN_TAG, body)

        fun create(
            identity: DualKeyIdentity,
            onionKeyBinding: OnionKeyBinding,
            sequenceNumber: Long,
            notValidAfterEpochSecond: Long,
            nowEpochSecond: Long,
        ): OnionRelayDescriptor {
            val identityKey = identity.secp256k1KeyPair.publicKey
            require(identity.verifyBinding()) { "identity's own binding does not verify" }
            require(onionKeyBinding.relayIdentity == identityKey) { "onion key binding belongs to another identity" }
            require(OnionKeyBinding.verify(onionKeyBinding, nowEpochSecond)) { "onion key binding invalid or expired" }
            require(sequenceNumber >= 0) { "sequenceNumber must be >= 0" }
            require(notValidAfterEpochSecond <= nowEpochSecond + MAX_TTL_WINDOW_SECONDS) {
                "descriptor validity exceeds the $MAX_TTL_WINDOW_SECONDS second window"
            }
            require(notValidAfterEpochSecond <= onionKeyBinding.notValidAfterEpochSecond) {
                "a descriptor must not outlive its onion key"
            }
            val proof =
                identity.ed25519KeyPair.sign(
                    possessionDigest(identityKey, onionKeyBinding.onionKeyFingerprint(), sequenceNumber),
                )
            val body =
                OnionRelayDescriptorCodec.encodeSignedBody(
                    identityKey,
                    identity.binding,
                    onionKeyBinding,
                    sequenceNumber,
                    notValidAfterEpochSecond,
                    proof,
                )
            val signature = identity.secp256k1KeyPair.sign(signingDigest(body))
            return OnionRelayDescriptor(
                identityKey,
                identity.binding,
                onionKeyBinding,
                sequenceNumber,
                notValidAfterEpochSecond,
                proof,
                signature,
            )
        }

        /** Complete verification; never throws, any internal failure is a `false`. */
        fun verify(
            d: OnionRelayDescriptor,
            nowEpochSecond: Long,
        ): Boolean =
            try {
                d.notValidAfterEpochSecond >= nowEpochSecond &&
                    d.notValidAfterEpochSecond <= nowEpochSecond + MAX_TTL_WINDOW_SECONDS + MAX_CLOCK_SKEW_SECONDS &&
                    d.notValidAfterEpochSecond <= d.onionKeyBinding.notValidAfterEpochSecond &&
                    d.onionKeyBinding.relayIdentity == d.identity &&
                    OnionKeyBinding.verify(d.onionKeyBinding, nowEpochSecond) &&
                    IdentityBinding.verify(d.identity, d.binding) &&
                    d.binding.ed25519PublicKey.verify(
                        possessionDigest(d.identity, d.onionKeyBinding.onionKeyFingerprint(), d.sequenceNumber),
                        d.possessionProof,
                    ) &&
                    d.identity.verify(
                        signingDigest(OnionRelayDescriptorCodec.encodeSignedBody(d)),
                        d.signature,
                    )
            } catch (e: RuntimeException) {
                false
            }

        internal fun fromDecoded(
            identity: Secp256k1PublicKey,
            binding: IdentityBinding,
            onionKeyBinding: OnionKeyBinding,
            sequenceNumber: Long,
            notValidAfterEpochSecond: Long,
            possessionProof: ByteArray,
            signature: ByteArray,
        ): OnionRelayDescriptor =
            OnionRelayDescriptor(
                identity,
                binding,
                onionKeyBinding,
                sequenceNumber,
                notValidAfterEpochSecond,
                possessionProof,
                signature,
            )
    }
}
