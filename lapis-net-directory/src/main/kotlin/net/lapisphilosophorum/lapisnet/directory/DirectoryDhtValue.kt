package net.lapisphilosophorum.lapisnet.directory

import net.lapisphilosophorum.lapisnet.identity.IdentityBinding
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey

/**
 * The envelope published under one IPNS name (V0.9.13): [identity], the [binding] that proves the
 * IPNS-signing Ed25519 key is its transport key, and the encoded [PeerRecord] and/or [PrekeyBundle].
 *
 * **Why an envelope.** An IPNS name is a public key, and a node has exactly one Ed25519 key - so
 * there is exactly one IPNS name per node, and the peer record and the prekey bundle have to share it.
 * [identity] and [binding] are repeated here (a [PeerRecord] carries them itself, a [PrekeyBundle] does
 * not) so that a bundle-only value can be checked just the same: the IPNS signature proves the holder of
 * the Ed25519 key wrote the value, the [binding] proves [identity] vouches for exactly that key.
 *
 * The parts are kept as their original encoded bytes ([peerRecordBytes], [prekeyBundleBytes]), not
 * re-encoded: persisting them into `NabuStorage` must yield the same CID as the gossip path does.
 * At least one part is present. Structure only - nothing in here is verified; see [DirectoryDhtValidator].
 */
class DirectoryDhtValue(
    val identity: Secp256k1PublicKey,
    val binding: IdentityBinding,
    peerRecordBytes: ByteArray?,
    prekeyBundleBytes: ByteArray?,
) {
    private val storedPeerRecord: ByteArray? = peerRecordBytes?.copyOf()
    private val storedPrekeyBundle: ByteArray? = prekeyBundleBytes?.copyOf()

    /** The encoded peer record, or `null` (a fresh copy on every access). */
    val peerRecordBytes: ByteArray? get() = storedPeerRecord?.copyOf()

    /** The encoded prekey bundle, or `null` (a fresh copy on every access). */
    val prekeyBundleBytes: ByteArray? get() = storedPrekeyBundle?.copyOf()

    init {
        require(storedPeerRecord != null || storedPrekeyBundle != null) {
            "a directory value carries a peer record, a prekey bundle or both"
        }
        require(storedPeerRecord == null || storedPeerRecord.isNotEmpty()) { "peer record bytes must not be empty" }
        require(storedPrekeyBundle == null || storedPrekeyBundle.isNotEmpty()) {
            "prekey bundle bytes must not be empty"
        }
    }

    override fun equals(other: Any?): Boolean =
        other is DirectoryDhtValue &&
            identity == other.identity &&
            binding == other.binding &&
            (storedPeerRecord?.contentEquals(other.storedPeerRecord) ?: (other.storedPeerRecord == null)) &&
            (storedPrekeyBundle?.contentEquals(other.storedPrekeyBundle) ?: (other.storedPrekeyBundle == null))

    override fun hashCode(): Int {
        var result = identity.hashCode()
        result = 31 * result + binding.hashCode()
        result = 31 * result + (storedPeerRecord?.contentHashCode() ?: 0)
        result = 31 * result + (storedPrekeyBundle?.contentHashCode() ?: 0)
        return result
    }

    override fun toString(): String =
        "DirectoryDhtValue(identity=${identity.fingerprint()}, peerRecord=${storedPeerRecord != null}, " +
            "prekeyBundle=${storedPrekeyBundle != null})"
}
