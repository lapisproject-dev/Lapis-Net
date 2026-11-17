package net.lapisphilosophorum.lapisnet.networking.config

import io.libp2p.core.crypto.PrivKey
import io.libp2p.crypto.keys.unmarshalEd25519PrivateKey
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.deriveLibp2pPrivKey
import java.security.SecureRandom

/**
 * Which key the libp2p host of a node signs its Noise handshakes (and therefore its transport PeerId) with
 * (wave V0.10.0-J1a).
 *
 * - [IdentityDerived] (the default, normal mode): the key derived from the identity, see [deriveLibp2pPrivKey]. The
 *   PeerId is publicly bound to the identity through every `PeerRecord`/`IdentityBinding` ever published.
 * - [EphemeralPerRun] (anonymity mode): a fresh Ed25519 key per process run. It is never written to disk and never
 *   logged; the seed bytes this class generated are overwritten as soon as the libp2p key object exists. Every peer
 *   this node connects to (its guards above all) still sees the PeerId of this run together with the IP address, but
 *   that PeerId carries no link to the identity. Two runs from the same address remain linkable through the address.
 */
sealed interface TransportKeyPolicy {
    data object IdentityDerived : TransportKeyPolicy

    data object EphemeralPerRun : TransportKeyPolicy

    /** The libp2p key for a host created under this policy. */
    fun resolve(
        identity: DualKeyIdentity,
        random: SecureRandom = SecureRandom(),
    ): PrivKey =
        when (this) {
            IdentityDerived -> identity.deriveLibp2pPrivKey()
            EphemeralPerRun -> {
                val seed = ByteArray(ED25519_SEED_BYTES)
                try {
                    random.nextBytes(seed)
                    unmarshalEd25519PrivateKey(seed)
                } finally {
                    seed.fill(0)
                }
            }
        }
}

private const val ED25519_SEED_BYTES = 32
