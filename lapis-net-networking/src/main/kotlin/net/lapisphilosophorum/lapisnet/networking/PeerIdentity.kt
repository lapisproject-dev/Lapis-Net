package net.lapisphilosophorum.lapisnet.networking

import io.libp2p.core.PeerId
import io.libp2p.core.crypto.PrivKey
import io.libp2p.crypto.keys.unmarshalEd25519PrivateKey
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity

/**
 * Derives this identity's libp2p signing key ([PrivKey]) from its Ed25519 keypair. Public since
 * V0.9.13: `lapis-net-directory` signs its IPNS-record publications (the DHT fallback for the peer
 * directory and prekey bundles) with the node's own transport key, and a record can only be accepted
 * by other nodes if it is signed with exactly the key their Noise handshake authenticated. Callers
 * that just want to identify, compare, or log a peer should use [deriveLibp2pPeerId] instead. Note this
 * does not widen what `lapis-net-identity` already exposes - its
 * [net.lapisphilosophorum.lapisnet.identity.Ed25519PrivateKey.seed] getter is public and already hands
 * the same raw signing-key bytes to any module depending on `lapis-net-identity`; the returned [PrivKey] is
 * a wrapper around those bytes and adds no capability beyond signing with that key. Never log it or put it
 * in an exception message.
 *
 * The raw 32-byte seed [net.lapisphilosophorum.lapisnet.identity.Ed25519PrivateKey.seed] stores
 * is exactly the byte layout jvm-libp2p's `unmarshalEd25519PrivateKey` expects - no adapter or
 * re-encoding needed.
 */
fun DualKeyIdentity.deriveLibp2pPrivKey(): PrivKey = unmarshalEd25519PrivateKey(ed25519KeyPair.privateKey.seed)

/**
 * Deterministically derives this identity's libp2p [PeerId] - the same [DualKeyIdentity] always
 * produces the same [PeerId], since it is a pure function of the Ed25519 key material. The
 * public key is derived from the private key (not read from the separately-stored public key
 * bytes), so a corrupted keystore that somehow desynced its stored public key from its private
 * key can never produce a [PeerId] the node can't actually sign with.
 */
fun DualKeyIdentity.deriveLibp2pPeerId(): PeerId = PeerId.fromPubKey(deriveLibp2pPrivKey().publicKey())
