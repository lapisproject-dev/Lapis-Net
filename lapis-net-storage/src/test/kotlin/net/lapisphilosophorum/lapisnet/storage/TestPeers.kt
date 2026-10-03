package net.lapisphilosophorum.lapisnet.storage

import io.libp2p.core.PeerId
import io.libp2p.core.crypto.KeyType
import io.libp2p.core.crypto.generateKeyPair

/**
 * A well-formed peer ID (identity multihash of an Ed25519 public key, 38 bytes). `PeerId.random()`
 * is NOT usable where the code under test validates the multihash structure of an ID: it is 32
 * random bytes.
 */
internal fun realPeerId(): PeerId = PeerId.fromPubKey(generateKeyPair(KeyType.ED25519).second)
