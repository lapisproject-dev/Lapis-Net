package net.lapisphilosophorum.lapisnet.dm

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.identity.X25519PublicKey

/**
 * The anti-replay binding for a [DmFirstContactDeposit], keyed to a DM *session* rather than a
 * single message. [x3dhEphemeralPublicKey] is the [DmEnvelope.X3DH_INITIAL] header's ephemeral
 * X25519 key that bootstrapped this session - X3DH mints a FRESH ephemeral key per handshake (see
 * `lapis-net-ratchet`'s `X3dh.initiate`), so binding to it means one paid deposit buys exactly one
 * session: an attacker who transplants a genuine deposit into a DIFFERENT session (a different
 * ephemeral key) fails [DmFirstContactDepositVerifier.verify]'s memo check.
 *
 * See [DmFirstContactDeposit]'s own class doc comment for why this is a per-SESSION binding, unlike
 * `lapis-net-mail`'s per-MESSAGE `FirstContactDeposit` binding.
 */
class DmDepositBinding(
    val x3dhEphemeralPublicKey: X25519PublicKey,
    val initiatorIdentity: Secp256k1PublicKey,
    val recipientIdentity: Secp256k1PublicKey,
)
