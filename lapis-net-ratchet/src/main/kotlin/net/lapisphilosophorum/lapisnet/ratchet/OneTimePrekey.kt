package net.lapisphilosophorum.lapisnet.ratchet

import net.lapisphilosophorum.lapisnet.identity.X25519PublicKey

/** One published one-time prekey: a stable, per-identity-monotonic [id] and its public half.
 * Consumed exactly once by an X3DH responder - see [PrekeyStore.consumeOneTimePrekey]'s doc
 * comment for the durable, one-shot consumption contract this id space depends on. */
class OneTimePrekey(
    val id: Int,
    val publicKey: X25519PublicKey,
) {
    init {
        require(id >= 0) { "one-time prekey id must be >= 0, was $id" }
    }

    override fun equals(other: Any?): Boolean = other is OneTimePrekey && id == other.id && publicKey == other.publicKey

    override fun hashCode(): Int = 31 * id + publicKey.hashCode()

    override fun toString(): String = "OneTimePrekey(id=$id, publicKey=$publicKey)"
}
