package net.lapisphilosophorum.lapisnet.directory

import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.onion.OnionKeyBinding
import java.time.Instant

/** A test relay identity with builders for onion key bindings and descriptors. */
internal class OnionRelayPublisher(
    val publisher: DirectoryPublisher = DirectoryPublisher(),
) {
    val identity: DualKeyIdentity get() = publisher.identity

    fun onionBinding(
        notValidAfter: Long = Instant.now().epochSecond + 7 * 86_400,
        owner: DualKeyIdentity = identity,
    ): OnionKeyBinding =
        OnionKeyBinding.create(owner.secp256k1KeyPair, X25519KeyPair.generate().publicKey, notValidAfter)

    fun descriptor(
        sequence: Long = 0,
        expiresInSeconds: Long = 3600,
        binding: OnionKeyBinding = onionBinding(),
        now: Long = Instant.now().epochSecond,
    ): OnionRelayDescriptor = OnionRelayDescriptor.create(identity, binding, sequence, now + expiresInSeconds, now)
}
