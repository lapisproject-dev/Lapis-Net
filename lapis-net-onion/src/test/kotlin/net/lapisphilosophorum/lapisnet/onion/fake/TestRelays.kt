package net.lapisphilosophorum.lapisnet.onion.fake

import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.onion.OnionKeyBinding
import net.lapisphilosophorum.lapisnet.onion.OnionRelay
import net.lapisphilosophorum.lapisnet.onion.OnionRelayLimits
import java.security.SecureRandom
import java.time.Clock

/** A relay with all of its key material exposed, for tests. */
class TestRelay(
    val identity: Secp256k1KeyPair,
    val onion: X25519KeyPair,
    val binding: OnionKeyBinding,
    val relay: OnionRelay,
)

fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }

fun unhex(s: String): ByteArray =
    ByteArray(s.length / 2) {
        (
            (Character.digit(s[it * 2], 16) shl 4) +
                Character.digit(s[it * 2 + 1], 16)
        ).toByte()
    }

fun newTestRelay(
    clock: Clock = FixedClock(),
    random: SecureRandom = SecureRandom(),
    limits: OnionRelayLimits = OnionRelayLimits(),
): TestRelay {
    val identity = Secp256k1KeyPair.generate()
    val onion = X25519KeyPair.generate()
    val binding = OnionKeyBinding.create(identity, onion.publicKey, clock.millis() / 1000 + 86_400)
    return TestRelay(identity, onion, binding, OnionRelay(binding, onion.privateKey, limits, clock, random))
}
