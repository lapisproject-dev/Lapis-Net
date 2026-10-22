package net.lapisphilosophorum.lapisnet.onion

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.identity.X25519PrivateKey
import org.bouncycastle.util.Arrays
import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write

/** A ring entry: a signed binding plus its private scalar (held only inside the ring). */
internal class OnionKeyEntry(
    val binding: OnionKeyBinding,
    val privateKey: X25519PrivateKey,
    val fingerprint: ByteArray = binding.onionKeyFingerprint(),
)

/**
 * The (at most two) onion keys a relay currently answers CREATEs with: the `current` key and the
 * `previous` one, kept alive during the rotation overlap so circuits being built against a
 * not-yet-republished descriptor still succeed. Pure key management, no I/O.
 *
 * Ownership: [install] takes ownership of the private key it is given; the ring zeroises a key when
 * it is retired ([retireExpired], a rotation pushing it out of the overlap window) and all keys on
 * [close]. A [ReentrantReadWriteLock] guards the entries: a handshake runs under the read lock
 * ([withKeyFor]) and every destroying operation takes the write lock, so a scalar can never be
 * zeroised while an X25519 operation is using it. Selection by fingerprint compares against
 * EVERY entry in constant time, without early exit.
 */
class OnionKeyRing(
    val relayIdentity: Secp256k1PublicKey,
) : AutoCloseable {
    private val lock = ReentrantReadWriteLock()
    private var current: OnionKeyEntry? = null
    private var previous: OnionKeyEntry? = null
    private var closed = false
    private val idDigest = OnionKeyBinding.relayIdDigestOf(relayIdentity)

    /** Copy of the relay-id digest (the relay's address in CREATE/EXTEND). */
    val relayIdDigest: ByteArray get() = idDigest.copyOf()

    fun current(): OnionKeyBinding? = lock.read { current?.binding }

    /** Bindings (current first, then previous) that are still unexpired at [nowEpochSecond]. */
    fun accepted(nowEpochSecond: Long): List<OnionKeyBinding> =
        lock.read {
            listOfNotNull(current, previous)
                .map { it.binding }
                .filter { nowEpochSecond <= it.notValidAfterEpochSecond }
        }

    /**
     * Makes [binding] the current key; the former current becomes `previous` and the former previous
     * is zeroised. Rejects a binding of a different identity, a bad/expired binding and a private
     * key that does not match the binding. On rejection nothing changes and [privateKey] is NOT
     * taken over (the caller still owns it).
     */
    fun install(
        binding: OnionKeyBinding,
        privateKey: X25519PrivateKey,
        nowEpochSecond: Long,
    ) {
        require(binding.relayIdentity == relayIdentity) { "binding belongs to a different relay identity" }
        require(OnionKeyBinding.verify(binding, nowEpochSecond)) { "invalid or expired onion key binding" }
        installChecked(binding, privateKey)
    }

    internal fun installChecked(
        binding: OnionKeyBinding,
        privateKey: X25519PrivateKey,
    ) {
        require(binding.relayIdentity == relayIdentity) { "binding belongs to a different relay identity" }
        require(X25519KeyPair.publicKeyFor(privateKey) == binding.onionKey) {
            "onion private key does not match the binding"
        }
        lock.write {
            check(!closed) { "ring is closed" }
            previous?.privateKey?.destroy()
            previous = current
            current = OnionKeyEntry(binding, privateKey)
        }
    }

    /** Zeroises and drops every key that is expired at [nowEpochSecond]; returns how many. */
    fun retireExpired(nowEpochSecond: Long): Int =
        lock.write {
            var n = 0
            current?.let {
                if (nowEpochSecond > it.binding.notValidAfterEpochSecond) {
                    it.privateKey.destroy()
                    current = null
                    n++
                }
            }
            previous?.let {
                if (nowEpochSecond > it.binding.notValidAfterEpochSecond) {
                    it.privateKey.destroy()
                    previous = null
                    n++
                }
            }
            // A surviving previous with no current would be an odd state; promote it.
            if (current == null && previous != null) {
                current = previous
                previous = null
            }
            n
        }

    /**
     * Runs [block] with the unexpired entry whose fingerprint equals [fingerprint], under the read
     * lock; `null` if none matches. The fingerprint is compared against all entries without early exit.
     */
    internal fun <T> withKeyFor(
        fingerprint: ByteArray,
        nowEpochSecond: Long,
        block: (OnionKeyBinding, X25519PrivateKey) -> T,
    ): T? =
        lock.read {
            if (closed) return@read null
            var match: OnionKeyEntry? = null
            for (e in listOfNotNull(current, previous)) {
                val same = Arrays.constantTimeAreEqual(e.fingerprint, fingerprint)
                if (same && nowEpochSecond <= e.binding.notValidAfterEpochSecond) match = e
            }
            match?.let { block(it.binding, it.privateKey) }
        }

    /**
     * Hands [block] copies of the private scalars (order: current, previous) for encrypted persistence, under the read
     * lock; the copies are zeroised right after [block] returns. Opt-in because it exposes private key material: only the
     * key store of the wire module may use it.
     */
    @ExperimentalOnionApi
    fun <T> snapshotForPersistence(block: (List<Pair<OnionKeyBinding, ByteArray>>) -> T): T =
        lock.read {
            val copies = listOfNotNull(current, previous).map { it.binding to it.privateKey.bytes }
            try {
                block(copies)
            } finally {
                copies.forEach { it.second.fill(0) }
            }
        }

    override fun close() {
        lock.write {
            closed = true
            current?.privateKey?.destroy()
            previous?.privateKey?.destroy()
            current = null
            previous = null
        }
    }

    companion object {
        /** One-entry ring for the single-key relay constructor; skips the expiry check (wave A behaviour). */
        fun single(
            binding: OnionKeyBinding,
            privateKey: X25519PrivateKey,
        ): OnionKeyRing {
            val ring = OnionKeyRing(binding.relayIdentity)
            ring.installChecked(binding, privateKey)
            return ring
        }
    }
}
