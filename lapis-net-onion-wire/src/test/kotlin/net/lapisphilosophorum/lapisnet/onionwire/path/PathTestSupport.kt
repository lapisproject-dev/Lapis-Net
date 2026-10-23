@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onionwire.path

import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptor
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onion.OnionKeyBinding
import net.lapisphilosophorum.lapisnet.onionwire.WireTestClock
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap

/** A relay descriptor without any network: a real signed descriptor over a fresh identity. */
fun syntheticDescriptor(
    expiresInSeconds: Long = 3600,
    nowEpochSecond: Long = System.currentTimeMillis() / 1000,
): OnionRelayDescriptor {
    val identity = DualKeyIdentity.generate()
    val binding =
        OnionKeyBinding.create(
            identity.secp256k1KeyPair,
            X25519KeyPair.generate().publicKey,
            nowEpochSecond + 7 * 86_400,
        )
    return OnionRelayDescriptor.create(identity, binding, 0, nowEpochSecond + expiresInSeconds, nowEpochSecond)
}

/** Deterministic randomness: the same seed yields the same stream. */
fun seededRandom(seed: Long): SecureRandom = SecureRandom.getInstance("SHA1PRNG").apply { setSeed(seed) }

/** Network buckets by identity; a relay not listed is in the unknown bucket. */
class MapLocator : RelayNetworkLocator {
    private val map = ConcurrentHashMap<Secp256k1PublicKey, Set<NetworkBucket>>()

    fun put(
        d: OnionRelayDescriptor,
        vararg buckets: NetworkBucket,
    ): OnionRelayDescriptor {
        map[d.identity] = buckets.toSet()
        return d
    }

    override fun bucketsOf(
        identity: Secp256k1PublicKey,
        nowEpochSecond: Long,
    ): Set<NetworkBucket> = map[identity] ?: setOf(NetworkBucket.Unknown)
}

fun v4(
    a: Int,
    b: Int,
): NetworkBucket = NetworkBucket.V4((a shl 8) or b)

/** A relay in its own /16 (`10+n` is never used as a real network in these tests; the locator is synthetic). */
fun MapLocator.relayIn(
    a: Int,
    b: Int,
): OnionRelayDescriptor = put(syntheticDescriptor(), v4(a, b))

class SelectorFixture(
    val relays: MutableList<OnionRelayDescriptor> = ArrayList(),
    val locator: MapLocator = MapLocator(),
    val reputation: MutableMap<io.libp2p.core.PeerId, Double> = HashMap(),
    val families: MutableMap<Secp256k1PublicKey, RelayFamilyId> = HashMap(),
    seed: Long = 1,
    val clock: WireTestClock = WireTestClock(),
    store: GuardStateStore = InMemoryGuardStateStore(),
    options: PathSelectionOptions = PathSelectionOptions(),
    val own: DualKeyIdentity = DualKeyIdentity.generate(),
) {
    val random = seededRandom(seed)
    val guards = GuardManager(store, random, clock)
    val selector =
        OnionPathSelector(
            { relays.toList() },
            own.secp256k1KeyPair.publicKey,
            locator,
            { reputation[it] },
            { families[it.identity] },
            guards,
            random,
            clock,
            options,
        )

    fun add(
        a: Int,
        b: Int,
    ): OnionRelayDescriptor = locator.relayIn(a, b).also { relays += it }
}

fun PathSelectionResult.hops(): List<OnionRelayDescriptor> = (this as PathSelectionResult.Selected).hops
