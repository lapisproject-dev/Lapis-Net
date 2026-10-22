package net.lapisphilosophorum.lapisnet.onion

import java.nio.ByteBuffer
import java.security.MessageDigest

/** Result of registering an introduction point. */
internal sealed interface IntroRegistration {
    /** Registered; [replaced] is the circuit whose registration was superseded (to be torn down), if any. */
    class Registered(
        val replaced: RelayCircuitRef?,
    ) : IntroRegistration

    /** `establishSeq` was not larger than the existing registration of the same auth key. */
    data object Stale : IntroRegistration

    data object LimitReached : IntroRegistration
}

/** Opaque handle kept by the tables so they stay independent of the relay's private circuit class. */
internal interface RelayCircuitRef {
    val linkKey: Long
}

/**
 * Introduction points registered at THIS relay: auth key to circuit, bounded in total and per previous
 * link, with a replay cache over the digests of forwarded INTRODUCE bodies (bounded LRU). Every method
 * is synchronised on the table itself and never calls into a circuit (no lock-order hazard).
 */
internal class IntroPointTable(
    private val maxTotal: Int,
    private val maxPerLink: Int,
    replayCacheEntries: Int,
) {
    private class Entry(
        val circuit: RelayCircuitRef,
        val seq: Long,
    )

    private val byKey = HashMap<ByteBuffer, Entry>()
    private val perLink = HashMap<Long, Int>()
    private val replay =
        object : LinkedHashMap<ByteBuffer, Boolean>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<ByteBuffer, Boolean>): Boolean =
                size > replayCacheEntries
        }

    @Synchronized
    fun register(
        authKey: ByteArray,
        circuit: RelayCircuitRef,
        seq: Long,
    ): IntroRegistration {
        val key = ByteBuffer.wrap(authKey.copyOf())
        val existing = byKey[key]
        if (existing != null && seq <= existing.seq) return IntroRegistration.Stale
        if (existing == null) {
            if (byKey.size >= maxTotal || (perLink[circuit.linkKey] ?: 0) >= maxPerLink) {
                return IntroRegistration.LimitReached
            }
        } else {
            dec(existing.circuit.linkKey)
            if ((perLink[circuit.linkKey] ?: 0) >= maxPerLink) {
                perLink.merge(existing.circuit.linkKey, 1, Int::plus)
                return IntroRegistration.LimitReached
            }
        }
        byKey[key] = Entry(circuit, seq)
        perLink.merge(circuit.linkKey, 1, Int::plus)
        return IntroRegistration.Registered(existing?.circuit)
    }

    @Synchronized
    fun lookup(authKey: ByteArray): RelayCircuitRef? = byKey[ByteBuffer.wrap(authKey)]?.circuit

    /** Removes the registration of [circuit] (if it is still the registered one). */
    @Synchronized
    fun remove(circuit: RelayCircuitRef) {
        val it = byKey.entries.iterator()
        while (it.hasNext()) {
            val e = it.next()
            if (e.value.circuit === circuit) {
                it.remove()
                dec(circuit.linkKey)
                return
            }
        }
    }

    /** `true` if this body was already forwarded (and records it otherwise). */
    @Synchronized
    fun seenBefore(body: ByteArray): Boolean {
        val digest = ByteBuffer.wrap(MessageDigest.getInstance("SHA-256").digest(body))
        if (replay.containsKey(digest)) return true
        replay[digest] = true
        return false
    }

    @get:Synchronized
    val size: Int get() = byKey.size

    private fun dec(link: Long) {
        val n = (perLink[link] ?: 0) - 1
        if (n <= 0) perLink.remove(link) else perLink[link] = n
    }
}

/** Rendezvous cookies waiting for their second circuit: bounded in total and per previous link, single use. */
internal class RendezvousTable(
    private val maxTotal: Int,
    private val maxPerLink: Int,
) {
    private val byCookie = HashMap<ByteBuffer, RelayCircuitRef>()
    private val perLink = HashMap<Long, Int>()

    enum class PutResult { OK, DUPLICATE, LIMIT }

    @Synchronized
    fun put(
        cookie: ByteArray,
        circuit: RelayCircuitRef,
    ): PutResult {
        val key = ByteBuffer.wrap(cookie.copyOf())
        if (byCookie.containsKey(key)) return PutResult.DUPLICATE
        if (byCookie.size >= maxTotal || (perLink[circuit.linkKey] ?: 0) >= maxPerLink) return PutResult.LIMIT
        byCookie[key] = circuit
        perLink.merge(circuit.linkKey, 1, Int::plus)
        return PutResult.OK
    }

    /** Single use: the entry is removed. */
    @Synchronized
    fun take(cookie: ByteArray): RelayCircuitRef? {
        val c = byCookie.remove(ByteBuffer.wrap(cookie)) ?: return null
        dec(c.linkKey)
        return c
    }

    @Synchronized
    fun remove(circuit: RelayCircuitRef) {
        val it = byCookie.entries.iterator()
        while (it.hasNext()) {
            val e = it.next()
            if (e.value === circuit) {
                it.remove()
                dec(circuit.linkKey)
                return
            }
        }
    }

    @get:Synchronized
    val size: Int get() = byCookie.size

    private fun dec(link: Long) {
        val n = (perLink[link] ?: 0) - 1
        if (n <= 0) perLink.remove(link) else perLink[link] = n
    }
}
