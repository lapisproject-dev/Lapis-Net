package net.lapisphilosophorum.lapisnet.onionwire.lookup

import io.ipfs.cid.Cid
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.time.Duration

/**
 * What a relay of the LOOKUP role does for one validated lookup (wave V0.10.0-J2). Called on a thread of the lookup
 * pool, never on an event loop. Everything returned is untrusted: [OnionLookupService] verifies it before answering.
 */
interface OnionLookupSink {
    fun fetchBlock(
        cid: Cid,
        maxBytes: Int,
        timeout: Duration,
    ): LookupOutcome

    fun resolveIpnsRecord(
        routingKey: ByteArray,
        timeout: Duration,
    ): LookupOutcome
}

/** Result of one [OnionLookupSink] call. */
sealed interface LookupOutcome {
    class Found(
        bytes: ByteArray,
    ) : LookupOutcome {
        private val stored = bytes.copyOf()
        val bytes: ByteArray get() = stored.copyOf()
        val size: Int get() = stored.size

        override fun toString(): String = "Found(length=${stored.size})"
    }

    data object NotFound : LookupOutcome

    data object Timeout : LookupOutcome

    /** The content exceeds the limit; [receivedBytes] is what the relay downloaded anyway (charged to its budget). */
    data class TooLarge(
        val receivedBytes: Long,
    ) : LookupOutcome
}

/**
 * The production sink: the relay's own [NabuStorage] in network mode. Blocks go through [NabuStorage.fetchTransient]
 * (nothing is kept, served or announced), IPNS records through [NabuStorage.resolveIpnsRecordRaw]. The relay's DHT and
 * Bitswap queries show the RELAY as the asker.
 */
class NabuLookupSink(
    private val storage: NabuStorage,
) : OnionLookupSink {
    override fun fetchBlock(
        cid: Cid,
        maxBytes: Int,
        timeout: Duration,
    ): LookupOutcome {
        val started = System.nanoTime()
        val bytes = storage.fetchTransient(cid, timeout)
        return when {
            bytes == null ->
                if (System.nanoTime() - started >= timeout.toNanos()) LookupOutcome.Timeout else LookupOutcome.NotFound
            // Bitswap delivers the whole block before its size is known here; the service charges it
            bytes.size > maxBytes -> LookupOutcome.TooLarge(bytes.size.toLong())
            else -> LookupOutcome.Found(bytes)
        }
    }

    override fun resolveIpnsRecord(
        routingKey: ByteArray,
        timeout: Duration,
    ): LookupOutcome {
        val started = System.nanoTime()
        val raw = storage.resolveIpnsRecordRaw(routingKey, timeout)
        return when {
            raw == null ->
                if (System.nanoTime() - started >= timeout.toNanos()) LookupOutcome.Timeout else LookupOutcome.NotFound
            else -> LookupOutcome.Found(raw)
        }
    }
}
