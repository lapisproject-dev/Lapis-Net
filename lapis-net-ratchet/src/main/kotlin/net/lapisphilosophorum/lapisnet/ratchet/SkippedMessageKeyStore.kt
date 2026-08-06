package net.lapisphilosophorum.lapisnet.ratchet

/** Wraps a ratchet public key's bytes + a message number with value equality so the pair can be a
 * map key - mirrors `PeerRecordContentId`/`PrekeyBundleContentId`'s identical shape, duplicated
 * locally for the same module-boundary reason those classes document (a `ByteArray` field breaks
 * `data class`'s synthesized `equals`/`hashCode`, so both are hand-written here). */
internal data class SkippedMessageKeyId(
    private val ratchetPublicKey: ByteArray,
    private val messageNumber: Int,
) {
    override fun equals(other: Any?): Boolean =
        other is SkippedMessageKeyId &&
            messageNumber == other.messageNumber &&
            ratchetPublicKey.contentEquals(other.ratchetPublicKey)

    override fun hashCode(): Int = 31 * ratchetPublicKey.contentHashCode() + messageNumber

    /** Fresh copy - for [DoubleRatchetSessionCodec], which needs the raw bytes to persist. */
    internal fun ratchetPublicKeyBytes(): ByteArray = ratchetPublicKey.copyOf()

    internal fun messageNumberValue(): Int = messageNumber
}

/**
 * Bounded, evicting, per-session storage of message keys derived for messages that arrived out of
 * order relative to the current chain position (skipped ahead of), so a late-arriving message can
 * still be decrypted - but only up to [maxStored], beyond which the OLDEST stored key is evicted
 * (and zeroed) to make room, and that message becomes permanently undecryptable - a correct,
 * accepted consequence of a bounded skip window, not a bug.
 *
 * **INSERTION-order [LinkedHashMap], deliberately NOT the access-order shape every gossip index in
 * this codebase uses** (`PeerRecordIndex.recordsByContentId`, `PrekeyBundleIndex`'s equivalent
 * field are all `LinkedHashMap(16, 0.75f, true)`). Those indexes treat recency-of-access as a
 * liveness signal, and `PeerRecordIndex`'s own doc comment defends that at length. Here the
 * opposite is true: an attacker can trigger arbitrary lookups against this store by replaying
 * arbitrary headers, so access-order would let them pin a chosen key alive and evict everyone
 * else's. A skipped key's value decays purely with AGE, so age is the correct eviction order - and
 * it is exactly what "the oldest skipped keys must be evicted" means.
 *
 * **Not independently synchronized, deliberately** - this store is session-private (only
 * [DoubleRatchetSession] ever holds one) and every access already runs under that session's own
 * `@Synchronized` monitor. Adding a second lock would buy nothing and suggest a sharing model that
 * does not exist.
 */
internal class SkippedMessageKeyStore(
    private val maxStored: Int = DoubleRatchetSession.MAX_SKIPPED_KEYS_STORED,
) {
    init {
        require(maxStored > 0) { "maxStored must be positive, was $maxStored" }
    }

    private val keys =
        object : LinkedHashMap<SkippedMessageKeyId, ByteArray>(16, 0.75f, false) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<SkippedMessageKeyId, ByteArray>): Boolean {
                if (size <= maxStored) return false
                eldest.value.fill(0) // zero BEFORE dropping the reference - forward secrecy
                return true
            }
        }

    /** Stores a defensive COPY of [keyMaterial]; the caller keeps ownership of (and must zero) its
     * own array. Evicts+zeroes the oldest entry if this pushes the store past [maxStored]. A repeat
     * `put` for the same [id] zeroes the previously-stored array before replacing it. */
    internal fun put(
        id: SkippedMessageKeyId,
        keyMaterial: ByteArray,
    ) {
        keys[id]?.fill(0)
        keys[id] = keyMaterial.copyOf()
    }

    /** A fresh COPY of the stored material, or `null`. **Does not remove and does not mutate the
     * store** - load-bearing for [DoubleRatchetSession.decrypt]'s commit-on-success discipline: a
     * failed AEAD must leave the skipped key still available for a later, legitimate retry. The
     * caller must zero the returned array. */
    internal fun peek(id: SkippedMessageKeyId): ByteArray? = keys[id]?.copyOf()

    /** Removes [id], zeroing the stored array in place. `true` iff it was present. This is the
     * delete-on-use step that makes a decrypted message unreplayable. */
    internal fun remove(id: SkippedMessageKeyId): Boolean {
        val removed = keys.remove(id) ?: return false
        removed.fill(0)
        return true
    }

    internal fun size(): Int = keys.size

    /** Oldest-first entries as `(ratchetPublicKeyBytes, messageNumber, keyMaterial)` triples, each
     * a fresh copy - used by [DoubleRatchetSessionCodec] to persist every skipped key, and by
     * [DoubleRatchetSession.keyMaterialSnapshotForTest] to inspect all live skipped-key material. */
    internal fun entriesOldestFirst(): List<Triple<ByteArray, Int, ByteArray>> =
        keys.entries.map { (id, material) ->
            Triple(id.ratchetPublicKeyBytes(), id.messageNumberValue(), material.copyOf())
        }

    /** Test-only accessor returning the ACTUAL stored array (not a copy) for [id] - lets a test
     * observe eviction/replacement zeroing the real backing array in place, mirroring
     * `HybridEcies.sealWithEphemeralKeyHook`'s identical test-seam visibility reasoning. Never call
     * from production code. */
    internal fun peekBackingArrayForTest(id: SkippedMessageKeyId): ByteArray? = keys[id]

    /** Zeroes every stored array and clears the map. Idempotent. */
    internal fun destroyAll() {
        keys.values.forEach { it.fill(0) }
        keys.clear()
    }
}
