package net.lapisphilosophorum.lapisnet.mail

/**
 * Pre-flight validation of a candidate CID byte array, to be run BEFORE it is ever handed to
 * `io.ipfs.cid.Cid.cast(...)`.
 *
 * **Why this exists.** `Cid.cast` parses a (non-CIDv0-shortcut) buffer as `version-varint |
 * codec-varint | multihash-type-varint | multihash-length-varint | hash-bytes` and delegates the
 * multihash portion to `io.ipfs.multihash.Multihash.deserialize(InputStream)` (java-multihash
 * `v1.3.4`, resolved transitively via this module's `com.github.ipld:java-cid:v1.3.8` dependency -
 * see `lapis-net-mail/build.gradle.kts`). That method does `byte[] hash = new byte[len]` using the
 * attacker-controlled declared length - read straight off the wire - BEFORE `Multihash`'s own
 * constructor ever runs its bound check (`if (hash.length > 127 && type != Type.id) throw
 * IllegalStateException(...)`, in `io.ipfs.multihash.Multihash`'s constructor). A candidate CID
 * byte array that declares an oversized multihash length - e.g. `0x7FFFFFFF` - therefore triggers a
 * multi-gigabyte array allocation attempt and an `OutOfMemoryError`, regardless of how small the
 * CID *field* itself was capped to be at the codec layer (`MessageEnvelopeCodec.MAX_CID_BYTES` /
 * `MessageBodyCodec.MAX_CID_BYTES`, both 128 bytes): the oversized length is a value encoded
 * *inside* those bytes, not the byte count of the field itself, and field-length caps do nothing to
 * bound it.
 *
 * [isSafeToCast] parses only the leading varints - mirroring `Multihash.readVarint`'s exact LEB128
 * semantics byte-for-byte, so it never disagrees with the real parser about where a varint ends or
 * overflows - to reject any declared multihash length that either overruns [candidate]'s own
 * remaining bytes or exceeds the constructor's 127-byte hard cap. It allocates nothing beyond a few
 * local variables. Every call site that decodes an untrusted CID must run this check first.
 */
internal object CidBytesValidation {
    /** Mirrors `io.ipfs.multihash.Multihash`'s own hard cap: every hash type other than the
     * identity hash (`Multihash.Type.id`) is rejected by the constructor once `hash.length > 127`.
     * Lapis Net content CIDs are always content hashes (sha2-256 in practice, see
     * [MessageBodyCodec.cidFor]), never identity multihashes, so this single cap - not the separate,
     * much larger `Multihash.MAX_IDENTITY_HASH_LENGTH` - is the correct bound to enforce here. */
    const val MULTIHASH_MAX_HASH_LENGTH = 127

    /**
     * `true` iff [candidate] can be safely passed to `io.ipfs.cid.Cid.cast(...)` without risking an
     * oversized allocation inside `Multihash.deserialize`. This does NOT fully validate that
     * [candidate] is a well-formed CID - codec legality, version legality, and exact hash-length-
     * per-type matching are still `Cid.cast`'s job, and it may still reject [candidate] after this
     * returns `true`. This function only guarantees that the allocation `Cid.cast` performs on its
     * way to that validation is bounded.
     */
    fun isSafeToCast(candidate: ByteArray): Boolean {
        // Mirrors io.ipfs.cid.Cid.cast's own CIDv0 shortcut exactly: a fixed 34-byte layout (the
        // sha2-256 multihash type/length bytes are hardcoded literals, not read off the wire), so
        // there is no attacker-controlled length varint to distrust here at all.
        if (candidate.size == 34 && candidate[0] == 18.toByte() && candidate[1] == 32.toByte()) return true

        val afterVersion = readVarintEnd(candidate, 0) ?: return false
        val afterCodec = readVarintEnd(candidate, afterVersion) ?: return false
        val afterHashType = readVarintEnd(candidate, afterCodec) ?: return false
        val (declaredHashLength, afterHashLength) = readVarint(candidate, afterHashType) ?: return false

        if (declaredHashLength < 0 || declaredHashLength > MULTIHASH_MAX_HASH_LENGTH) return false
        val remaining = candidate.size - afterHashLength
        return declaredHashLength <= remaining
    }

    /**
     * Reads one LEB128 unsigned varint starting at [startPos], mirroring
     * `io.ipfs.multihash.Multihash.readVarint(InputStream)`'s exact byte-for-byte semantics (7
     * payload bits per byte, MSB continuation bit, at most 10 bytes, the 10th byte only allowed a
     * value of 0 or 1) - so this rejects precisely the inputs that would make the real
     * `readVarint` throw, and never disagrees with it about where a varint ends. Returns `null` on
     * a truncated buffer or an overflowing/too-long varint rather than throwing - callers treat
     * `null` as "reject the candidate", matching how a real truncated/overflowing varint here would
     * surface as a decode failure anyway.
     */
    private fun readVarint(
        bytes: ByteArray,
        startPos: Int,
    ): Pair<Long, Int>? {
        var value = 0L
        var shift = 0
        var pos = startPos
        for (i in 0 until 10) {
            if (pos >= bytes.size) return null
            val b = bytes[pos].toInt() and 0xFF
            pos++
            if (b < 0x80) {
                if (i == 9 && b > 1) return null
                return (value or (b.toLong() shl shift)) to pos
            }
            value = value or ((b.toLong() and 0x7f) shl shift)
            shift += 7
        }
        return null
    }

    private fun readVarintEnd(
        bytes: ByteArray,
        startPos: Int,
    ): Int? = readVarint(bytes, startPos)?.second
}
