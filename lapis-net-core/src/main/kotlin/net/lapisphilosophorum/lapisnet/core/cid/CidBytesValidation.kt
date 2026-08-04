package net.lapisphilosophorum.lapisnet.core.cid

/**
 * Pre-flight validation of a candidate CID byte array, to be run BEFORE it is ever handed to
 * `io.ipfs.cid.Cid.cast(...)`.
 *
 * **Why this exists.** `Cid.cast` parses a (non-CIDv0-shortcut) buffer as `version-varint |
 * codec-varint | multihash-type-varint | multihash-length-varint | hash-bytes` and delegates the
 * multihash portion to `io.ipfs.multihash.Multihash.deserialize(InputStream)` (java-multihash
 * `v1.3.4`, resolved transitively via `com.github.ipld:java-cid:v1.3.8`, an `api` dependency of
 * every module that decodes CIDs off the wire - see e.g. `lapis-net-trust/build.gradle.kts`).
 * That method does `byte[] hash = new byte[len]` using the attacker-controlled declared length -
 * read straight off the wire - BEFORE `Multihash`'s own constructor ever runs its bound check
 * (`if (hash.length > 127 && type != Type.id) throw IllegalStateException(...)`, in
 * `io.ipfs.multihash.Multihash`'s constructor). A candidate CID byte array that declares an
 * oversized multihash length - e.g. `0x7FFFFFFF` - therefore triggers a multi-gigabyte array
 * allocation attempt and an `OutOfMemoryError`, regardless of how small the CID *field* itself was
 * capped to be at the codec layer (every affected codec caps the wire field around 64-128 bytes,
 * e.g. `MessageEnvelopeCodec.MAX_CID_BYTES`/`MessageBodyCodec.MAX_CID_BYTES`/
 * `LtrRecordCodec.MAX_CID_BYTES`/`KarmaVoteCodec.MAX_CID_BYTES`, all 128): the oversized length is
 * a value encoded *inside* those bytes, not the byte count of the field itself, and field-length
 * caps do nothing to bound it.
 *
 * [isSafeToCast] parses only the leading varints - mirroring `Multihash.readVarint`'s exact LEB128
 * semantics byte-for-byte, so it never disagrees with the real parser about where a varint ends or
 * overflows - to reject any declared multihash length that either overruns [candidate]'s own
 * remaining bytes or exceeds the constructor's 127-byte hard cap. It allocates nothing beyond a few
 * local variables. Every call site that decodes an untrusted CID must run this check first.
 *
 * **Lives here, in `lapis-net-core`, rather than in any one of its consumers.** Originally added to
 * `lapis-net-mail` (V0.9.1) to fix this construct in `MessageEnvelopeCodec`/`MessageBodyCodec`, a
 * follow-up security pass found the identical unguarded `Cid.cast(cidBytes)` construct already
 * shipped in three older, sibling codecs - `lapis-net-trust`'s `VeritasGrantCodec` (V0.1.5),
 * `lapis-net-virtus`'s `LtrRecordCodec` (V0.2.1), and `lapis-net-karma`'s `KarmaVoteCodec` (V0.3).
 * All four modules already depend on `lapis-net-core`, making it the natural shared home - see
 * `docs/architecture.adoc`'s "Known gap closed: CID multihash length overflow" note for the full
 * history.
 */
object CidBytesValidation {
    /** Mirrors `io.ipfs.multihash.Multihash`'s own hard cap: every hash type other than the
     * identity hash (`Multihash.Type.id`) is rejected by the constructor once `hash.length > 127`.
     * Every CID this project decodes off the wire is a content hash (sha2-256 in practice), never
     * an identity multihash, so this single cap - not the separate, much larger
     * `Multihash.MAX_IDENTITY_HASH_LENGTH` - is the correct bound to enforce here. */
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
        return isSafeMultihashSuffix(candidate, afterCodec)
    }

    /**
     * `true` iff [candidate] can be safely passed to `io.ipfs.multihash.Multihash.deserialize(...)`
     * (either overload - both funnel through the same `type-varint | length-varint | hash-bytes`
     * read) without risking an oversized allocation. Unlike [isSafeToCast], this does NOT expect a
     * leading version/codec varint pair - [candidate] must already be positioned at the multihash's
     * own type varint, exactly what `Multihash.deserialize` itself expects as input.
     *
     * **Why this exists as its own entry point.** `io.ipfs.cid.Cid.decode(String)` has a second,
     * *separate* unguarded path from [isSafeToCast]'s: a legacy CIDv0 shortcut
     * (`v.length() == 46 && v.startsWith("Qm")`) that calls `Multihash.fromBase58(v)` directly -
     * `Base58.decode(v)` then `Multihash.deserialize(...)` - and never goes through `Cid.cast` at
     * all. The decoded byte count for a valid 46-character base58 string is tightly coupled to its
     * numeric magnitude (roughly 33-34 bytes, matching the fixed-size legitimate CIDv0 case), so this
     * branch is more constrained than the general `Multibase.decode` path [isSafeToCast] guards -
     * but it is built from the exact same `type-varint | length-varint | hash-bytes` read as every
     * other multihash decode in this codebase, with the identical allocate-before-bound-check defect
     * (`Multihash.deserialize`'s `byte[] hash = new byte[len]` runs before its own constructor's
     * `hash.length > 127` check), so it gets the identical guard rather than a carve-out based on an
     * assumption about how large a declared length an attacker can fit inside that magnitude window.
     * See `docs/architecture.adoc`'s "Known gap closed: CID multihash length overflow" note for the
     * full history, including this specific gap.
     */
    fun isSafeToDeserializeMultihash(candidate: ByteArray): Boolean = isSafeMultihashSuffix(candidate, 0)

    /**
     * Shared implementation for [isSafeToCast] (after its version/codec prefix) and
     * [isSafeToDeserializeMultihash] (from the very start of [candidate]): validates the
     * `type-varint | length-varint | hash-bytes` suffix starting at [startPos], mirroring
     * `Multihash.deserialize`'s own read order exactly.
     */
    private fun isSafeMultihashSuffix(
        candidate: ByteArray,
        startPos: Int,
    ): Boolean {
        val afterHashType = readVarintEnd(candidate, startPos) ?: return false
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
