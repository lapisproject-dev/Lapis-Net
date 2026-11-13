package net.lapisphilosophorum.lapisnet.dm

import java.nio.ByteBuffer

/**
 * Durable record of this node's own, still UNACKNOWLEDGED first-contact initiation towards one peer (no inbound
 * message of that peer has been decrypted since the `X3DH_INITIAL` was sent). Stored next to the session file as
 * `<peer-hex>.lndm.x3dhpending`, 0600, atomic temp+move - like the `.x3dhinit` replay registry, and like that file
 * NOT encrypted: it holds no secret (only public keys, ids, counters and times), but contact metadata, hence the
 * same file permissions as the session files. A missing file means "acknowledged" (or never initiated by this
 * node): every session that existed before this record type keeps its previous behaviour, no migration.
 *
 * Wire layout, big-endian: magic "LNXP" | version 1 | responderX25519IdentityKey(32) | ephemeralPublicKey(32) |
 * signedPrekeyId(4) | otkPresent(1) | otkId(4) | bundleSequence(8) | initiatedAtEpochSecond(8) |
 * sendsSinceInitiation(4) | rejectionRebootstraps(1) | unackedRebootstraps(1) | gaveUp(1) |
 * awaitBundleNewerThan(8) | excludedCount(1) | excludedIds(4 x n, n <= 16).
 *
 * There is deliberately no "next allowed at" field: the rejection backoff gates only the automatic re-send (an
 * in-memory scheduled task), never a user send, so the record does not promise a gate that does not exist.
 */
internal class DmPendingInitiation(
    /** The responder's X25519 identity key from the bundle used for this initiation (verifies rejection tags). */
    val responderX25519IdentityKey: ByteArray,
    val ephemeralPublicKey: ByteArray,
    val signedPrekeyId: Int,
    val oneTimePrekeyId: Int?,
    val bundleSequence: Long,
    val initiatedAtEpochSecond: Long,
    val sendsSinceInitiation: Int,
    val rejectionRebootstraps: Int,
    val unackedRebootstraps: Int,
    /** No further AUTOMATIC re-initiation after this; a user send still bootstraps (with [excludedIds]). */
    val gaveUp: Boolean,
    /** `-1` = none; otherwise the next initiation needs a bundle with a higher sequence number (stale SPK). */
    val awaitBundleNewerThan: Long,
    val excludedIds: Set<Int>,
) {
    init {
        require(responderX25519IdentityKey.size == 32 && ephemeralPublicKey.size == 32)
        require(excludedIds.size <= MAX_EXCLUDED_IDS)
        require(rejectionRebootstraps in 0..255 && unackedRebootstraps in 0..255)
    }

    fun copy(
        sendsSinceInitiation: Int = this.sendsSinceInitiation,
        rejectionRebootstraps: Int = this.rejectionRebootstraps,
        unackedRebootstraps: Int = this.unackedRebootstraps,
        gaveUp: Boolean = this.gaveUp,
        awaitBundleNewerThan: Long = this.awaitBundleNewerThan,
        excludedIds: Set<Int> = this.excludedIds,
    ) = DmPendingInitiation(
        responderX25519IdentityKey,
        ephemeralPublicKey,
        signedPrekeyId,
        oneTimePrekeyId,
        bundleSequence,
        initiatedAtEpochSecond,
        sendsSinceInitiation,
        rejectionRebootstraps,
        unackedRebootstraps,
        gaveUp,
        awaitBundleNewerThan,
        excludedIds,
    )

    fun encode(): ByteArray {
        val ids = excludedIds.sorted()
        val buffer = ByteBuffer.allocate(FIXED_SIZE + 4 * ids.size)
        buffer.put(MAGIC)
        buffer.put(VERSION)
        buffer.put(responderX25519IdentityKey)
        buffer.put(ephemeralPublicKey)
        buffer.putInt(signedPrekeyId)
        buffer.put(if (oneTimePrekeyId != null) 1 else 0)
        buffer.putInt(oneTimePrekeyId ?: 0)
        buffer.putLong(bundleSequence)
        buffer.putLong(initiatedAtEpochSecond)
        buffer.putInt(sendsSinceInitiation)
        buffer.put(rejectionRebootstraps.toByte())
        buffer.put(unackedRebootstraps.toByte())
        buffer.put(if (gaveUp) 1 else 0)
        buffer.putLong(awaitBundleNewerThan)
        buffer.put(ids.size.toByte())
        ids.forEach { buffer.putInt(it) }
        return buffer.array()
    }

    companion object {
        const val MAX_EXCLUDED_IDS = 16
        private val MAGIC = "LNXP".toByteArray(Charsets.US_ASCII)
        private const val VERSION: Byte = 1
        private const val FIXED_SIZE = 4 + 1 + 32 + 32 + 4 + 1 + 4 + 8 + 8 + 4 + 1 + 1 + 1 + 8 + 1

        /** `null` for any structural problem - a corrupt record is treated as absent (fails open to "acknowledged"). */
        fun decode(bytes: ByteArray): DmPendingInitiation? {
            if (bytes.size < FIXED_SIZE) return null
            return try {
                val b = ByteBuffer.wrap(bytes)
                val magic = ByteArray(4).also { b.get(it) }
                if (!magic.contentEquals(MAGIC) || b.get() != VERSION) return null
                val responder = ByteArray(32).also { b.get(it) }
                val eph = ByteArray(32).also { b.get(it) }
                val spk = b.getInt()
                val otkPresent = b.get().toInt()
                val otkRaw = b.getInt()
                val seq = b.getLong()
                val initiatedAt = b.getLong()
                val sends = b.getInt()
                val rejections = b.get().toInt() and 0xff
                val unacked = b.get().toInt() and 0xff
                val gaveUp = b.get().toInt() == 1
                val awaitNewer = b.getLong()
                val n = b.get().toInt() and 0xff
                if (n > MAX_EXCLUDED_IDS || bytes.size != FIXED_SIZE + 4 * n) return null
                val ids = (0 until n).map { b.getInt() }.toSet()
                DmPendingInitiation(
                    responder,
                    eph,
                    spk,
                    if (otkPresent == 1) otkRaw else null,
                    seq,
                    initiatedAt,
                    sends,
                    rejections,
                    unacked,
                    gaveUp,
                    awaitNewer,
                    ids,
                )
            } catch (e: RuntimeException) {
                null
            }
        }
    }
}
