package net.lapisphilosophorum.lapisnet.onion

import java.security.SecureRandom

/** Status byte of MAILBOX_PUBLISHED. Deliberately coarse: the same value answers every accepted item. */
object MailboxPublishStatus {
    const val ACCEPTED: Byte = 0
    const val RATE_LIMITED: Byte = 2
}

/**
 * MAILBOX_PUBLISH body (wave V0.10.0-F1), always exactly [BODY_SIZE] (720) bytes:
 * `itemIndex(1) | fragIndex(1) | fragCount(1) = 8 | reserved(1) = 0 | data(716)`. One item is a sealed
 * mailbox item of [ITEM_SIZE] (5,728) bytes sent as [FRAGMENT_COUNT] consecutive fragments, which is how an
 * item larger than one cell reaches the last hop. The relay never interprets the item: it checks the size,
 * reassembles it and hands it to the host, which announces it on the shared mailbox topic. 720 bytes fit the
 * relay-message capacity of a circuit with the maximum number of hops (929 bytes).
 */
object MailboxPublishBody {
    const val BODY_SIZE = 720
    const val HEADER_SIZE = 4
    const val FRAGMENT_SIZE = BODY_SIZE - HEADER_SIZE
    const val FRAGMENT_COUNT = 8
    const val ITEM_SIZE = FRAGMENT_SIZE * FRAGMENT_COUNT

    /** A decoded fragment header. */
    class Header(
        val itemIndex: Int,
        val fragIndex: Int,
    )

    fun encodeFragment(
        itemIndex: Int,
        fragIndex: Int,
        fragment: ByteArray,
    ): ByteArray {
        require(itemIndex in 0..255 && fragIndex in 0 until FRAGMENT_COUNT) { "fragment index out of range" }
        require(fragment.size == FRAGMENT_SIZE) { "fragment has the wrong size" }
        val out = ByteArray(BODY_SIZE)
        out[0] = itemIndex.toByte()
        out[1] = fragIndex.toByte()
        out[2] = FRAGMENT_COUNT.toByte()
        out[3] = 0
        fragment.copyInto(out, HEADER_SIZE)
        return out
    }

    /** Splits an [ITEM_SIZE]-byte item into the [FRAGMENT_COUNT] message bodies of item [itemIndex]. */
    fun encodeItem(
        itemIndex: Int,
        item: ByteArray,
    ): List<ByteArray> {
        require(item.size == ITEM_SIZE) { "mailbox item must be exactly $ITEM_SIZE bytes" }
        return (0 until FRAGMENT_COUNT).map { i ->
            encodeFragment(itemIndex, i, item.copyOfRange(i * FRAGMENT_SIZE, (i + 1) * FRAGMENT_SIZE))
        }
    }

    /**
     * Checks the exact length first, then the header: `fragCount` must be 8 and `reserved` zero.
     *
     * @throws CellFormatException on any deviation.
     */
    fun decodeHeader(data: ByteArray): Header {
        if (data.size != BODY_SIZE) throw CellFormatException("mailbox publish body has the wrong length")
        if ((data[2].toInt() and 0xFF) != FRAGMENT_COUNT || data[3].toInt() != 0) {
            throw CellFormatException("mailbox publish header is malformed")
        }
        val fragIndex = data[1].toInt() and 0xFF
        if (fragIndex >= FRAGMENT_COUNT) throw CellFormatException("mailbox fragment index out of range")
        return Header(data[0].toInt() and 0xFF, fragIndex)
    }

    fun fragmentOf(data: ByteArray): ByteArray = data.copyOfRange(HEADER_SIZE, BODY_SIZE)

    /** Test helper: a random item of the exact size. */
    fun randomItem(random: SecureRandom = SecureRandom()): ByteArray = ByteArray(ITEM_SIZE).also(random::nextBytes)
}
