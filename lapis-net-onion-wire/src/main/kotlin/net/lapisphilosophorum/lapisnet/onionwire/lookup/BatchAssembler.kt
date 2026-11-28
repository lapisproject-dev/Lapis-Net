package net.lapisphilosophorum.lapisnet.onionwire.lookup

import net.lapisphilosophorum.lapisnet.onion.CellFormatException
import net.lapisphilosophorum.lapisnet.onion.LookupBatchResponseBody
import net.lapisphilosophorum.lapisnet.onion.LookupResponseBody
import net.lapisphilosophorum.lapisnet.onion.LookupSizeClass
import net.lapisphilosophorum.lapisnet.onion.LookupStatus
import net.lapisphilosophorum.lapisnet.onion.RelayCommand
import net.lapisphilosophorum.lapisnet.onion.RelayMessage

/**
 * Strict reassembly of the answer to ONE version-2 lookup batch (wave Q16). Items 0..n-1 arrive in order, the
 * fragments of an item contiguously and ascending; any deviation is [Result.Broken] (a manipulation). The payload
 * buffer of an item is allocated only after its header was checked (at most one class), and dropped when the item is
 * complete, so the memory is bounded by one class plus the content collected so far (at most n x 128 KiB).
 *
 * One exception, only for the very first fragment: an older relay (0.13.0 or before) that does not know version 2
 * answers a refusal in the version-1 framing, three fragments of class 0 with the same request id. Exactly two statuses
 * are accepted that way: UNSUPPORTED_VERSION ([Result.V1Only]) and RATE_LIMITED ([Result.WholeRefused], an older relay
 * counts the rate limit before it looks at the version). The three fragments are consumed completely, so the circuit
 * can carry the next request. Anything else in the version-1 framing is a manipulation.
 *
 * Not thread-safe (one circuit, one event loop).
 */
internal class BatchAssembler(
    private val requestId: Int,
    private val itemCount: Int,
) {
    /** One answered item; [content] is empty unless [status] is FOUND. */
    class Item(
        val status: Byte,
        val content: ByteArray,
    )

    sealed interface Result {
        class Complete(
            val items: List<Item>,
        ) : Result

        /** The relay answered in the version-1 framing with UNSUPPORTED_VERSION: it does not know version 2. */
        data object V1Only : Result

        /** The relay answered in the version-1 framing with RATE_LIMITED: the whole batch is refused. */
        data object WholeRefused : Result

        data object Broken : Result
    }

    init {
        require(itemCount in 1..net.lapisphilosophorum.lapisnet.onion.LookupBatchRequestBody.MAX_ITEMS) {
            "item count out of range"
        }
    }

    @Volatile var started = false
        private set
    private var finished = false
    private val items = ArrayList<Item>(itemCount)

    // current item
    private var buffer: ByteArray? = null
    private var fragCount = 0
    private var next = 0
    private var status: Byte = 0
    private var length = 0

    // the version-1 refusal path
    private var v1Status: Byte = -1
    private var v1Next = 0

    fun accept(msg: RelayMessage): Result? {
        if (finished) return null
        started = true
        val result = acceptInternal(msg)
        if (result != null) {
            finished = true
            buffer = null
        }
        return result
    }

    private fun acceptInternal(msg: RelayMessage): Result? {
        if (msg.command != RelayCommand.LOOKUP_RESPONSE) return Result.Broken
        val data = msg.data
        val first = items.isEmpty() && next == 0 && buffer == null
        if (data.isNotEmpty() && (data[0].toInt() and 0xFF) == LookupResponseBody.VERSION) {
            // the version-1 refusal: only as the very first message of the answer
            if (!first && v1Next == 0) return Result.Broken
            return acceptV1(data)
        }
        if (v1Next != 0) return Result.Broken
        val header =
            try {
                LookupBatchResponseBody.decodeFragmentHeader(data, itemCount)
            } catch (e: CellFormatException) {
                return Result.Broken
            }
        if (header.requestId != requestId || header.itemIndex != items.size || header.fragIndex != next) {
            return Result.Broken
        }
        if (next == 0) {
            val answer =
                try {
                    LookupBatchResponseBody.decodeAnswerHeader(data, header.fragCount)
                } catch (e: CellFormatException) {
                    return Result.Broken
                }
            fragCount = header.fragCount
            status = answer.status
            length = answer.length
            buffer = ByteArray(fragCount * LookupBatchResponseBody.FRAGMENT_DATA)
        } else if (header.fragCount != fragCount) {
            return Result.Broken
        }
        val buf = buffer ?: return Result.Broken
        data.copyInto(
            buf,
            next * LookupBatchResponseBody.FRAGMENT_DATA,
            LookupBatchResponseBody.HEADER,
            LookupBatchResponseBody.BODY_SIZE,
        )
        next++
        if (next < fragCount) return null
        val content =
            if (status == LookupStatus.FOUND) {
                buf.copyOfRange(LookupSizeClass.ANSWER_HEADER, LookupSizeClass.ANSWER_HEADER + length)
            } else {
                ByteArray(0)
            }
        items += Item(status, content)
        buffer = null
        next = 0
        fragCount = 0
        return if (items.size == itemCount) Result.Complete(items.toList()) else null
    }

    private fun acceptV1(data: ByteArray): Result? {
        val header =
            try {
                LookupResponseBody.decodeFragmentHeader(data)
            } catch (e: CellFormatException) {
                return Result.Broken
            }
        // class 0 only (three fragments), the same request id, strictly ascending
        if (header.requestId != requestId ||
            header.fragCount != LookupSizeClass.fragmentCount(0) ||
            header.fragIndex != v1Next
        ) {
            return Result.Broken
        }
        if (v1Next == 0) {
            val answer =
                try {
                    LookupResponseBody.decodeAnswerHeader(data, header.fragCount)
                } catch (e: CellFormatException) {
                    return Result.Broken
                }
            if (answer.status != LookupStatus.UNSUPPORTED_VERSION && answer.status != LookupStatus.RATE_LIMITED) {
                return Result.Broken
            }
            v1Status = answer.status
        }
        v1Next++
        if (v1Next < header.fragCount) return null
        return if (v1Status == LookupStatus.UNSUPPORTED_VERSION) Result.V1Only else Result.WholeRefused
    }
}
