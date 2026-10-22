package net.lapisphilosophorum.lapisnet.onion

import net.lapisphilosophorum.lapisnet.onion.OnionConstants.BODY_SIZE

enum class CellCommand(
    val code: Byte,
) {
    PADDING(0),
    CREATE(1),
    CREATED(2),
    RELAY(3),
    DESTROY(4),
    ;

    companion object {
        fun fromCode(b: Byte): CellCommand? = entries.firstOrNull { it.code == b }
    }
}

/** A fixed-size link-level cell. [circuitId] 0 is reserved for PADDING (and PADDING must use 0). */
class Cell(
    val circuitId: Int,
    val command: CellCommand,
    body: ByteArray,
) {
    private val storedBody: ByteArray

    init {
        require(body.size == BODY_SIZE) { "cell body must be exactly $BODY_SIZE bytes" }
        require((circuitId == 0) == (command == CellCommand.PADDING)) {
            "circuit id 0 is reserved for PADDING and PADDING must use it"
        }
        storedBody = body.copyOf()
    }

    /** Fresh copy on every access. */
    val body: ByteArray get() = storedBody.copyOf()

    override fun equals(other: Any?): Boolean =
        other is Cell &&
            circuitId == other.circuitId &&
            command == other.command &&
            storedBody.contentEquals(other.storedBody)

    override fun hashCode(): Int = 31 * (31 * circuitId + command.hashCode()) + storedBody.contentHashCode()

    /** Never prints body bytes. */
    override fun toString(): String = "Cell(circuitId=$circuitId, command=$command)"
}
