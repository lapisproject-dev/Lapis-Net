package net.lapisphilosophorum.lapisnet.onion

import net.lapisphilosophorum.lapisnet.onion.OnionConstants.BODY_SIZE
import net.lapisphilosophorum.lapisnet.onion.OnionConstants.CELL_SIZE
import net.lapisphilosophorum.lapisnet.onion.OnionConstants.HEADER_SIZE

/**
 * Cell wire codec. Hardening: there is no length field on the wire, so no allocation ever depends
 * on attacker-controlled data - the input size is compared to [CELL_SIZE] BEFORE anything is
 * copied. Unknown commands and a circuit id of 0 on a non-PADDING cell are rejected.
 */
object CellCodec {
    fun encode(cell: Cell): ByteArray {
        val out = ByteArray(CELL_SIZE)
        val id = cell.circuitId
        out[0] = (id ushr 24).toByte()
        out[1] = (id ushr 16).toByte()
        out[2] = (id ushr 8).toByte()
        out[3] = id.toByte()
        out[4] = cell.command.code
        cell.body.copyInto(out, HEADER_SIZE)
        return out
    }

    fun decode(bytes: ByteArray): Cell {
        if (bytes.size != CELL_SIZE) throw CellFormatException("cell has wrong size")
        return decodeAt(bytes, 0)
    }

    fun decode(
        bytes: ByteArray,
        offset: Int,
    ): Cell {
        if (offset < 0 || offset > bytes.size - CELL_SIZE) throw CellFormatException("cell has wrong size")
        return decodeAt(bytes, offset)
    }

    private fun decodeAt(
        bytes: ByteArray,
        offset: Int,
    ): Cell {
        val id =
            ((bytes[offset].toInt() and 0xFF) shl 24) or
                ((bytes[offset + 1].toInt() and 0xFF) shl 16) or
                ((bytes[offset + 2].toInt() and 0xFF) shl 8) or
                (bytes[offset + 3].toInt() and 0xFF)
        val command = CellCommand.fromCode(bytes[offset + 4]) ?: throw CellFormatException("unknown cell command")
        if ((id == 0) != (command == CellCommand.PADDING)) throw CellFormatException("invalid circuit id for command")
        return Cell(id, command, bytes.copyOfRange(offset + HEADER_SIZE, offset + HEADER_SIZE + BODY_SIZE))
    }
}
