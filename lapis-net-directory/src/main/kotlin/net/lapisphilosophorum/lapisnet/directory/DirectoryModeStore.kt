package net.lapisphilosophorum.lapisnet.directory

import io.github.oshai.kotlinlogging.KotlinLogging
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption

private val logger = KotlinLogging.logger {}

/** The persisted directory state of this node: which publication mode it ran in last and the last sequence it used. */
data class DirectoryModeState(
    val mode: DirectoryAnonymityMode,
    val lastSequence: Long,
)

/**
 * Where the previous [DirectoryAnonymityMode] comes from after a restart (wave V0.10.0-D), so that a mode switch is
 * detected and the other record type is retired. Not a migration: a new, tiny state file. A missing or corrupt file
 * means "no previous state", which is treated as [DirectoryAnonymityMode.OFF]: a normal node never publishes a
 * revocation and never writes to the anonymous topic.
 */
interface DirectoryModeStore {
    fun load(): DirectoryModeState?

    fun save(state: DirectoryModeState)
}

/** Test store. */
class InMemoryDirectoryModeStore(
    initial: DirectoryModeState? = null,
) : DirectoryModeStore {
    @Volatile private var state: DirectoryModeState? = initial

    override fun load(): DirectoryModeState? = state

    override fun save(state: DirectoryModeState) {
        this.state = state
    }
}

/**
 * File-backed [DirectoryModeStore]: `"LNDM"(4) | version(1) | mode(1) | lastSequence(8)`, written atomically
 * (temp file + `ATOMIC_MOVE`). Reading tolerates any damage (returns `null`); log lines never contain file content.
 */
class FileDirectoryModeStore(
    private val file: Path,
) : DirectoryModeStore {
    override fun load(): DirectoryModeState? {
        try {
            if (!Files.isRegularFile(file) || Files.size(file) != SIZE.toLong()) {
                if (Files.exists(file)) logger.warn { "directory mode file ignored: unexpected shape" }
                return null
            }
            val b = ByteBuffer.wrap(Files.readAllBytes(file))
            val magic = ByteArray(4).also { b.get(it) }
            if (!magic.contentEquals(MAGIC) || b.get() != VERSION) {
                logger.warn { "directory mode file ignored: unknown format" }
                return null
            }
            val mode = DirectoryAnonymityMode.entries.getOrNull(b.get().toInt()) ?: return null
            val seq = b.getLong()
            if (seq < 0) return null
            return DirectoryModeState(mode, seq)
        } catch (e: IOException) {
            logger.warn { "directory mode file could not be read (${e.javaClass.simpleName})" }
            return null
        } catch (e: RuntimeException) {
            logger.warn { "directory mode file ignored (${e.javaClass.simpleName})" }
            return null
        }
    }

    override fun save(state: DirectoryModeState) {
        val bytes =
            ByteBuffer
                .allocate(SIZE)
                .put(MAGIC)
                .put(VERSION)
                .put(state.mode.ordinal.toByte())
                .putLong(state.lastSequence)
                .array()
        val parent = file.toAbsolutePath().parent
        Files.createDirectories(parent)
        val tmp = Files.createTempFile(parent, file.fileName.toString(), ".tmp")
        try {
            Files.write(tmp, bytes)
            try {
                Files.move(tmp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            } catch (e: AtomicMoveNotSupportedException) {
                Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING)
            }
        } finally {
            Files.deleteIfExists(tmp)
        }
    }

    private companion object {
        val MAGIC = "LNDM".toByteArray(Charsets.US_ASCII)
        const val VERSION: Byte = 1
        const val SIZE = 4 + 1 + 1 + 8
    }
}
