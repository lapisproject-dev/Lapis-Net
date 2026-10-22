package net.lapisphilosophorum.lapisnet.onionwire

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.onion.E2eType
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onion.OnionIntegrityException
import net.lapisphilosophorum.lapisnet.onion.OnionResourceLimitException
import net.lapisphilosophorum.lapisnet.onion.RelayCommand
import net.lapisphilosophorum.lapisnet.onion.RelayMessage
import net.lapisphilosophorum.lapisnet.onion.RendezvousEndToEnd
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean

private val logger = KotlinLogging.logger {}

/**
 * A bidirectional, end-to-end encrypted message channel to the other end of a rendezvous (either side). Messages are
 * at most [maxPayload] bytes (910) and travel as fixed-size blobs over the rendezvous circuit. A session lives at most as
 * long as the circuits' relay lifetime (10 minutes by default); there is no resumption in this wave.
 *
 * Until [onReceive] is set, at most [PRE_CALLBACK_LIMIT] arriving messages are kept (so a message sent right after the
 * rendezvous completes is not lost); everything beyond is dropped. After that nothing is buffered: a message goes
 * synchronously to the callback, and an exception from the callback closes the stream.
 */
@ExperimentalOnionApi
class OnionRendezvousStream internal constructor(
    private val circuit: OnionClientCircuit,
    private val e2e: RendezvousEndToEnd,
    private val random: SecureRandom = SecureRandom(),
) : AutoCloseable {
    private val closed = AtomicBoolean(false)
    private val lock = Any()
    private var receiver: ((ByteArray) -> Unit)? = null
    private val early = ArrayDeque<ByteArray>()

    @Volatile private var closeListener: () -> Unit = {}

    @Volatile private var ownerCloseListener: () -> Unit = {}

    /** For the creator of the stream (separate from the application's [onClose]); runs immediately if already closed. */
    internal fun onOwnerClose(callback: () -> Unit) {
        ownerCloseListener = callback
        if (closed.get()) callback()
    }

    val maxPayload: Int get() = e2e.maxPayload

    val isClosed: Boolean get() = closed.get()

    /** Sets the receive callback and delivers anything that arrived before it was set. */
    fun onReceive(callback: (ByteArray) -> Unit) {
        val pending: List<ByteArray>
        synchronized(lock) {
            receiver = callback
            pending = early.toList()
            early.clear()
        }
        pending.forEach { dispatch(it) }
    }

    fun onClose(callback: () -> Unit) {
        closeListener = callback
        if (closed.get()) callback()
    }

    /** `false` if the stream is closed, [data] is too large, or the circuit refused it. */
    fun send(data: ByteArray): Boolean {
        if (closed.get() || data.size > e2e.maxPayload) return false
        val sent =
            try {
                synchronized(lock) {
                    if (closed.get()) return false
                    circuit.send(RelayMessage(RelayCommand.RENDEZVOUS_DATA, 0, e2e.seal(E2eType.DATA, data, random)))
                }
            } catch (e: IllegalStateException) {
                false // closed concurrently, or the cipher is exhausted
            } catch (e: OnionResourceLimitException) {
                false
            }
        if (!sent) shutdown(sendEnd = false)
        return sent
    }

    /** Called by the owner with a RENDEZVOUS_DATA payload. */
    internal fun deliver(blob: ByteArray) {
        if (closed.get()) return
        val opened =
            try {
                synchronized(lock) { e2e.open(blob) }
            } catch (e: OnionIntegrityException) {
                logger.debug { "rendezvous stream closed: integrity failure" }
                shutdown(sendEnd = false)
                return
            } catch (e: IllegalStateException) {
                shutdown(sendEnd = false)
                return
            }
        when (opened.first) {
            E2eType.DATA -> {
                val cb =
                    synchronized(lock) {
                        val r = receiver
                        if (r == null) {
                            if (early.size < PRE_CALLBACK_LIMIT) early.addLast(opened.second)
                        }
                        r
                    }
                if (cb != null) dispatch(opened.second)
            }
            E2eType.END -> shutdown(sendEnd = false)
            E2eType.DROP -> Unit
        }
    }

    private fun dispatch(data: ByteArray) {
        val cb = synchronized(lock) { receiver } ?: return
        try {
            cb(data)
        } catch (e: RuntimeException) {
            logger.debug { "rendezvous stream closed: receiver failed" }
            shutdown(sendEnd = true)
        }
    }

    /** The circuit underneath is gone. */
    internal fun networkClosed() = shutdown(sendEnd = false)

    private fun shutdown(sendEnd: Boolean) {
        if (!closed.compareAndSet(false, true)) return
        if (sendEnd) {
            runCatching {
                synchronized(lock) {
                    circuit.send(
                        RelayMessage(RelayCommand.RENDEZVOUS_DATA, 0, e2e.seal(E2eType.END, ByteArray(0), random)),
                    )
                }
            }
        }
        circuit.close()
        synchronized(lock) { e2e.close() }
        runCatching { ownerCloseListener() }
        runCatching { closeListener() }
    }

    /** Sends an end-of-session marker, destroys the circuit (which also tears down the other half at the rendezvous point) and zeroises the keys. */
    override fun close() = shutdown(sendEnd = true)

    override fun toString(): String = "OnionRendezvousStream(REDACTED)"

    private companion object {
        const val PRE_CALLBACK_LIMIT = 8
    }
}
