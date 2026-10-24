package net.lapisphilosophorum.lapisnet.onionwire

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

private val logger = KotlinLogging.logger {}

/** The applications that share the one onion service of a node (wave V0.10.0-F1). MAIL and CALL are reserved for later waves. */
enum class OnionServiceApp(
    val id: Byte,
) {
    DM(1),
    ;

    companion object {
        fun fromId(id: Byte): OnionServiceApp? = entries.firstOrNull { it.id == id }
    }
}

/** The HELLO frame that opens every rendezvous stream: `"LNSV" | version(1) | appId(1)`. */
object OnionServiceHello {
    const val VERSION: Byte = 1
    private val MAGIC = "LNSV".toByteArray(Charsets.US_ASCII)
    const val SIZE = 6

    fun encode(app: OnionServiceApp): ByteArray = MAGIC + byteArrayOf(VERSION, app.id)

    /** The application named by [frame], or `null` for anything that is not a well-formed HELLO of this version. */
    fun decode(frame: ByteArray): OnionServiceApp? {
        if (frame.size != SIZE || !frame.copyOfRange(0, 4).contentEquals(MAGIC) || frame[4] != VERSION) return null
        return OnionServiceApp.fromId(frame[5])
    }
}

/**
 * Dispatches the rendezvous streams that reach the node's onion service to the application named in the first frame.
 * A stream that does not send a well-formed HELLO of a registered application within [helloTimeoutMillis] is closed;
 * the HELLO frame is consumed here and never reaches the application. Nothing about the peer is known or logged.
 */
@ExperimentalOnionApi
class OnionServiceStreamRouter(
    private val helloTimeoutMillis: Long = 10_000L,
) : AutoCloseable {
    private val handlers = ConcurrentHashMap<OnionServiceApp, (OnionRendezvousStream) -> Unit>()
    private val closed = AtomicBoolean(false)
    private val timer: ScheduledExecutorService by lazy {
        Executors.newSingleThreadScheduledExecutor { r ->
            Thread(r, "lapis-net-onion-service-router").apply {
                isDaemon =
                    true
            }
        }
    }

    fun register(
        app: OnionServiceApp,
        handler: (OnionRendezvousStream) -> Unit,
    ) {
        handlers[app] = handler
    }

    /** The handler to install as `OnionServiceHost.onConnection`. */
    fun route(stream: OnionRendezvousStream) {
        if (closed.get()) {
            stream.close()
            return
        }
        val greeted = AtomicBoolean(false)
        val timeout =
            try {
                timer.schedule(
                    {
                        if (!greeted.get()) {
                            logger.debug { "service stream closed: no HELLO in time" }
                            stream.close()
                        }
                    },
                    helloTimeoutMillis,
                    TimeUnit.MILLISECONDS,
                )
            } catch (e: java.util.concurrent.RejectedExecutionException) {
                stream.close()
                return
            }
        stream.onReceive { first ->
            if (!greeted.compareAndSet(false, true)) {
                stream.close()
                return@onReceive
            }
            timeout.cancel(false)
            val app = OnionServiceHello.decode(first)
            val handler = app?.let { handlers[it] }
            if (handler == null) {
                logger.debug { "service stream closed: unknown application" }
                stream.close()
                return@onReceive
            }
            handler(stream)
        }
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        handlers.clear()
        runCatching { timer.shutdownNow() }
    }
}
