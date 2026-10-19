package net.lapisphilosophorum.lapisnet.browser

import net.lapisphilosophorum.lapisnet.call.CallMediaEngine
import net.lapisphilosophorum.lapisnet.call.CallMediaObserver
import net.lapisphilosophorum.lapisnet.call.CallMediaSession

/**
 * V0.8.7b - defers creating the real [CallMediaEngine] until the first call actually needs a media
 * session. `WebRtcCallMediaEngine.create()` immediately opens an audio device module (and with it
 * possibly the microphone), which must not happen merely because the browser node started.
 *
 * [close] only closes an engine that was really created, and is idempotent.
 */
class LazyCallMediaEngine(
    private val factory: () -> CallMediaEngine,
) : CallMediaEngine {
    private var engine: CallMediaEngine? = null
    private var closed = false

    @Synchronized
    override fun newSession(observer: CallMediaObserver): CallMediaSession {
        check(!closed) { "media engine already closed" }
        val created = engine ?: factory().also { engine = it }
        return created.newSession(observer)
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        engine?.close()
        engine = null
    }
}
