package net.lapisphilosophorum.lapisnet.browser

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.call.CallMediaEngine
import net.lapisphilosophorum.lapisnet.call.CallMediaObserver
import net.lapisphilosophorum.lapisnet.call.CallMediaSession
import java.util.concurrent.atomic.AtomicInteger

private class CountingEngine : CallMediaEngine {
    val sessions = AtomicInteger(0)
    val closes = AtomicInteger(0)

    override fun newSession(observer: CallMediaObserver): CallMediaSession {
        sessions.incrementAndGet()
        return FakeBrowserCallMediaEngine().newSession(observer)
    }

    override fun close() {
        closes.incrementAndGet()
    }
}

private val noopObserver =
    object : CallMediaObserver {
        override fun onMediaConnected() {}

        override fun onMediaFailed(cause: String) {}

        override fun onMediaClosed() {}
    }

class LazyCallMediaEngineTest :
    FunSpec({
        test("the real engine is created only on the first session and exactly once") {
            val created = AtomicInteger(0)
            val real = CountingEngine()
            val lazy = LazyCallMediaEngine { created.incrementAndGet().let { real } }
            created.get() shouldBe 0
            lazy.newSession(noopObserver)
            lazy.newSession(noopObserver)
            created.get() shouldBe 1
            real.sessions.get() shouldBe 2
        }

        test("close never creates an engine, closes a created one once, and is idempotent") {
            val created = AtomicInteger(0)
            val never = LazyCallMediaEngine { created.incrementAndGet().let { CountingEngine() } }
            never.close()
            never.close()
            created.get() shouldBe 0

            val real = CountingEngine()
            val lazy = LazyCallMediaEngine { real }
            lazy.newSession(noopObserver)
            lazy.close()
            lazy.close()
            real.closes.get() shouldBe 1
            shouldThrow<IllegalStateException> { lazy.newSession(noopObserver) }
        }
    })
