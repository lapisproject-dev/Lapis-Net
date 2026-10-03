package net.lapisphilosophorum.lapisnet.storage

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.Stream
import java.lang.reflect.Proxy
import java.util.concurrent.CompletableFuture

class ReplyTrackingStreamTest :
    FunSpec({
        fun fakeStream(calls: MutableList<String>): Stream =
            Proxy.newProxyInstance(Stream::class.java.classLoader, arrayOf(Stream::class.java)) { _, method, args ->
                calls += "${method.name}${args?.joinToString(prefix = "(", postfix = ")") ?: "()"}"
                if (method.returnType ==
                    CompletableFuture::class.java
                ) {
                    CompletableFuture.completedFuture(Unit)
                } else {
                    null
                }
            } as Stream

        test("it reports a write only once something was written, and passes the write through") {
            val calls = mutableListOf<String>()
            val tracking = ReplyTrackingStream(fakeStream(calls))
            tracking.written shouldBe false
            tracking.close()
            tracking.written shouldBe false

            tracking.writeAndFlush("reply")
            tracking.written shouldBe true
            calls shouldBe listOf("close()", "writeAndFlush(reply)")
        }
    })
