@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.dmonion

import io.kotest.assertions.withClue
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.directory.DirectoryReachability
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import java.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * Regression for the late visibility in the anonymous directory: B starts only AFTER A has published its directory
 * objects, so B was not subscribed to the gossip topics when A published. Without the early republication B would
 * see A only after the hourly republication. With the early schedule (5 s ... 5 min after the first publication) B sees
 * A without any restart within a few minutes. The timeline goes to stdout (timestamps and booleans only).
 */
class MultiNodeEarlyRepublishVisibilityTest :
    FunSpec({
        val relays = List(6) { RelayHost() }
        for (i in relays.indices) for (j in i + 1 until relays.size) relays[i].connectTo(relays[j])
        val locator = SyntheticLocator()
        relays.forEachIndexed { i, r -> locator.put(r.key, 10 + i, i) }
        val a = DmOnionNode(relays, locator)
        val b = DmOnionNode(relays, locator)

        afterSpec {
            runCatching { a.stop() }
            runCatching { b.stop() }
            relays.forEach { runCatching { it.close() } }
        }

        test(
            "B starts after A published and still sees A (record, service descriptor, prekey bundle) without a restart",
        ).config(timeout = 600.seconds) {
            val t0 = System.currentTimeMillis()

            fun at() = "t+${(System.currentTimeMillis() - t0) / 1000}s"
            a.start()
            a.awaitPublished() shouldBe true
            println("TIMELINE ${at()} A published (publications=${a.runtime.publications()})")
            // B subscribes to the directory topics only after A's first publication AND its first early slots
            Thread.sleep(25_000)
            b.start()
            println("TIMELINE ${at()} B started")
            b.awaitPublished() shouldBe true
            println("TIMELINE ${at()} B published (publications=${b.runtime.publications()})")

            fun bSeesA() =
                b.runtime.resolveIdentity(a.key) is DirectoryReachability.Hidden &&
                    b.bundleGossip.lookup(a.key) != null

            var lastLine = ""
            val seen =
                awaitCondition(Duration.ofSeconds(360)) {
                    val line =
                        "B->A ${b.runtime.resolveIdentity(a.key)::class.simpleName}, " +
                            "bundle=${b.bundleGossip.lookup(a.key) != null}"
                    if (line != lastLine) println("TIMELINE ${at()} $line")
                    lastLine = line
                    bSeesA()
                }
            println("TIMELINE ${at()} done, seen=$seen")
            withClue("B->A ${b.runtime.resolveIdentity(a.key)::class.simpleName}") { seen shouldBe true }
        }
    })
