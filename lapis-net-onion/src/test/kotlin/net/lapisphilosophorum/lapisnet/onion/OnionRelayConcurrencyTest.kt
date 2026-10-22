package net.lapisphilosophorum.lapisnet.onion

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.onion.fake.FixedClock
import net.lapisphilosophorum.lapisnet.onion.fake.newTestRelay
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

class OnionRelayConcurrencyTest :
    FunSpec({
        test(
            "32 threads x 500 CREATEs never exceed the circuit cap; parallel DESTROYs are idempotent",
        ).config(timeout = kotlin.time.Duration.parse("60s")) {
            val cap = 1000
            val clock = FixedClock()
            val r =
                newTestRelay(
                    clock,
                    limits =
                        OnionRelayLimits(
                            maxCircuitsTotal = cap,
                            maxCircuitsPerLink = 100_000,
                            createsPerSecondPerLink = 1_000_000_000,
                            createsPerSecondTotal = 1_000_000_000,
                        ),
                )
            // one valid CREATE body, replayed under many circuit ids (the relay does not track X)
            val template = ClientCircuitBuilder(listOf(r.binding), clock = clock).start().body
            val threads = 32
            val perThread = 500
            val pool = Executors.newFixedThreadPool(threads + 1)
            val start = CountDownLatch(1)
            val done = CountDownLatch(threads)
            val created = ConcurrentLinkedQueue<Pair<Long, Int>>()
            val maxSeen = AtomicInteger(0)
            val stop = AtomicBoolean(false)
            pool.submit {
                while (!stop.get()) maxSeen.accumulateAndGet(r.relay.circuitCount, ::maxOf)
            }
            for (t in 0 until threads) {
                pool.submit {
                    start.await()
                    for (i in 1..perThread) {
                        val actions = r.relay.onCell(LinkId(t.toLong()), Cell(i, CellCommand.CREATE, template))
                        val cell = (actions.single() as RelayAction.SendCell).cell
                        if (cell.command == CellCommand.CREATED) created.add(t.toLong() to i)
                    }
                    done.countDown()
                }
            }
            start.countDown()
            done.await(50, TimeUnit.SECONDS) shouldBe true
            stop.set(true)
            (maxSeen.get() <= cap) shouldBe true
            created.size shouldBe cap
            r.relay.circuitCount shouldBe cap

            // every successful circuit is destroyed twice, from several threads at once
            val items = created.toList()
            val done2 = CountDownLatch(threads)
            for (t in 0 until threads) {
                pool.submit {
                    for ((idx, item) in items.withIndex()) {
                        if (idx % threads == t || idx % 7 == 0) {
                            r.relay.onCell(
                                LinkId(item.first),
                                Cell(item.second, CellCommand.DESTROY, DestroyBody.encode(DestroyReason.FINISHED)),
                            )
                        }
                    }
                    done2.countDown()
                }
            }
            done2.await(50, TimeUnit.SECONDS) shouldBe true
            r.relay.circuitCount shouldBe 0
            pool.shutdownNow()
        }
    })
