package net.lapisphilosophorum.lapisnet.onion

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.onion.fake.FixedClock
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

class OnionKeyRingConcurrencyTest :
    FunSpec({
        test("rotation in parallel with handshakes never yields an exception or a wrongly zeroised key") {
            val clock = FixedClock()
            val now = clock.millis() / 1000
            val identity = Secp256k1KeyPair.generate()
            val ring = OnionKeyRing(identity.publicKey)

            fun fresh(): Pair<OnionKeyBinding, X25519KeyPair> {
                val kp = X25519KeyPair.generate()
                return OnionKeyBinding.create(identity, kp.publicKey, now + 100_000) to kp
            }
            val (b0, k0) = fresh()
            ring.install(b0, k0.privateKey, now)
            val relay =
                OnionRelay(
                    ring,
                    OnionRelayLimits(
                        maxCircuitsTotal = 1_000_000,
                        maxCircuitsPerLink = 1_000_000,
                        createsPerSecondPerLink = 1_000_000_000,
                        createsPerSecondTotal = 1_000_000_000,
                    ),
                    clock,
                )
            val destroyBody = DestroyBody.encode(DestroyReason.FINISHED)
            val errors = ConcurrentLinkedQueue<Throwable>()
            val stop = AtomicBoolean(false)
            val pool = Executors.newFixedThreadPool(5)
            val done = CountDownLatch(4)
            // CREATEs addressed to the CURRENT binding at the time of building; a rotation may race, so the
            // only acceptable outcomes are CREATED or DESTROY, never an exception
            repeat(4) { t ->
                pool.submit {
                    try {
                        var i = 1
                        while (!stop.get()) {
                            val binding = ring.current() ?: continue
                            val (_, create) = NtorHandshake.clientStart(binding, 1)
                            val cell = Cell(t * 1_000_000 + i++, CellCommand.CREATE, create.encode())
                            val out = relay.onCell(LinkId(t.toLong()), cell).single() as RelayAction.SendCell
                            if (out.cell.command == CellCommand.CREATED) {
                                relay.onCell(
                                    LinkId(t.toLong()),
                                    Cell(cell.circuitId, CellCommand.DESTROY, destroyBody),
                                )
                            }
                        }
                    } catch (e: Throwable) {
                        errors.add(e)
                    } finally {
                        done.countDown()
                    }
                }
            }
            pool.submit {
                try {
                    repeat(200) {
                        val (b, k) = fresh()
                        ring.install(b, k.privateKey, now)
                    }
                } catch (e: Throwable) {
                    errors.add(e)
                } finally {
                    stop.set(true)
                }
            }
            done.await(60, TimeUnit.SECONDS) shouldBe true
            pool.shutdownNow()
            errors.toList() shouldBe emptyList()
            relay.close()
            ring.close()
        }
    })
