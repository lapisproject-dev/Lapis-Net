package net.lapisphilosophorum.lapisnet.networking.relay

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.libp2p.core.PeerId
import io.libp2p.core.multiformats.Multiaddr
import java.time.Instant

private fun peer(seed: Int): PeerId = PeerId(ByteArray(32) { seed.toByte() })

private fun from(ip: String): Multiaddr = Multiaddr("/ip4/$ip/tcp/4001")

/**
 * Priority by usage balance: inside the headroom band debtors are deferred, outside it everybody is
 * served - the balance is never a hard gate on its own.
 */
class RelayReservationPriorityTest :
    FunSpec({
        val now = Instant.parse("2026-10-18T12:00:00Z")

        // 4 slots, 25% headroom -> soft limit 3: the 4th NEW reservation needs a non-negative balance.
        fun limits(headroom: Double = 0.25) =
            RelayServerLimits(
                maxConcurrentReservations = 4,
                maxReservationsPerSourceAddress = 99,
                maxConcurrentCircuits = 4,
                maxCircuitsPerReservation = 99,
                priorityHeadroomFraction = headroom,
            )

        fun fill(
            registry: RelayReservationRegistry,
            count: Int,
        ) {
            for (i in 1..count) {
                registry
                    .tryReserve(
                        peer(i),
                        from("10.0.0.$i"),
                        now,
                    ).shouldBeInstanceOf<ReservationOutcome.Granted>()
            }
        }

        test("a debtor is still served while capacity below the soft limit is free (no hard gate)") {
            val ledger = RelayUsageLedger()
            val registry = RelayReservationRegistry(limits(), ledger)
            ledger.recordServed(peer(50), 10_000_000)
            registry.tryReserve(peer(50), from("10.1.0.1"), now).shouldBeInstanceOf<ReservationOutcome.Granted>()
        }

        test("inside the headroom band a debtor is deferred and a non-debtor is granted") {
            val ledger = RelayUsageLedger()
            val registry = RelayReservationRegistry(limits(), ledger)
            fill(registry, 3)
            ledger.recordServed(peer(50), 1)
            registry.tryReserve(peer(50), from("10.1.0.1"), now) shouldBe ReservationOutcome.DeferredLowPriority
            // A neutral newcomer (balance 0) and a contributor are admitted into the band.
            registry.tryReserve(peer(51), from("10.1.0.2"), now).shouldBeInstanceOf<ReservationOutcome.Granted>()
        }

        test("a deferred debtor is served later once load drops (reservation expiry)") {
            val ledger = RelayUsageLedger()
            val registry = RelayReservationRegistry(limits(), ledger)
            fill(registry, 3)
            ledger.recordServed(peer(50), 5_000)
            registry.tryReserve(peer(50), from("10.1.0.1"), now) shouldBe ReservationOutcome.DeferredLowPriority
            val later = now.plus(RelayServerLimits().reservationTtl).plusSeconds(1)
            registry.tryReserve(peer(50), from("10.1.0.1"), later).shouldBeInstanceOf<ReservationOutcome.Granted>()
        }

        test("a renewal by a debtor inside the band is always granted") {
            val ledger = RelayUsageLedger()
            val registry = RelayReservationRegistry(limits(), ledger)
            fill(registry, 3)
            ledger.recordServed(peer(2), 9_999_999)
            registry
                .tryReserve(
                    peer(2),
                    from("10.0.0.2"),
                    now.plusSeconds(60),
                ).shouldBeInstanceOf<ReservationOutcome.Granted>()
        }

        test("the hard limit still refuses everybody, including contributors") {
            val ledger = RelayUsageLedger()
            val registry = RelayReservationRegistry(limits(), ledger)
            fill(registry, 4)
            ledger.recordReceivedFrom(peer(50), 1_000_000)
            registry.tryReserve(peer(50), from("10.1.0.1"), now) shouldBe ReservationOutcome.CapacityFull
        }

        test("headroom 0.0 behaves like before: balance is ignored") {
            val ledger = RelayUsageLedger()
            val registry = RelayReservationRegistry(limits(0.0), ledger)
            fill(registry, 3)
            ledger.recordServed(peer(50), 1_000_000)
            registry.tryReserve(peer(50), from("10.1.0.1"), now).shouldBeInstanceOf<ReservationOutcome.Granted>()
            registry.reserve(peer(51), from("10.1.0.2"), now) shouldBe null
        }

        test("the legacy reserve() wrapper returns null for a deferred request") {
            val ledger = RelayUsageLedger()
            val registry = RelayReservationRegistry(limits(), ledger)
            fill(registry, 3)
            ledger.recordServed(peer(50), 1)
            registry.reserve(peer(50), from("10.1.0.1"), now) shouldBe null
        }

        test("circuit claims: a debtor initiator is deferred inside the band, a neutral one is granted") {
            val ledger = RelayUsageLedger()
            val registry = RelayReservationRegistry(limits(), ledger)
            registry.reserve(peer(1), from("10.0.0.1"), now)
            // soft circuit limit 3: claims 1..3 are free for everybody.
            repeat(3) {
                registry.claimCircuitFor(peer(1), now, initiator = peer(60)).shouldBeInstanceOf<CircuitClaim.Granted>()
            }
            ledger.recordServed(peer(61), 100)
            registry.claimCircuitFor(peer(1), now, initiator = peer(61)) shouldBe CircuitClaim.DeferredLowPriority
            registry.circuitCount() shouldBe 3
            registry.claimCircuitFor(peer(1), now, initiator = peer(62)).shouldBeInstanceOf<CircuitClaim.Granted>()
            registry.circuitCount() shouldBe 4
            // Hard limit.
            ledger.recordReceivedFrom(peer(63), 1_000_000)
            registry.claimCircuitFor(peer(1), now, initiator = peer(63)) shouldBe CircuitClaim.LimitExceeded
        }

        test("circuit claims without an initiator are unaffected by the ledger") {
            val registry = RelayReservationRegistry(limits(), RelayUsageLedger())
            registry.reserve(peer(1), from("10.0.0.1"), now)
            repeat(4) { registry.claimCircuitFor(peer(1), now).shouldBeInstanceOf<CircuitClaim.Granted>() }
        }

        test("a debtor initiator below the soft limit is served") {
            val ledger = RelayUsageLedger()
            val registry = RelayReservationRegistry(limits(), ledger)
            registry.reserve(peer(1), from("10.0.0.1"), now)
            ledger.recordServed(peer(61), 100)
            registry.claimCircuitFor(peer(1), now, initiator = peer(61)).shouldBeInstanceOf<CircuitClaim.Granted>()
        }

        test("priorityHeadroomFraction is validated") {
            shouldThrow<IllegalArgumentException> { RelayServerLimits(priorityHeadroomFraction = -0.1) }
            shouldThrow<IllegalArgumentException> { RelayServerLimits(priorityHeadroomFraction = 0.95) }
            RelayServerLimits(priorityHeadroomFraction = 0.0)
            RelayServerLimits(priorityHeadroomFraction = 0.9)
        }

        test("the priority band is clamped: tiny limits never turn priority into a hard gate") {
            softLimit(1, 0.25) shouldBe 1
            softLimit(2, 0.25) shouldBe 1
            softLimit(4, 0.25) shouldBe 3
            softLimit(1, 0.9) shouldBe 1
            softLimit(10, 0.0) shouldBe 10
        }

        test("max=1 reservation: a debtor is served on an idle relay") {
            val ledger = RelayUsageLedger()
            val registry =
                RelayReservationRegistry(
                    RelayServerLimits(maxConcurrentReservations = 1, maxConcurrentCircuits = 1),
                    ledger,
                )
            ledger.recordServed(peer(50), 10_000_000)
            registry.tryReserve(peer(50), from("10.1.0.1"), now).shouldBeInstanceOf<ReservationOutcome.Granted>()
        }

        test("max=1 circuit: a debtor initiator can still open a circuit") {
            val ledger = RelayUsageLedger()
            val registry =
                RelayReservationRegistry(
                    RelayServerLimits(maxConcurrentReservations = 2, maxConcurrentCircuits = 1),
                    ledger,
                )
            registry.tryReserve(peer(1), from("10.0.0.1"), now).shouldBeInstanceOf<ReservationOutcome.Granted>()
            ledger.recordServed(peer(50), 10_000_000)
            registry.claimCircuitFor(peer(1), now, peer(50)).shouldBeInstanceOf<CircuitClaim.Granted>()
        }

        test("max=2: a debtor gets the first slot, is deferred only for the last one") {
            val ledger = RelayUsageLedger()
            val registry =
                RelayReservationRegistry(
                    RelayServerLimits(maxConcurrentReservations = 2, maxConcurrentCircuits = 2),
                    ledger,
                )
            ledger.recordServed(peer(50), 10_000_000)
            registry.tryReserve(peer(50), from("10.1.0.1"), now).shouldBeInstanceOf<ReservationOutcome.Granted>()
            ledger.recordServed(peer(51), 10_000_000)
            registry.tryReserve(peer(51), from("10.1.0.2"), now) shouldBe ReservationOutcome.DeferredLowPriority
        }
    })
