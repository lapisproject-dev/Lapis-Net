package net.lapisphilosophorum.lapisnet.networking.relay

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.libp2p.core.PeerId
import io.libp2p.core.multiformats.Multiaddr
import java.time.Duration
import java.time.Instant

private fun peer(seed: Int): PeerId = PeerId(ByteArray(32) { seed.toByte() })

private fun from(
    ip: String,
    port: Int = 4001,
): Multiaddr = Multiaddr("/ip4/$ip/tcp/$port")

/**
 * The relay-side reservation table, on its own.
 *
 * `MultiNodeCircuitRelayTest` proves the end-to-end path but can only reach the registry through
 * real nodes on loopback, which makes exactly the properties that matter here - the counter balance
 * across renewals and expiry, the caps, the Sybil floor, the CONNECT rate limit - either impossible
 * or absurdly slow to exercise. Every one of them is a bound an unauthenticated stranger would
 * otherwise be free to grow, so each gets a direct test.
 */
class RelayReservationRegistryTest :
    FunSpec({
        val now = Instant.parse("2026-09-08T12:00:00Z")

        test("reservations are granted up to maxConcurrentReservations and then refused") {
            val registry =
                RelayReservationRegistry(
                    RelayServerLimits(maxConcurrentReservations = 2, maxReservationsPerSourceAddress = 99),
                )
            registry.reserve(peer(1), from("10.0.0.1"), now).shouldNotBeNull()
            registry.reserve(peer(2), from("10.0.0.2"), now).shouldNotBeNull()
            registry.reserve(peer(3), from("10.0.0.3"), now).shouldBeNull()
            registry.reservationCount() shouldBe 2

            // A renewal is not a new slot, or a well-behaved client would be refused as soon as the
            // relay filled up.
            registry.reserve(peer(1), from("10.0.0.1"), now).shouldNotBeNull()
            registry.reservationCount() shouldBe 2
        }

        test("one source address cannot squat the table with freshly minted peer ids") {
            // The Sybil floor: PeerIds cost one keygen, so counting only per PeerId lets a single
            // machine take every slot. Counting per source address makes the flood cost network
            // locations instead.
            val registry =
                RelayReservationRegistry(
                    RelayServerLimits(maxConcurrentReservations = 64, maxReservationsPerSourceAddress = 2),
                )
            registry.reserve(peer(1), from("203.0.113.7", 1111), now).shouldNotBeNull()
            registry.reserve(peer(2), from("203.0.113.7", 2222), now).shouldNotBeNull()
            // Same host, different ephemeral port and a brand-new identity - still refused.
            registry.reserve(peer(3), from("203.0.113.7", 3333), now).shouldBeNull()
            // A genuinely different location is unaffected.
            registry.reserve(peer(4), from("203.0.113.8"), now).shouldNotBeNull()
            // And an existing holder can still renew from its own address.
            registry.reserve(peer(1), from("203.0.113.7", 1111), now).shouldNotBeNull()
            registry.reservationCount() shouldBe 3
        }

        test("expired reservations are pruned on the next call") {
            val registry = RelayReservationRegistry(RelayServerLimits(reservationTtl = Duration.ofMinutes(15)))
            registry.reserve(peer(1), from("10.0.0.1"), now).shouldNotBeNull()
            registry.find(peer(1), now.plus(Duration.ofMinutes(14))).shouldNotBeNull()
            registry.find(peer(1), now.plus(Duration.ofMinutes(16))).shouldBeNull()
            registry.reservationCount() shouldBe 0
        }

        test("claiming a circuit is atomic with the lookup and answers the three cases distinctly") {
            val registry =
                RelayReservationRegistry(
                    RelayServerLimits(maxConcurrentCircuits = 10, maxCircuitsPerReservation = 2),
                )
            registry.claimCircuitFor(peer(1), now).shouldBeInstanceOf<CircuitClaim.NoReservation>()

            registry.reserve(peer(1), from("10.0.0.1"), now).shouldNotBeNull()
            val first = registry.claimCircuitFor(peer(1), now).shouldBeInstanceOf<CircuitClaim.Granted>()
            registry.claimCircuitFor(peer(1), now).shouldBeInstanceOf<CircuitClaim.Granted>()
            registry.claimCircuitFor(peer(1), now).shouldBeInstanceOf<CircuitClaim.LimitExceeded>()
            registry.circuitCount() shouldBe 2

            registry.releaseCircuit(first.reservation)
            registry.circuitCount() shouldBe 1
            registry.claimCircuitFor(peer(1), now).shouldBeInstanceOf<CircuitClaim.Granted>()
        }

        test("the relay-wide circuit budget is enforced across reservations") {
            val registry =
                RelayReservationRegistry(
                    RelayServerLimits(maxConcurrentCircuits = 2, maxCircuitsPerReservation = 8),
                )
            registry.reserve(peer(1), from("10.0.0.1"), now).shouldNotBeNull()
            registry.reserve(peer(2), from("10.0.0.2"), now).shouldNotBeNull()
            registry.claimCircuitFor(peer(1), now).shouldBeInstanceOf<CircuitClaim.Granted>()
            registry.claimCircuitFor(peer(2), now).shouldBeInstanceOf<CircuitClaim.Granted>()
            registry.claimCircuitFor(peer(1), now).shouldBeInstanceOf<CircuitClaim.LimitExceeded>()
            registry.circuitCount() shouldBe 2
        }

        test("a renewal keeps the per-peer circuit counter, so live circuits stay counted") {
            val registry = RelayReservationRegistry(RelayServerLimits(maxCircuitsPerReservation = 2))
            registry.reserve(peer(1), from("10.0.0.1"), now).shouldNotBeNull()
            val claimed = registry.claimCircuitFor(peer(1), now).shouldBeInstanceOf<CircuitClaim.Granted>()

            val renewed = registry.reserve(peer(1), from("10.0.0.1"), now.plus(Duration.ofMinutes(13)))!!
            renewed.liveCircuits.get() shouldBe 1

            // The circuit opened before the renewal releases against the object its close callback
            // captured; both objects must be the same counter, or capacity would leak away.
            registry.releaseCircuit(claimed.reservation)
            renewed.liveCircuits.get() shouldBe 0
            registry.circuitCount() shouldBe 0
        }

        test("a reservation that expires while its circuits are live does not reset that peer's counter") {
            // Without the peer-keyed counter that outlives the reservation, the re-reservation below
            // would start from zero while the pre-expiry circuit is still up, letting this peer hold
            // maxCircuitsPerReservation + 1 at once - and then decrement an orphan on release.
            val registry =
                RelayReservationRegistry(
                    RelayServerLimits(reservationTtl = Duration.ofMinutes(15), maxCircuitsPerReservation = 1),
                )
            registry.reserve(peer(1), from("10.0.0.1"), now).shouldNotBeNull()
            val live = registry.claimCircuitFor(peer(1), now).shouldBeInstanceOf<CircuitClaim.Granted>()

            val later = now.plus(Duration.ofMinutes(20))
            registry.find(peer(1), later).shouldBeNull()
            registry.reserve(peer(1), from("10.0.0.1"), later).shouldNotBeNull()

            registry.claimCircuitFor(peer(1), later).shouldBeInstanceOf<CircuitClaim.LimitExceeded>()
            registry.releaseCircuit(live.reservation)
            registry.claimCircuitFor(peer(1), later).shouldBeInstanceOf<CircuitClaim.Granted>()
        }

        test("CONNECT attempts are rate limited per initiator and recover after the window") {
            val registry =
                RelayReservationRegistry(
                    RelayServerLimits(
                        maxConnectAttemptsPerWindow = 3,
                        connectRateLimitWindow = Duration.ofMinutes(1),
                    ),
                )
            repeat(3) { registry.allowConnectAttempt(peer(9), now) shouldBe true }
            registry.allowConnectAttempt(peer(9), now) shouldBe false
            // Another initiator is unaffected: the limit is per peer, not a global throttle.
            registry.allowConnectAttempt(peer(8), now) shouldBe true
            // Once the window has slid past, the budget is back.
            registry.allowConnectAttempt(peer(9), now.plus(Duration.ofSeconds(61))) shouldBe true
        }

        test("the rate limiter's own table is bounded and self-pruning") {
            val limiter = ConnectRateLimiter(limit = 1, window = Duration.ofMinutes(1), maxTrackedPeers = 4)
            (1..4).forEach { limiter.tryAcquire(peer(it), now) shouldBe true }
            limiter.trackedPeers() shouldBe 4
            // A fifth, previously unseen initiator is refused rather than growing the table - the
            // limiter must not become the unbounded structure it exists to prevent.
            limiter.tryAcquire(peer(5), now) shouldBe false
            limiter.trackedPeers() shouldBe 4
            // Elapsed windows are dropped, and the table takes new peers again.
            val later = now.plus(Duration.ofSeconds(61))
            limiter.tryAcquire(peer(5), later) shouldBe true
            limiter.trackedPeers() shouldBe 1
        }

        test("a source key ignores the port and tolerates an address with no host component") {
            reservationSourceKey(from("198.51.100.4", 1)) shouldBe reservationSourceKey(from("198.51.100.4", 2))
            reservationSourceKey(from("198.51.100.4")) shouldBe "ip4/198.51.100.4"
            reservationSourceKey(Multiaddr("/ip6/::1/tcp/4001")) shouldBe "ip6/::1"
            // Nothing recognisable to key on: the per-address cap simply does not apply, and the
            // per-PeerId cap still does. Refusing here would be a denial of service of its own.
            reservationSourceKey(Multiaddr("/unix/%2Ftmp%2Fsock")).shouldBeNull()
        }
    })
