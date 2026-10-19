package net.lapisphilosophorum.lapisnet.madli

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerId
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair

private fun testPeerId(seed: Byte): PeerId = PeerId(ByteArray(34) { seed })

private fun testMetrics(reachabilityMicros: Int = 500_000): MadliMetrics =
    MadliMetrics(
        reachabilityMicros = reachabilityMicros,
        medianBandwidthBytesPerSec = 10_000_000L,
        medianLatencyMillis = 50,
        deliveryIntegrityMicros = 900_000,
        routingHelpfulnessMicros = 700_000,
        observationCount = 10,
    )

private fun vector(
    observer: Secp256k1KeyPair,
    peer: PeerId,
    epochDay: Long = 100L,
    reachabilityMicros: Int = 500_000,
): MadliDailyVector = MadliDailyVector.create(observer, peer, epochDay, testMetrics(reachabilityMicros))

class MadliVectorIndexTest :
    FunSpec({
        // --- Happy path / dedup-by-content-id ---------------------------------------------

        test("add returns true for a new vector, false for the exact same vector added again") {
            val observer = Secp256k1KeyPair.generate()
            val peer = testPeerId(1)
            val v = vector(observer, peer)
            val index = MadliVectorIndex()

            index.add(v) shouldBe true
            index.add(v) shouldBe false
            index.vectorsForObservedPeer(peer) shouldBe listOf(v)
        }

        test("add rejects a signature-tampered vector and never throws") {
            val observer = Secp256k1KeyPair.generate()
            val peer = testPeerId(1)
            val v = vector(observer, peer)
            val bytes = MadliDailyVectorCodec.encode(v)
            bytes[bytes.size - 1] = (bytes[bytes.size - 1] + 1).toByte() // tamper the signature
            val tampered = MadliDailyVectorCodec.decode(bytes)
            val index = MadliVectorIndex()

            index.add(tampered) shouldBe false
            index.allObservedPeers() shouldBe emptySet()
        }

        test("vectors about different observed peers by different observers are both tracked independently") {
            val observerA = Secp256k1KeyPair.generate()
            val observerB = Secp256k1KeyPair.generate()
            val peerA = testPeerId(1)
            val peerB = testPeerId(2)
            val vA = vector(observerA, peerA)
            val vB = vector(observerB, peerB)
            val index = MadliVectorIndex()

            index.add(vA) shouldBe true
            index.add(vB) shouldBe true
            index.vectorsForObservedPeer(peerA) shouldBe listOf(vA)
            index.vectorsForObservedPeer(peerB) shouldBe listOf(vB)
            index.allObservedPeers() shouldBe setOf(peerA, peerB)
        }

        test(
            "multiple observers' vectors about the SAME observed peer are ALL tracked - never resolved to one winner",
        ) {
            val peer = testPeerId(1)
            val v1 = vector(Secp256k1KeyPair.generate(), peer, epochDay = 1L)
            val v2 = vector(Secp256k1KeyPair.generate(), peer, epochDay = 2L)
            val v3 = vector(Secp256k1KeyPair.generate(), peer, epochDay = 3L)
            val index = MadliVectorIndex()

            index.add(v1) shouldBe true
            index.add(v2) shouldBe true
            index.add(v3) shouldBe true

            index.vectorsForObservedPeer(peer) shouldBe listOf(v1, v2, v3)
        }

        test("vectorsForObservedPeer for an unknown peer returns an empty list") {
            val index = MadliVectorIndex()

            index.vectorsForObservedPeer(testPeerId(1)) shouldBe emptyList()
        }

        // --- canAccept: cheap, non-mutating admission pre-check -----------------------------

        test("canAccept returns true for a not-yet-tracked vector, under cap") {
            val v = vector(Secp256k1KeyPair.generate(), testPeerId(1))
            val index = MadliVectorIndex()

            index.canAccept(v) shouldBe true
        }

        test("canAccept returns false for a vector already tracked by content id") {
            val v = vector(Secp256k1KeyPair.generate(), testPeerId(1))
            val index = MadliVectorIndex()
            index.add(v) shouldBe true

            index.canAccept(v) shouldBe false
        }

        test("canAccept returns true even when the index is at capacity - a full index evicts, it never rejects") {
            val index = MadliVectorIndex(maxTracked = 2, maxPersisted = 10, maxDaysPerObserverPeer = 128)
            index.add(vector(Secp256k1KeyPair.generate(), testPeerId(1))) shouldBe true
            index.add(vector(Secp256k1KeyPair.generate(), testPeerId(2))) shouldBe true

            val newVector = vector(Secp256k1KeyPair.generate(), testPeerId(3))

            index.canAccept(newVector) shouldBe true
        }

        // --- tryReservePersistence: separate, non-evicting cap -------------------------------

        test("tryReservePersistence succeeds for a new content id under the persistence cap") {
            val v = vector(Secp256k1KeyPair.generate(), testPeerId(1))
            val index = MadliVectorIndex(maxTracked = 10, maxPersisted = 2, maxDaysPerObserverPeer = 128)

            index.tryReservePersistence(v) shouldBe true
        }

        test("tryReservePersistence fails once the persistence cap is reached, and stays failing - it does not evict") {
            val index = MadliVectorIndex(maxTracked = 10, maxPersisted = 2, maxDaysPerObserverPeer = 128)

            val v0 = vector(Secp256k1KeyPair.generate(), testPeerId(1))
            val v1 = vector(Secp256k1KeyPair.generate(), testPeerId(2))
            val v2 = vector(Secp256k1KeyPair.generate(), testPeerId(3))

            index.tryReservePersistence(v0) shouldBe true
            index.tryReservePersistence(v1) shouldBe true
            index.tryReservePersistence(v2) shouldBe false

            val v3 = vector(Secp256k1KeyPair.generate(), testPeerId(4))
            index.tryReservePersistence(v3) shouldBe false
        }

        test(
            "tryReservePersistence is idempotent - calling it again for an already-reserved content id " +
                "succeeds without consuming a second slot",
        ) {
            val v0 = vector(Secp256k1KeyPair.generate(), testPeerId(1))
            val index = MadliVectorIndex(maxTracked = 10, maxPersisted = 1, maxDaysPerObserverPeer = 128)

            index.tryReservePersistence(v0) shouldBe true
            repeat(5) { index.tryReservePersistence(v0) shouldBe true }

            val v1 = vector(Secp256k1KeyPair.generate(), testPeerId(2))
            index.tryReservePersistence(v1) shouldBe false
        }

        test(
            "tryReservePersistence and the in-memory tracking cap are independent - " +
                "a low persistence cap does not stop the index from tracking more vectors",
        ) {
            val index = MadliVectorIndex(maxTracked = 10, maxPersisted = 1, maxDaysPerObserverPeer = 128)

            val v0 = vector(Secp256k1KeyPair.generate(), testPeerId(1))
            val v1 = vector(Secp256k1KeyPair.generate(), testPeerId(2))
            val v2 = vector(Secp256k1KeyPair.generate(), testPeerId(3))

            index.tryReservePersistence(v0) shouldBe true
            index.tryReservePersistence(v1) shouldBe false
            index.tryReservePersistence(v2) shouldBe false

            index.add(v0) shouldBe true
            index.add(v1) shouldBe true
            index.add(v2) shouldBe true
            index.allObservedPeers().size shouldBe 3
        }

        // --- Invariant A: one tracked vector per (observer, observedPeer, epochDay) ----------

        test(
            "a second vector from the SAME observer for the SAME peer on the SAME day REPLACES the first, " +
                "rather than adding a second entry alongside it",
        ) {
            val observer = Secp256k1KeyPair.generate()
            val peer = testPeerId(1)
            val first = vector(observer, peer, epochDay = 5L, reachabilityMicros = 100_000)
            val second = vector(observer, peer, epochDay = 5L, reachabilityMicros = 900_000)
            val index = MadliVectorIndex()

            index.add(first) shouldBe true
            index.add(second) shouldBe true

            index.vectorsForObservedPeer(peer) shouldBe listOf(second)
        }

        test("invariant-A replacement removes the old vector from ALL secondary indices, not just one") {
            val observer = Secp256k1KeyPair.generate()
            val peer = testPeerId(1)
            val first = vector(observer, peer, epochDay = 5L, reachabilityMicros = 100_000)
            val second = vector(observer, peer, epochDay = 5L, reachabilityMicros = 900_000)
            val index = MadliVectorIndex()

            index.add(first) shouldBe true
            index.add(second) shouldBe true

            // vectorsByObservedPeer
            index.vectorsForObservedPeer(peer) shouldBe listOf(second)
            // vectorsByContentId (via canAccept dedup)
            index.canAccept(first) shouldBe true // first is gone entirely - a resubmit would be accepted again
            index.canAccept(second) shouldBe false
        }

        test("replacing a (observer, peer) day-tuple does not disturb that observer's vectors for OTHER days") {
            val observer = Secp256k1KeyPair.generate()
            val peer = testPeerId(1)
            val dayA1 = vector(observer, peer, epochDay = 5L, reachabilityMicros = 100_000)
            val dayA2 = vector(observer, peer, epochDay = 5L, reachabilityMicros = 900_000)
            val dayB = vector(observer, peer, epochDay = 6L, reachabilityMicros = 300_000)
            val index = MadliVectorIndex()

            index.add(dayA1) shouldBe true
            index.add(dayB) shouldBe true
            index.add(dayA2) shouldBe true

            index.vectorsForObservedPeer(peer) shouldBe listOf(dayB, dayA2)
        }

        test("replacing one observer's day-tuple does not disturb OTHER observers' vectors for the same peer/day") {
            val observerA = Secp256k1KeyPair.generate()
            val observerB = Secp256k1KeyPair.generate()
            val peer = testPeerId(1)
            val aFirst = vector(observerA, peer, epochDay = 5L, reachabilityMicros = 100_000)
            val bVector = vector(observerB, peer, epochDay = 5L, reachabilityMicros = 500_000)
            val aSecond = vector(observerA, peer, epochDay = 5L, reachabilityMicros = 900_000)
            val index = MadliVectorIndex()

            index.add(aFirst) shouldBe true
            index.add(bVector) shouldBe true
            index.add(aSecond) shouldBe true

            index.vectorsForObservedPeer(peer) shouldBe listOf(bVector, aSecond)
        }

        // --- Invariant B: anti-backdating cap on distinct days per (observer, observedPeer) --

        test(
            "publishing more than MAX_TRACKED_DAYS_PER_OBSERVER_PEER distinct-day vectors for one " +
                "(observer, observedPeer) pair keeps only the newest cap-many - smallest epochDay evicted",
        ) {
            val observer = Secp256k1KeyPair.generate()
            val peer = testPeerId(1)
            val cap = 5
            val index = MadliVectorIndex(maxTracked = 1_000, maxPersisted = 1_000, maxDaysPerObserverPeer = cap)

            val extra = 3
            val vectors = (1..(cap + extra)).map { day -> vector(observer, peer, epochDay = day.toLong()) }
            vectors.forEach { index.add(it) shouldBe true }

            val tracked = index.vectorsForObservedPeer(peer)
            tracked shouldHaveSize cap
            // The oldest `extra` days (1..extra) must have been evicted; the newest `cap` survive.
            tracked.map { it.epochDay }.toSet() shouldBe ((extra + 1)..(cap + extra)).map { it.toLong() }.toSet()
        }

        test("invariant-B eviction removes the evicted vector from ALL secondary indices") {
            val observer = Secp256k1KeyPair.generate()
            val peer = testPeerId(1)
            val cap = 3
            val index = MadliVectorIndex(maxTracked = 1_000, maxPersisted = 1_000, maxDaysPerObserverPeer = cap)

            val v1 = vector(observer, peer, epochDay = 1L)
            val v2 = vector(observer, peer, epochDay = 2L)
            val v3 = vector(observer, peer, epochDay = 3L)
            val v4 = vector(observer, peer, epochDay = 4L) // pushes v1 (smallest epochDay) out

            index.add(v1) shouldBe true
            index.add(v2) shouldBe true
            index.add(v3) shouldBe true
            index.add(v4) shouldBe true

            index.vectorsForObservedPeer(peer) shouldBe listOf(v2, v3, v4)
            // v1 must be gone from vectorsByContentId too - re-adding it is accepted as "new" again.
            index.canAccept(v1) shouldBe true
        }

        test("invariant B is scoped per (observer, observedPeer) pair - a different observer is unaffected") {
            val observerA = Secp256k1KeyPair.generate()
            val observerB = Secp256k1KeyPair.generate()
            val peer = testPeerId(1)
            val cap = 2
            val index = MadliVectorIndex(maxTracked = 1_000, maxPersisted = 1_000, maxDaysPerObserverPeer = cap)

            val aVectors = (1..3L).map { day -> vector(observerA, peer, epochDay = day) }
            val bVector = vector(observerB, peer, epochDay = 1L)

            aVectors.forEach { index.add(it) shouldBe true }
            index.add(bVector) shouldBe true

            // observerA: only the newest `cap` (days 2,3) survive; observerB's single vector is untouched.
            val tracked = index.vectorsForObservedPeer(peer)
            tracked.filter { it.observer == observerA.publicKey }.map { it.epochDay }.toSet() shouldBe setOf(2L, 3L)
            tracked.filter { it.observer == observerB.publicKey } shouldBe listOf(bVector)
        }

        test("invariant B is scoped per observed peer too - the same observer against a different peer is unaffected") {
            val observer = Secp256k1KeyPair.generate()
            val peerA = testPeerId(1)
            val peerB = testPeerId(2)
            val cap = 2
            val index = MadliVectorIndex(maxTracked = 1_000, maxPersisted = 1_000, maxDaysPerObserverPeer = cap)

            val aVectors = (1..3L).map { day -> vector(observer, peerA, epochDay = day) }
            val bVector = vector(observer, peerB, epochDay = 1L)

            aVectors.forEach { index.add(it) shouldBe true }
            index.add(bVector) shouldBe true

            index.vectorsForObservedPeer(peerA).map { it.epochDay }.toSet() shouldBe setOf(2L, 3L)
            index.vectorsForObservedPeer(peerB) shouldBe listOf(bVector)
        }

        // --- The highest-value test in this module: eviction must clean ALL secondary buckets --

        test(
            "MAX_TRACKED_VECTORS (global LRU) cap evicts the oldest tracked vector from ALL secondary " +
                "indices - vectorsByObservedPeer AND the per-(observer,peer) day bucket AND currentByObserverPeerDay",
        ) {
            val observerA = Secp256k1KeyPair.generate()
            val observerB = Secp256k1KeyPair.generate()
            val observerC = Secp256k1KeyPair.generate()
            val peers = (1..3).map { testPeerId(it.toByte()) }
            val index = MadliVectorIndex(maxTracked = 2, maxPersisted = 10, maxDaysPerObserverPeer = 128)

            // Three distinct (observer, peer) pairs - so a bug that only cleans SOME of the three
            // secondary indices is unambiguously observable.
            val v0 = vector(observerA, peers[0], epochDay = 1L)
            val v1 = vector(observerB, peers[1], epochDay = 1L)
            val v2 = vector(observerC, peers[2], epochDay = 1L)

            index.add(v0) shouldBe true
            index.add(v1) shouldBe true
            index.add(v2) shouldBe true // evicts v0 (oldest, access-order LinkedHashMap)

            index.allObservedPeers().size shouldBe 2

            // vectorsByObservedPeer must have forgotten v0 entirely.
            index.vectorsForObservedPeer(peers[0]) shouldBe emptyList()
            // vectorsByContentId must have forgotten v0 too - a resubmit is accepted as new again.
            index.canAccept(v0) shouldBe true

            // The two surviving vectors remain correct in the secondary index.
            index.vectorsForObservedPeer(peers[1]) shouldBe listOf(v1)
            index.vectorsForObservedPeer(peers[2]) shouldBe listOf(v2)
        }

        test(
            "eviction cleans the per-(observer,peer) day bucket correctly even when the same observer/peer " +
                "pair has multiple tracked days and only one is evicted",
        ) {
            val observer = Secp256k1KeyPair.generate()
            val otherObserver = Secp256k1KeyPair.generate()
            val peer = testPeerId(1)
            val otherPeer = testPeerId(2)
            val index = MadliVectorIndex(maxTracked = 2, maxPersisted = 10, maxDaysPerObserverPeer = 128)

            val v0 = vector(observer, peer, epochDay = 1L)
            val v1 = vector(observer, peer, epochDay = 2L)
            val v2 = vector(otherObserver, otherPeer, epochDay = 1L)

            index.add(v0) shouldBe true
            index.add(v1) shouldBe true
            index.add(v2) shouldBe true // evicts v0 - v1 (same observer/peer, different day) must remain intact

            index.vectorsForObservedPeer(peer) shouldBe listOf(v1)
            index.vectorsForObservedPeer(otherPeer) shouldBe listOf(v2)
        }

        test("a replayed core-only vector never displaces the merged vector carrying a relay block") {
            val observer = Secp256k1KeyPair.generate()
            val peer = testPeerId(1)
            val core = vector(observer, peer)
            val merged =
                MadliDailyVector.create(
                    observer,
                    peer,
                    100L,
                    testMetrics(),
                    MadliRelayMetrics(relayReliabilityMicros = 100_000, relayAttemptCount = 9),
                )
            val index = MadliVectorIndex()

            index.add(core) shouldBe true
            index.add(merged) shouldBe true // merge replaces the core-only vector
            index.canAccept(core) shouldBe false // replay is refused up front
            index.add(core) shouldBe false // and by add itself
            index.vectorFor(observer.publicKey, peer, 100L) shouldBe merged
            index.vectorsForObservedPeer(peer) shouldBe listOf(merged)
            // repeated replay cannot make it flip back
            repeat(3) { index.add(core) shouldBe false }
            index.vectorFor(observer.publicKey, peer, 100L) shouldBe merged
        }

        test("a relay-bearing vector replaces a core-only one and another relay vector") {
            val observer = Secp256k1KeyPair.generate()
            val peer = testPeerId(2)
            val relay1 = MadliRelayMetrics(relayReliabilityMicros = 100_000, relayAttemptCount = 5)
            val relay2 = MadliRelayMetrics(relayReliabilityMicros = 900_000, relayAttemptCount = 7)
            val v1 = MadliDailyVector.create(observer, peer, 100L, testMetrics(), relay1)
            val v2 = MadliDailyVector.create(observer, peer, 100L, testMetrics(), relay2)
            val index = MadliVectorIndex()

            index.add(vector(observer, peer)) shouldBe true
            index.add(v1) shouldBe true
            index.add(v2) shouldBe true
            index.vectorFor(observer.publicKey, peer, 100L) shouldBe v2
        }
    })
