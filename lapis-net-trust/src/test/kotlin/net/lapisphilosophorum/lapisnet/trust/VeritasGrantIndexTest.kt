package net.lapisphilosophorum.lapisnet.trust

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair

class VeritasGrantIndexTest :
    FunSpec({
        test("version advances only on a successful add") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val grant = VeritasGrant.create(truster, target, trustMicros = 500_000)
            val index = VeritasGrantIndex()
            val v0 = index.version()

            index.add(grant) shouldBe true
            val v1 = index.version()
            (v1 > v0) shouldBe true
            index.add(grant) shouldBe false
            index.version() shouldBe v1
        }

        test("add returns true for a new grant, false for the same grant added again") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val grant = VeritasGrant.create(truster, target, trustMicros = 500_000)
            val index = VeritasGrantIndex()

            index.add(grant) shouldBe true
            index.add(grant) shouldBe false
            index.grantsFor(truster.publicKey, target) shouldBe listOf(grant)
        }

        test("add rejects a signature-tampered grant and never throws") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val grant = VeritasGrant.create(truster, target, trustMicros = 500_000)
            val bytes = VeritasGrantCodec.encode(grant)
            bytes[bytes.size - 1] = (bytes[bytes.size - 1] + 1).toByte() // tamper the signature
            val tampered = VeritasGrantCodec.decode(bytes)
            val index = VeritasGrantIndex()

            index.add(tampered) shouldBe false
            index.allPairs() shouldBe emptySet()
        }

        test("two grants for different (truster, target) pairs are both tracked independently") {
            val truster = Secp256k1KeyPair.generate()
            val targetA = Secp256k1KeyPair.generate().publicKey
            val targetB = Secp256k1KeyPair.generate().publicKey
            val grantA = VeritasGrant.create(truster, targetA, trustMicros = 500_000)
            val grantB = VeritasGrant.create(truster, targetB, trustMicros = 700_000)
            val index = VeritasGrantIndex()

            index.add(grantA) shouldBe true
            index.add(grantB) shouldBe true
            index.grantsFor(truster.publicKey, targetA) shouldBe listOf(grantA)
            index.grantsFor(truster.publicKey, targetB) shouldBe listOf(grantB)
            index.allPairs() shouldBe setOf(truster.publicKey to targetA, truster.publicKey to targetB)
        }

        test("multiple grants in the same version chain are all tracked for that pair") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val g1 = VeritasGrant.create(truster, target, trustMicros = 200_000)
            val g2 = VeritasGrant.create(truster, target, trustMicros = 600_000, previous = g1)

            val index = VeritasGrantIndex()
            index.add(g1) shouldBe true
            index.add(g2) shouldBe true
            index.grantsFor(truster.publicKey, target) shouldBe listOf(g1, g2)
        }

        test("grantsFor an unknown pair returns an empty list") {
            val truster = Secp256k1KeyPair.generate().publicKey
            val target = Secp256k1KeyPair.generate().publicKey
            val index = VeritasGrantIndex()

            index.grantsFor(truster, target) shouldBe emptyList()
        }

        // --- Eviction once MAX_TRACKED_GRANTS is exceeded (round-2 M2 fix) ---------------------
        // Note: grantsByContentId is an access-order LinkedHashMap, but nothing in this class ever
        // performs a read that counts as an "access" for its promotion bookkeeping (containsKey
        // does not count; only get()/put() do, and this class never calls get()) - so under actual
        // usage, eviction order is indistinguishable from plain insertion order/FIFO. These tests
        // are named and worded to reflect that "oldest tracked entry is evicted" behavior, not
        // "least-recently-used" (which would imply promotion-on-read, which this class does not
        // implement - see VeritasGrantIndex's and grantsByContentId's doc comments).

        test("MAX_TRACKED_GRANTS cap no longer rejects - it evicts the oldest tracked entry") {
            val truster = Secp256k1KeyPair.generate()
            val targets = (1..3).map { Secp256k1KeyPair.generate().publicKey }
            val index = VeritasGrantIndex(maxTracked = 2)

            val g0 = VeritasGrant.create(truster, targets[0], trustMicros = 100_000)
            val g1 = VeritasGrant.create(truster, targets[1], trustMicros = 200_000)
            val g2 = VeritasGrant.create(truster, targets[2], trustMicros = 300_000)

            index.add(g0) shouldBe true
            index.add(g1) shouldBe true
            // A third distinct grant now succeeds - something else is evicted to make room,
            // rather than this add() being declined.
            index.add(g2) shouldBe true
            index.allPairs().size shouldBe 2

            // g0 is the oldest (inserted first, never re-accessed) - it must be the one evicted,
            // both from grantsFor() and from allPairs() (it was targets[0]'s only grant).
            index.grantsFor(truster.publicKey, targets[0]) shouldBe emptyList()
            index.allPairs() shouldBe setOf(truster.publicKey to targets[1], truster.publicKey to targets[2])

            // g1 and g2 (the two most-recently-inserted) both survive.
            index.grantsFor(truster.publicKey, targets[1]) shouldBe listOf(g1)
            index.grantsFor(truster.publicKey, targets[2]) shouldBe listOf(g2)
        }

        test("a grant added right before the eviction point is not evicted - only the oldest entry is") {
            val truster = Secp256k1KeyPair.generate()
            val targets = (1..4).map { Secp256k1KeyPair.generate().publicKey }
            val index = VeritasGrantIndex(maxTracked = 3)

            val g0 = VeritasGrant.create(truster, targets[0], trustMicros = 100_000)
            val g1 = VeritasGrant.create(truster, targets[1], trustMicros = 200_000)
            val g2 = VeritasGrant.create(truster, targets[2], trustMicros = 300_000)
            val g3 = VeritasGrant.create(truster, targets[3], trustMicros = 400_000)

            index.add(g0) shouldBe true
            index.add(g1) shouldBe true
            index.add(g2) shouldBe true
            // Index is now full (g0, g1, g2). Adding g3 must evict g0 (the oldest entry, since
            // nothing in this class ever performs a read that would promote an entry - see the
            // section comment above) - g1 and g2, despite being closer in insertion order to the
            // eviction point than g0, must NOT be evicted.
            index.add(g3) shouldBe true

            index.grantsFor(truster.publicKey, targets[0]) shouldBe emptyList()
            index.grantsFor(truster.publicKey, targets[1]) shouldBe listOf(g1)
            index.grantsFor(truster.publicKey, targets[2]) shouldBe listOf(g2)
            index.grantsFor(truster.publicKey, targets[3]) shouldBe listOf(g3)
        }

        // --- canAccept: cheap, non-mutating admission pre-check (round-2 C2 fix) ----------------

        test("canAccept returns true for a not-yet-tracked grant, under cap") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val grant = VeritasGrant.create(truster, target, trustMicros = 500_000)
            val index = VeritasGrantIndex()

            index.canAccept(grant) shouldBe true
        }

        test("canAccept returns false for a grant already tracked by content id") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val grant = VeritasGrant.create(truster, target, trustMicros = 500_000)
            val index = VeritasGrantIndex()
            index.add(grant) shouldBe true

            index.canAccept(grant) shouldBe false
        }

        test("canAccept returns true even when the index is at capacity - a full index evicts, it never rejects") {
            val truster = Secp256k1KeyPair.generate()
            val targets = (1..2).map { Secp256k1KeyPair.generate().publicKey }
            val index = VeritasGrantIndex(maxTracked = 2)
            index.add(VeritasGrant.create(truster, targets[0], trustMicros = 100_000)) shouldBe true
            index.add(VeritasGrant.create(truster, targets[1], trustMicros = 200_000)) shouldBe true

            val newTarget = Secp256k1KeyPair.generate().publicKey
            val newGrant = VeritasGrant.create(truster, newTarget, trustMicros = 300_000)

            index.canAccept(newGrant) shouldBe true
        }

        test("calling canAccept repeatedly never itself mutates the index or fills the cap") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val grant = VeritasGrant.create(truster, target, trustMicros = 500_000)
            val index = VeritasGrantIndex(maxTracked = 2)

            repeat(10) { index.canAccept(grant) shouldBe true }

            index.allPairs() shouldBe emptySet()
            index.grantsFor(truster.publicKey, target) shouldBe emptyList()
            // The index is still empty, so a real add() afterward succeeds normally.
            index.add(grant) shouldBe true
        }

        // --- tryReservePersistence: separate, non-evicting cap on durable persistence (round-3 fix) ---

        test("tryReservePersistence succeeds for a new content id under the persistence cap") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val grant = VeritasGrant.create(truster, target, trustMicros = 500_000)
            val index = VeritasGrantIndex(maxTracked = 10, maxPersisted = 2)

            index.tryReservePersistence(grant) shouldBe true
        }

        test("tryReservePersistence fails once the persistence cap is reached, and stays failing - it does not evict") {
            val truster = Secp256k1KeyPair.generate()
            val targets = (1..3).map { Secp256k1KeyPair.generate().publicKey }
            val index = VeritasGrantIndex(maxTracked = 10, maxPersisted = 2)

            val g0 = VeritasGrant.create(truster, targets[0], trustMicros = 100_000)
            val g1 = VeritasGrant.create(truster, targets[1], trustMicros = 200_000)
            val g2 = VeritasGrant.create(truster, targets[2], trustMicros = 300_000)

            index.tryReservePersistence(g0) shouldBe true
            index.tryReservePersistence(g1) shouldBe true
            // Cap (2) reached - a third, distinct content id must be declined...
            index.tryReservePersistence(g2) shouldBe false

            // ...and unlike the evicting in-memory index, this does NOT free up room for g2 by
            // displacing g0/g1 - a fresh, different content id still fails afterward too.
            val g3 = VeritasGrant.create(truster, Secp256k1KeyPair.generate().publicKey, trustMicros = 400_000)
            index.tryReservePersistence(g3) shouldBe false
        }

        test(
            "tryReservePersistence is idempotent - calling it again for an already-reserved content id " +
                "succeeds without consuming a second slot",
        ) {
            val truster = Secp256k1KeyPair.generate()
            val targets = (1..2).map { Secp256k1KeyPair.generate().publicKey }
            val index = VeritasGrantIndex(maxTracked = 10, maxPersisted = 1)

            val g0 = VeritasGrant.create(truster, targets[0], trustMicros = 100_000)
            index.tryReservePersistence(g0) shouldBe true

            // Calling it again for the SAME grant keeps succeeding, even though the cap (1) has
            // technically been reached - it's the same content id, not a new one.
            repeat(5) { index.tryReservePersistence(g0) shouldBe true }

            // A genuinely different content id still correctly fails - the repeated calls above
            // did not silently free up (or consume extra) capacity.
            val g1 = VeritasGrant.create(truster, targets[1], trustMicros = 200_000)
            index.tryReservePersistence(g1) shouldBe false
        }

        test(
            "tryReservePersistence and the in-memory tracking cap are independent - " +
                "a low persistence cap does not stop the index from tracking more grants",
        ) {
            val truster = Secp256k1KeyPair.generate()
            val targets = (1..3).map { Secp256k1KeyPair.generate().publicKey }
            val index = VeritasGrantIndex(maxTracked = 10, maxPersisted = 1)

            val g0 = VeritasGrant.create(truster, targets[0], trustMicros = 100_000)
            val g1 = VeritasGrant.create(truster, targets[1], trustMicros = 200_000)
            val g2 = VeritasGrant.create(truster, targets[2], trustMicros = 300_000)

            index.tryReservePersistence(g0) shouldBe true
            index.tryReservePersistence(g1) shouldBe false
            index.tryReservePersistence(g2) shouldBe false

            // Persistence capping out has no bearing on the in-memory index - add() is a wholly
            // separate mechanism and all three are tracked regardless.
            index.add(g0) shouldBe true
            index.add(g1) shouldBe true
            index.add(g2) shouldBe true
            index.allPairs().size shouldBe 3
        }
    })
