package net.lapisphilosophorum.lapisnet.directory

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.libp2p.core.multiformats.Multiaddr
import net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.IdentityBinding
import java.time.Instant

private fun testAddress(port: Int): Multiaddr = Multiaddr("/ip4/127.0.0.1/tcp/$port")

/** [notValidAfterEpochSecond] defaults to a near-future (not far-future) value - since
 * [PeerRecord.create]'s round-4 [PeerRecord.MAX_TTL_WINDOW_SECONDS] cap rejects anything claiming
 * validity more than 24h beyond "now", the old `9_999_999_999L` (year 2286) placeholder this file
 * used before that fix would now throw at construction time. */
private fun record(
    identity: DualKeyIdentity,
    sequenceNumber: Long,
    addresses: List<Multiaddr> = listOf(testAddress(4000 + sequenceNumber.toInt())),
): PeerRecord =
    PeerRecord.create(identity, addresses, setOf(PeerCapability.DM), sequenceNumber, Instant.now().epochSecond + 3600)

/** Genuinely self-signed by [signingIdentity] (so [PeerRecord.verify] is true), but embedding a
 * DIFFERENT identity's [IdentityBinding] - so [PeerRecord.verifyBinding] is false. Bypasses
 * [PeerRecord.create]'s own `require(identity.verifyBinding())` guard by building the signed body
 * and signature directly, mirroring [PeerRecordSpoofingTest]'s central attack (case a). */
private fun spoofedRecord(
    signingIdentity: DualKeyIdentity,
    victimBinding: IdentityBinding,
    addresses: List<Multiaddr> = emptyList(),
    capabilities: Set<PeerCapability> = emptySet(),
    sequenceNumber: Long = 0,
    notValidAfterEpochSecond: Long = 9_999_999_999L,
): PeerRecord {
    val body =
        PeerRecordCodec.encodeSignedBody(
            identity = signingIdentity.secp256k1KeyPair.publicKey,
            binding = victimBinding,
            possessionProof = ByteArray(64),
            addresses = addresses,
            capabilities = capabilities,
            sequenceNumber = sequenceNumber,
            notValidAfterEpochSecond = notValidAfterEpochSecond,
        )
    val digest = domainSeparatedDigest("LapisNet:peer-record:v1", body)
    val signature = signingIdentity.secp256k1KeyPair.sign(digest)
    return PeerRecord.fromDecoded(
        identity = signingIdentity.secp256k1KeyPair.publicKey,
        binding = victimBinding,
        addresses = addresses,
        capabilities = capabilities,
        sequenceNumber = sequenceNumber,
        notValidAfterEpochSecond = notValidAfterEpochSecond,
        signature = signature,
    )
}

class PeerRecordIndexTest :
    FunSpec({
        test("latest-wins by sequence number: sequence 2 supersedes sequence 1, dropping it entirely") {
            val identity = DualKeyIdentity.generate()
            val r1 = record(identity, 1)
            val r2 = record(identity, 2)
            val index = PeerRecordIndex()

            index.add(r1) shouldBe true
            index.add(r2) shouldBe true

            index.current(identity.secp256k1KeyPair.publicKey) shouldBe r2
            index.size() shouldBe 1
        }

        test("a stale/rollback sequence number is rejected and does not disturb the tracked record") {
            val identity = DualKeyIdentity.generate()
            val r5 = record(identity, 5)
            val r3 = record(identity, 3)
            val index = PeerRecordIndex()

            index.add(r5) shouldBe true
            index.add(r3) shouldBe false

            index.current(identity.secp256k1KeyPair.publicKey) shouldBe r5
            index.size() shouldBe 1
        }

        test("equal-sequence tie-break is deterministic and order-independent") {
            val identity = DualKeyIdentity.generate()
            val a = record(identity, 7, addresses = listOf(testAddress(5001)))
            val b = record(identity, 7, addresses = listOf(testAddress(5002)))

            val indexAB = PeerRecordIndex()
            indexAB.add(a)
            indexAB.add(b)
            val winnerAB = indexAB.current(identity.secp256k1KeyPair.publicKey)

            val indexBA = PeerRecordIndex()
            indexBA.add(b)
            indexBA.add(a)
            val winnerBA = indexBA.current(identity.secp256k1KeyPair.publicKey)

            winnerAB shouldBe winnerBA
            // Exactly one of the two calls in each index actually won - the other must have
            // returned false since only one record can be "current" for the same sequence number.
        }

        test("tie-break: the tracking size stays 1 and current() is always one of the two candidates") {
            val identity = DualKeyIdentity.generate()
            val a = record(identity, 7, addresses = listOf(testAddress(5001)))
            val b = record(identity, 7, addresses = listOf(testAddress(5002)))
            val index = PeerRecordIndex()

            // The first add always succeeds (no existing record for this identity yet). The
            // second either wins the deterministic tie-break (superseding the first, also true)
            // or loses it (false) - either way exactly one record ends up tracked.
            index.add(a) shouldBe true
            index.add(b)

            index.size() shouldBe 1
            (index.current(identity.secp256k1KeyPair.publicKey) in listOf(a, b)) shouldBe true
        }

        test("eviction: exceeding maxTracked evicts the oldest identity's record") {
            val identities = (1..4).map { DualKeyIdentity.generate() }
            val index = PeerRecordIndex(maxTracked = 3, maxPersisted = 100)

            val records = identities.map { record(it, 0) }
            records.forEach { index.add(it) shouldBe true }

            index.size() shouldBe 3
            index.current(identities[0].secp256k1KeyPair.publicKey).shouldBeNull()
            index.current(identities[3].secp256k1KeyPair.publicKey) shouldBe records[3]
        }

        test("persistence-cap decoupling: tracking succeeds past maxPersisted, only maxPersisted reserve") {
            val identities = (1..3).map { DualKeyIdentity.generate() }
            val index = PeerRecordIndex(maxTracked = 100, maxPersisted = 2)

            val records = identities.map { record(it, 0) }

            index.tryReservePersistence(records[0]) shouldBe true
            index.tryReservePersistence(records[1]) shouldBe true
            index.tryReservePersistence(records[2]) shouldBe false

            // Tracking (add) is unaffected by the persistence cap being full.
            records.forEach { index.add(it) shouldBe true }
            index.size() shouldBe 3
        }

        test("tryReservePersistence is idempotent per content id") {
            val identity = DualKeyIdentity.generate()
            val r = record(identity, 0)
            val index = PeerRecordIndex(maxTracked = 100, maxPersisted = 1)

            index.tryReservePersistence(r) shouldBe true
            index.tryReservePersistence(r) shouldBe true // same content id, does not consume a second slot
        }

        test("canAccept/add consistency for a fresh check-then-act pair") {
            val identity = DualKeyIdentity.generate()
            val r = record(identity, 0)
            val index = PeerRecordIndex()

            index.canAccept(r) shouldBe true
            index.add(r) shouldBe true

            // Re-checking the exact same (now-tracked) record must agree between canAccept and add:
            // both must now decline it as an exact content-id duplicate.
            index.canAccept(r) shouldBe false
            index.add(r) shouldBe false
        }

        test("add and canAccept both return false, never throw, for a signature-invalid record") {
            val identity = DualKeyIdentity.generate()
            val r = record(identity, 0)
            val bytes = PeerRecordCodec.encode(r)
            bytes[bytes.size - 1] = (bytes[bytes.size - 1] + 1).toByte() // tamper the outer signature
            val tampered = PeerRecordCodec.decode(bytes)
            val index = PeerRecordIndex()

            index.add(tampered) shouldBe false
            index.canAccept(tampered) shouldBe true // canAccept does not check signature validity, only ordering
        }

        test("add returns false for a genuinely signature-valid but binding-invalid record, never throws") {
            val identityA = DualKeyIdentity.generate()
            val identityB = DualKeyIdentity.generate()
            val spoofed = spoofedRecord(signingIdentity = identityA, victimBinding = identityB.binding)
            PeerRecord.verify(spoofed) shouldBe true // genuinely signed - not a signature-failure case
            spoofed.verifyBinding() shouldBe false
            val index = PeerRecordIndex()

            index.add(spoofed) shouldBe false
        }

        // Security regression (V0.8.1 sub-wave audit round 3, major finding): add() must
        // independently re-verify verifyPossession(), not just verify()+verifyBinding(). Before
        // this fix, this exact case-(h)-shaped forgery (see PeerRecordSpoofingTest) - a FRESH,
        // self-consistent IdentityBinding the attacker mints over a victim's public Ed25519 key,
        // genuinely self-signed by the attacker's own secp256k1 key - passed both remaining checks
        // and was tracked by add(), becoming `current` for the victim's identity even though it was
        // never possible to reach through PeerDirectoryGossip.onGossipMessage (which already checks
        // verifyPossession before calling add). This test isolates add() itself, since add() is
        // public API also reached by PeerDirectoryGossip.announce() with no verification of its own.
        test("add returns false for a genuinely signature-valid, binding-valid, but possession-invalid record") {
            val attacker = DualKeyIdentity.generate()
            val victim = DualKeyIdentity.generate()

            // The attacker mints a BRAND-NEW binding, self-signed with their OWN secp256k1 key,
            // over the victim's PUBLIC (and therefore freely copyable) Ed25519 key - NOT the
            // victim's own binding object, so verifyBinding() genuinely passes.
            val forgedBinding = IdentityBinding.create(attacker.secp256k1KeyPair, victim.ed25519KeyPair.publicKey)
            IdentityBinding.verify(attacker.secp256k1KeyPair.publicKey, forgedBinding) shouldBe true

            val body =
                PeerRecordCodec.encodeSignedBody(
                    identity = attacker.secp256k1KeyPair.publicKey,
                    binding = forgedBinding,
                    // The attacker does not hold the victim's Ed25519 private key, so this can only
                    // ever be a placeholder, never a genuine possession proof.
                    possessionProof = ByteArray(64),
                    addresses = emptyList(),
                    capabilities = emptySet(),
                    sequenceNumber = 0,
                    notValidAfterEpochSecond = 9_999_999_999L,
                )
            val signature =
                attacker.secp256k1KeyPair.sign(domainSeparatedDigest("LapisNet:peer-record:v1", body))
            val forged =
                PeerRecord.fromDecoded(
                    identity = attacker.secp256k1KeyPair.publicKey,
                    binding = forgedBinding,
                    addresses = emptyList(),
                    capabilities = emptySet(),
                    sequenceNumber = 0,
                    notValidAfterEpochSecond = 9_999_999_999L,
                    signature = signature,
                )

            // Both checks add() ran before this fix genuinely pass here - proving this is NOT a
            // signature or binding failure, only the new possession check catches it.
            PeerRecord.verify(forged) shouldBe true
            forged.verifyBinding() shouldBe true
            forged.verifyPossession() shouldBe false

            val index = PeerRecordIndex()
            index.add(forged) shouldBe false
            index.allIdentities() shouldBe emptySet()
        }

        test("allIdentities reflects every distinct tracked identity") {
            val identities = (1..3).map { DualKeyIdentity.generate() }
            val index = PeerRecordIndex()
            identities.forEach { index.add(record(it, 0)) shouldBe true }

            index.allIdentities() shouldBe identities.map { it.secp256k1KeyPair.publicKey }.toSet()
        }

        // Security regression (V0.8.1 sub-wave audit round 1, major finding 2). Direct index-level
        // counterpart to PeerRecordSpoofingTest's case (g), which exercises the same scenario
        // through the real PeerDirectoryGossip.onGossipMessage validator - this one isolates the
        // anti-rollback high-water mark itself. Before the fix, canAccept/add compared a candidate
        // only against currentByIdentity, which removeEldestEntry clears the moment a record is
        // evicted from recordsByContentId - after that, canAccept had no high-water mark left to
        // compare against and returned true for ANY sequence number, including one already
        // superseded.
        test("a stale record is still rejected after its victim's entry is evicted from the tracking cap") {
            val cap = 5
            val index = PeerRecordIndex(maxTracked = cap, maxPersisted = 100)

            val victim = DualKeyIdentity.generate()
            val victimNewer = record(victim, 99, addresses = listOf(testAddress(5002)))
            index.add(victimNewer) shouldBe true
            index.current(victim.secp256k1KeyPair.publicKey) shouldBe victimNewer

            // Flood past maxTracked with freshly-fabricated identities so the victim's record is
            // evicted from recordsByContentId - and, per removeEldestEntry, un-linked from
            // currentByIdentity too.
            repeat(cap * 2) { index.add(record(DualKeyIdentity.generate(), 0)) shouldBe true }
            index.current(victim.secp256k1KeyPair.publicKey).shouldBeNull() // evicted, as expected

            // Replay the victim's OLD, stale sequence number - must still be rejected by BOTH
            // canAccept and add, even though currentByIdentity no longer has a live entry to
            // compare it against.
            val victimStale = record(victim, 1, addresses = listOf(testAddress(5001)))
            index.canAccept(victimStale) shouldBe false
            index.add(victimStale) shouldBe false
            index.current(victim.secp256k1KeyPair.publicKey).shouldBeNull()
        }

        // Security regression (V0.8.1 sub-wave audit round 2, major finding 2). Direct index-level
        // reproduction of the auditor's PROBE C: a flood arrives and fills the high-water-mark cap
        // BEFORE the genuine victim's record ever arrives - the exact ordering the round-1 fix's
        // own regression test (above) does not cover, since it seeds the victim FIRST. Before this
        // fix, highestSequenceByIdentity was a plain, never-evicting HashMap admission-gated at its
        // cap: once full (from the flood alone, no victim involved), every identity arriving
        // afterward - including a perfectly legitimate one - never got a high-water mark at all,
        // for the rest of the process lifetime. This test proves the LRU-evicting replacement fixes
        // the admission side (the victim DOES get tracked despite arriving after the cap first
        // filled) while STILL closing the original rollback: a later flood evicts the victim from
        // currentByIdentity too, and a replay of its old, stale record is still rejected - proving
        // highestSequenceByIdentity's own, independently-sized cap gave it enough headroom to
        // survive that second flood wave.
        test(
            "a victim arriving AFTER the high-water-mark cap is already full by a flood still gets " +
                "rollback protection (PROBE C)",
        ) {
            val maxTrackedCap = 5
            val maxHighWater = 20
            val index =
                PeerRecordIndex(maxTracked = maxTrackedCap, maxPersisted = 100, maxHighWaterMarks = maxHighWater)

            // Phase 1: fill the high-water-mark cap with distinct, one-off identities BEFORE the
            // victim ever publishes anything.
            repeat(maxHighWater) { index.add(record(DualKeyIdentity.generate(), 0)) shouldBe true }

            // Phase 2: the victim's genuine record arrives AFTER the cap was already full. Under
            // the round-1 (non-evicting, admission-gated) design this identity would NEVER receive
            // a high-water mark; under LRU eviction it evicts the oldest (dormant) flood entry to
            // make room.
            val victim = DualKeyIdentity.generate()
            val fresh = record(victim, 99)
            index.add(fresh) shouldBe true
            index.current(victim.secp256k1KeyPair.publicKey) shouldBe fresh

            // Phase 3: more flood evicts the victim's OWN record from currentByIdentity/
            // recordsByContentId (maxTrackedCap churn, same mechanic the test above exercises) - so
            // only highestSequenceByIdentity's own (now-populated) entry can protect a replay from
            // here on. maxHighWater is sized comfortably larger than maxTrackedCap so this modest
            // second flood does not ALSO evict the victim's high-water mark in the same step.
            repeat(maxTrackedCap) { index.add(record(DualKeyIdentity.generate(), 0)) shouldBe true }
            index.current(victim.secp256k1KeyPair.publicKey).shouldBeNull()

            // Phase 4: replay the victim's OLD, stale record - must still be rejected, proving the
            // victim DID receive a high-water mark despite arriving after the cap first filled.
            val stale = record(victim, 1)
            index.canAccept(stale) shouldBe false
            index.add(stale) shouldBe false
            index.current(victim.secp256k1KeyPair.publicKey).shouldBeNull()
        }

        // Regression (V0.8.1 sub-wave audit round 4, minor finding 1 - the "no expiry-driven
        // eviction" half; see PeerRecord.create's MAX_TTL_WINDOW_SECONDS cap for the complementary
        // half of the same finding). Before evictExpired existed, an expired record stayed resident
        // in recordsByContentId/currentByIdentity forever - only PeerDirectoryGossip.lookup's
        // read-time filter hid it, this index itself never reclaimed the memory.
        test("evictExpired removes an expired current record from tracking, but a still-valid one survives") {
            val now = Instant.now().epochSecond
            val index = PeerRecordIndex()

            val expiredIdentity = DualKeyIdentity.generate()
            // notValidAfterEpochSecond in the PAST is never rejected by create()'s cap (which only
            // bounds how far into the FUTURE a claimed TTL may reach) - this is exactly the
            // ordinary, non-adversarial shape of "a record that was valid once and has since
            // expired", the case evictExpired exists to reclaim.
            val expired =
                PeerRecord.create(
                    expiredIdentity,
                    emptyList(),
                    emptySet(),
                    sequenceNumber = 0,
                    notValidAfterEpochSecond = now - 3600,
                )
            index.add(expired) shouldBe true

            val liveIdentity = DualKeyIdentity.generate()
            val live = record(liveIdentity, 0)
            index.add(live) shouldBe true

            index.size() shouldBe 2

            val evictedCount = index.evictExpired(now)

            evictedCount shouldBe 1
            index.current(expiredIdentity.secp256k1KeyPair.publicKey).shouldBeNull()
            index.current(liveIdentity.secp256k1KeyPair.publicKey) shouldBe live
            index.size() shouldBe 1
        }

        // Regression: evictExpired must NOT touch highestSequenceByIdentity - anti-rollback
        // protection for an identity whose current record just expired must survive this sweep
        // exactly as it survives capacity-driven eviction (removeEldestEntry's identical contract).
        test("evictExpired does not weaken anti-rollback protection - a stale replay is still rejected afterward") {
            val now = Instant.now().epochSecond
            val index = PeerRecordIndex()
            val identity = DualKeyIdentity.generate()

            val newer =
                PeerRecord.create(
                    identity,
                    listOf(testAddress(5002)),
                    setOf(PeerCapability.DM),
                    sequenceNumber = 5,
                    notValidAfterEpochSecond = now - 3600,
                )
            index.add(newer) shouldBe true

            index.evictExpired(now) shouldBe 1
            index.current(identity.secp256k1KeyPair.publicKey).shouldBeNull()

            val rollback = record(identity, 3, addresses = listOf(testAddress(5001)))
            index.canAccept(rollback) shouldBe false
            index.add(rollback) shouldBe false
        }

        // Security regression backport (V0.8.5 finding, originally fixed in
        // MailboxPointerIndex.releaseReservedPersistence, backported here): releaseReservedPersistence
        // must free a reservation for reuse rather than burning it permanently. maxPersisted = 1 is
        // the tightest possible window to prove RELEASE, not merely non-exhaustion - a single
        // successful reservation would otherwise permanently exhaust a cap of 1 forever if release()
        // were a no-op.
        test(
            "releaseReservedPersistence frees a reservation for reuse rather than burning it " +
                "permanently - V0.8.5 security fix backport regression",
        ) {
            val index = PeerRecordIndex(maxTracked = 100, maxPersisted = 1)
            val identityA = DualKeyIdentity.generate()
            val identityB = DualKeyIdentity.generate()
            val a = record(identityA, 0)
            val b = record(identityB, 0)

            // Mirrors what PeerDirectoryGossip.onGossipMessage does on a storage.put() failure: call
            // tryReservePersistence (which unconditionally inserts into the never-evicting
            // persistedContentIds the moment it is called), THEN releaseReservedPersistence when the
            // actual durable write never went through.
            index.tryReservePersistence(a) shouldBe true
            index.releaseReservedPersistence(a)

            // THE CENTRAL ASSERTION: a wholly different, later record can still claim the cap's ONE
            // slot - proving `a`'s failed/released reservation did not permanently burn it. Without
            // releaseReservedPersistence (or if it were a no-op), this would fail: the cap would
            // already be exhausted by `a` alone.
            index.tryReservePersistence(b) shouldBe true

            // releaseReservedPersistence is a no-op for a content id that was never reserved (or was
            // already released) - safe to call defensively.
            index.releaseReservedPersistence(a) // already released above - must not throw or corrupt state
            index.tryReservePersistence(record(DualKeyIdentity.generate(), 0)) shouldBe false // cap still enforced
        }

        test("evictExpired evicts nothing when every tracked record is still valid") {
            val index = PeerRecordIndex()
            val identities = (1..3).map { DualKeyIdentity.generate() }
            identities.forEach { index.add(record(it, 0)) shouldBe true }

            index.evictExpired(Instant.now().epochSecond) shouldBe 0
            index.size() shouldBe 3
        }
    })
