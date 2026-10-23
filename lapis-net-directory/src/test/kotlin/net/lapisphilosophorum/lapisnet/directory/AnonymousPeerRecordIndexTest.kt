package net.lapisphilosophorum.lapisnet.directory

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import java.time.Instant

class AnonymousPeerRecordIndexTest :
    FunSpec({
        val now = Instant.now().epochSecond

        fun index(
            capacity: Int = 16,
            marks: Int = 64,
        ) = AnonymousPeerRecordIndex(PeerRecordIndex(), capacity, marks)

        test("only strictly rising sequence numbers are accepted; replays and older records are refused") {
            val p = AnonymousPublisher()
            val idx = index()
            idx.add(p.record(10), now) shouldBe AnonymousIngestOutcome.ACCEPTED
            idx.add(p.record(9), now) shouldBe AnonymousIngestOutcome.REPLAYED_OR_STALE
            idx.add(p.record(11), now) shouldBe AnonymousIngestOutcome.ACCEPTED
            idx.current(p.key, now)!!.sequenceNumber shouldBe 11
        }

        test("an exact duplicate is reported as such and equivocation (same sequence, other content) is ignored") {
            val p = AnonymousPublisher()
            val idx = index()
            val r = p.record(10)
            idx.add(r, now) shouldBe AnonymousIngestOutcome.ACCEPTED
            idx.add(r, now) shouldBe AnonymousIngestOutcome.DUPLICATE
            val other = p.record(10, capabilities = setOf(AnonymousCapability.MAIL))
            idx.add(other, now) shouldBe AnonymousIngestOutcome.REPLAYED_OR_STALE
            idx.current(p.key, now) shouldBe r
        }

        test("invalid and expired records are refused without being stored") {
            val p = AnonymousPublisher()
            val idx = index()
            idx.add(p.record(1, expiresInSeconds = -5), now) shouldBe AnonymousIngestOutcome.EXPIRED
            val bad = resign(p.identity, p.record(1), serviceProof = ByteArray(64) { 1 })
            idx.add(bad, now) shouldBe AnonymousIngestOutcome.INVALID
            idx.size() shouldBe 0
        }

        test("the high-water mark survives eviction, so an evicted identity can not be rolled back") {
            val p = AnonymousPublisher()
            val idx = index()
            idx.add(p.record(10, expiresInSeconds = 100), now) shouldBe AnonymousIngestOutcome.ACCEPTED
            idx.evictExpired(now + 1000) shouldBe 1
            idx.size() shouldBe 0
            idx.add(p.record(9, now = now + 1000), now + 1000) shouldBe AnonymousIngestOutcome.REPLAYED_OR_STALE
            idx.add(p.record(11, now = now + 1000), now + 1000) shouldBe AnonymousIngestOutcome.ACCEPTED
        }

        test(
            "a full index refuses NEW identities but never evicts a valid entry, and known identities can still update",
        ) {
            val idx = index(capacity = 3, marks = 8)
            val known = List(3) { AnonymousPublisher() }
            known.forEach { idx.add(it.record(1), now) shouldBe AnonymousIngestOutcome.ACCEPTED }
            idx.add(AnonymousPublisher().record(1), now) shouldBe AnonymousIngestOutcome.CAPACITY
            known.forEach { idx.current(it.key, now).shouldNotBeNull() }
            idx.add(known[0].record(2), now) shouldBe AnonymousIngestOutcome.ACCEPTED
            idx.size() shouldBe 3
        }

        test("expired entries make room for new identities") {
            val idx = index(capacity = 1, marks = 8)
            val old = AnonymousPublisher()
            idx.add(old.record(1, expiresInSeconds = 100), now) shouldBe AnonymousIngestOutcome.ACCEPTED
            val fresh = AnonymousPublisher()
            idx.add(fresh.record(1, now = now + 500), now + 500) shouldBe AnonymousIngestOutcome.ACCEPTED
            idx.current(old.key, now + 500).shouldBeNull()
        }

        test("a revocation overrides the entry, stays until its TTL ends and is reported as revoked") {
            val p = AnonymousPublisher()
            val idx = index()
            idx.add(p.record(10), now)
            idx.add(p.revocation(11, expiresInSeconds = 7200), now) shouldBe AnonymousIngestOutcome.ACCEPTED
            idx.current(p.key, now).shouldBeNull()
            idx.isRevoked(p.key, now) shouldBe true
            idx.currentIncludingRevocation(p.key, now)!!.revoked shouldBe true
            // an older anonymous record can not resurrect the presence
            idx.add(p.record(10), now) shouldBe AnonymousIngestOutcome.REPLAYED_OR_STALE
            idx.isRevoked(p.key, now + 8000) shouldBe false
            idx.add(p.record(9, now = now + 8000), now + 8000) shouldBe AnonymousIngestOutcome.REPLAYED_OR_STALE
        }

        test("precheck spends nothing and classifies without verifying signatures") {
            val p = AnonymousPublisher()
            val idx = index()
            val r = p.record(5)
            idx.precheck(r, now).shouldBeNull()
            idx.add(r, now)
            idx.precheck(r, now) shouldBe AnonymousIngestOutcome.DUPLICATE
            idx.precheck(p.record(4), now) shouldBe AnonymousIngestOutcome.REPLAYED_OR_STALE
            idx.precheck(p.record(6, expiresInSeconds = -1), now) shouldBe AnonymousIngestOutcome.EXPIRED
        }
    })
