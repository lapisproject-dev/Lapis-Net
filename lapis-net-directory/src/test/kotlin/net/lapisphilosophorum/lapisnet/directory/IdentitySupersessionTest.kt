package net.lapisphilosophorum.lapisnet.directory

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import java.time.Instant

/** Cross-type downgrade protection between address-bearing and anonymous records of one identity. */
class IdentitySupersessionTest :
    FunSpec({
        val now = Instant.now().epochSecond

        test("the floors are unset for an unknown identity and rise monotonically") {
            val s = IdentitySupersession(maxEntries = 4)
            val key = DualKeyIdentity.generate().secp256k1KeyPair.publicKey
            s.peerRecordFloor(key) shouldBe Long.MIN_VALUE
            s.anonymousRecordFloor(key) shouldBe Long.MIN_VALUE
            s.raiseAnonymous(key, 10)
            s.raiseAnonymous(key, 5)
            s.peerRecordFloor(key) shouldBe 10
            s.raisePeerRecord(key, 7)
            s.anonymousRecordFloor(key) shouldBe 7
        }

        test("the table is LRU-bounded") {
            val s = IdentitySupersession(maxEntries = 2)
            val keys = List(3) { DualKeyIdentity.generate().secp256k1KeyPair.publicKey }
            keys.forEach { s.raiseAnonymous(it, 1) }
            s.peerRecordFloor(keys[0]) shouldBe Long.MIN_VALUE
            s.peerRecordFloor(keys[2]) shouldBe 1
        }

        test("an accepted anonymous record removes the address record and an old address record can not come back") {
            val peers = PeerRecordIndex()
            val anon = AnonymousPeerRecordIndex(peers)
            val p = AnonymousPublisher()
            val old = p.peerRecord(sequence = 100)
            peers.add(old) shouldBe true
            peers.current(p.key) shouldBe old

            anon.add(p.record(200), now) shouldBe AnonymousIngestOutcome.ACCEPTED
            peers.current(p.key).shouldBeNull()
            // replay of the old record, and of anything not newer than the anonymous one
            peers.canAccept(old) shouldBe false
            peers.add(old) shouldBe false
            peers.add(p.peerRecord(sequence = 150, port = 4002)) shouldBe false
            peers.add(p.peerRecord(sequence = 200, port = 4003)) shouldBe false // a tie goes to the anonymous record
            peers.current(p.key).shouldBeNull()
        }

        test("the way back: a newer address record hides the anonymous entry") {
            val peers = PeerRecordIndex()
            val anon = AnonymousPeerRecordIndex(peers)
            val p = AnonymousPublisher()
            anon.add(p.record(200), now) shouldBe AnonymousIngestOutcome.ACCEPTED
            anon.current(p.key, now).shouldNotBeNull()

            val back = p.peerRecord(sequence = 201)
            peers.add(back) shouldBe true
            anon.current(p.key, now).shouldBeNull()
            anon.isRevoked(p.key, now) shouldBe false
            // an older anonymous record is stale now, a newer one wins again
            anon.add(p.record(150), now) shouldBe AnonymousIngestOutcome.REPLAYED_OR_STALE
            anon.add(p.record(300), now) shouldBe AnonymousIngestOutcome.ACCEPTED
            peers.current(p.key).shouldBeNull()
        }

        test("identities without an anonymous record behave exactly as before") {
            val peers = PeerRecordIndex()
            val anon = AnonymousPeerRecordIndex(peers)
            val plain = AnonymousPublisher()
            val other = AnonymousPublisher()
            anon.add(other.record(1_000_000), now) // unrelated identity with a huge anonymous sequence
            peers.add(plain.peerRecord(sequence = 5)) shouldBe true
            peers.add(plain.peerRecord(sequence = 4, port = 4002)) shouldBe false // ordinary rollback protection
            peers.add(plain.peerRecord(sequence = 6, port = 4003)) shouldBe true
            peers.supersession.peerRecordFloor(plain.key) shouldBe Long.MIN_VALUE
        }

        test("superseding releases the persistence reservation of the removed record") {
            val peers = PeerRecordIndex(maxTracked = 10, maxPersisted = 1, maxHighWaterMarks = 10)
            val anon = AnonymousPeerRecordIndex(peers)
            val p = AnonymousPublisher()
            val old = p.peerRecord(sequence = 1)
            peers.add(old)
            peers.tryReservePersistence(old) shouldBe true
            val other = AnonymousPublisher().peerRecord(sequence = 1)
            peers.tryReservePersistence(other) shouldBe false // cap of one reached
            anon.add(p.record(2), now)
            peers.tryReservePersistence(other) shouldBe true // the slot of the superseded record is free again
        }

        test("sequence numbers of both types share the epoch millisecond scale") {
            // a sequence in seconds would be ~1.7e9, in milliseconds ~1.7e12: mixing them silently breaks the guard
            val ms = System.currentTimeMillis()
            val peers = PeerRecordIndex()
            val anon = AnonymousPeerRecordIndex(peers)
            val p = AnonymousPublisher()
            anon.add(p.record(ms), now) shouldBe AnonymousIngestOutcome.ACCEPTED
            peers.add(p.peerRecord(sequence = ms / 1000)) shouldBe false // a seconds value is "older" and refused
            peers.add(p.peerRecord(sequence = ms + 1)) shouldBe true
        }
    })
