package net.lapisphilosophorum.lapisnet.directory

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.multiformats.Multiaddr
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files
import java.time.Instant

private fun testAddress(port: Int): Multiaddr = Multiaddr("/ip4/127.0.0.1/tcp/$port")

private fun record(
    identity: DualKeyIdentity,
    sequenceNumber: Long,
): PeerRecord =
    PeerRecord.create(
        identity,
        listOf(testAddress(4001)),
        setOf(PeerCapability.DM),
        sequenceNumber,
        Instant.now().epochSecond + 3600,
    )

/** [PeerPresenceAnnouncer.announceIfDue]'s interval decision is monotonic-nanosecond-based (see
 * that class's doc comment for the round-4 fix), so every test here deals in synthetic
 * [System.nanoTime]-shaped tick counts, never epoch seconds - this helper makes that conversion
 * explicit and readable at every call site rather than scattering raw `* 1_000_000_000L` literals. */
private fun secondsToNanos(seconds: Long): Long = seconds * 1_000_000_000L

/** A stub [PeerDirectoryGossip]-shaped call counter is unnecessary here - a REAL, attached,
 * never-connected-to-peers [PeerDirectoryGossip] is used instead (mirrors this module's other
 * test files' "real components, no mocking" discipline), and a suppressed call's absence of side
 * effects is observed directly through [NabuStorage]/[PeerRecordIndex] state, per the class doc
 * comment's own suggested verification approach. */
class PeerPresenceAnnouncerTest :
    FunSpec({
        test("MIN_REPUBLISH_INTERVAL_SECONDS default is 300") {
            PeerPresenceAnnouncer.MIN_REPUBLISH_INTERVAL_SECONDS shouldBe 300L
        }

        test("the first call is always due, even though lastAnnouncedAtNanos starts unset") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("announcer-first-call"))
                val gossip = PeerDirectoryGossip.attach(GossipPubSub.attach(node), storage)
                val announcer = PeerPresenceAnnouncer(gossip)

                announcer.announceIfDue(record(identity, 0), nowNanos = secondsToNanos(1000)) shouldBe true
            } finally {
                node.stop()
            }
        }

        test("a call well under the floor (50s after a 300s default) is suppressed") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("announcer-suppressed"))
                val gossip = PeerDirectoryGossip.attach(GossipPubSub.attach(node), storage)
                val announcer = PeerPresenceAnnouncer(gossip)

                announcer.announceIfDue(record(identity, 0), nowNanos = secondsToNanos(1000)) shouldBe true
                announcer.announceIfDue(record(identity, 1), nowNanos = secondsToNanos(1050)) shouldBe false
            } finally {
                node.stop()
            }
        }

        test("boundary is inclusive-due: exactly at the floor (300s later) is due, one second before is not") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("announcer-boundary"))
                val gossip = PeerDirectoryGossip.attach(GossipPubSub.attach(node), storage)
                val announcer = PeerPresenceAnnouncer(gossip)

                announcer.announceIfDue(record(identity, 0), nowNanos = secondsToNanos(1000)) shouldBe true
                announcer.announceIfDue(record(identity, 1), nowNanos = secondsToNanos(1299)) shouldBe false
                announcer.announceIfDue(record(identity, 2), nowNanos = secondsToNanos(1300)) shouldBe true
            } finally {
                node.stop()
            }
        }

        test("a custom, small minRepublishIntervalSeconds is honored across a fast-moving sequence") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("announcer-custom-interval"))
                val gossip = PeerDirectoryGossip.attach(GossipPubSub.attach(node), storage)
                val announcer = PeerPresenceAnnouncer(gossip, minRepublishIntervalSeconds = 5)

                announcer.announceIfDue(record(identity, 0), nowNanos = secondsToNanos(0)) shouldBe true
                announcer.announceIfDue(record(identity, 1), nowNanos = secondsToNanos(3)) shouldBe false
                announcer.announceIfDue(record(identity, 2), nowNanos = secondsToNanos(5)) shouldBe true
                announcer.announceIfDue(record(identity, 3), nowNanos = secondsToNanos(6)) shouldBe false
                announcer.announceIfDue(record(identity, 4), nowNanos = secondsToNanos(10)) shouldBe true
            } finally {
                node.stop()
            }
        }

        test("a suppressed call has no observable side effect - no new content id in storage or index") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("announcer-no-side-effect"))
                val pubsub = GossipPubSub.attach(node)
                val gossip = PeerDirectoryGossip.attach(pubsub, storage)
                val announcer = PeerPresenceAnnouncer(gossip)

                announcer.announceIfDue(record(identity, 0), nowNanos = secondsToNanos(1000)) shouldBe true
                val before = gossip.lookup(identity.secp256k1KeyPair.publicKey)

                val suppressed = record(identity, 1)
                announcer.announceIfDue(suppressed, nowNanos = secondsToNanos(1010)) shouldBe false

                val after = gossip.lookup(identity.secp256k1KeyPair.publicKey)
                after shouldBe before
                (after?.sequenceNumber ?: -1) shouldBe 0L // still the first record, not the suppressed one
            } finally {
                node.stop()
            }
        }

        // Security/liveness regression (V0.8.1 sub-wave audit round 4, major finding): replaces
        // round 2's wall-clock-rewind regression entirely, because round 4 removed wall-clock time
        // from this decision altogether rather than special-casing a backward jump within it.
        // Round 2's fix (treat nowEpochSecond < last as "immediately due") closed a fail-CLOSED
        // stall but reopened a fail-OPEN bypass: anything able to make Instant.now() read
        // backward before every single call - a misbehaving local NTP daemon, a VM host adjusting
        // guest time, or a deliberately misconfigured local clock - permanently disabled the floor,
        // since every call would then satisfy the "was a rewind" branch. announceIfDue no longer
        // accepts an epoch-second parameter at all: the ONLY lever a caller has is nowNanos, a
        // System.nanoTime()-shaped monotonic tick count that is, by the JVM's own guarantee, never
        // able to move backward within a process's lifetime - there is no way to feed this
        // real API an input shaped like the round-2 attack at all. This test proves the decision
        // genuinely only depends on the elapsed MONOTONIC delta between calls: an arbitrarily large
        // simulated wall-clock disruption (which this call never even receives, by construction) has
        // zero effect on it, and normal rate limiting keeps working either side of that gap.
        test(
            "the interval decision depends only on elapsed monotonic nanos - " +
                "no wall-clock rewind can stall or bypass it, because none is ever consulted",
        ) {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("announcer-monotonic"))
                val gossip = PeerDirectoryGossip.attach(GossipPubSub.attach(node), storage)
                val announcer = PeerPresenceAnnouncer(gossip)

                // An arbitrary, large absolute nowNanos value - deliberately NOT epoch-scale, to
                // underline that only DIFFERENCES between successive readings matter here, unlike
                // wall-clock time where the absolute value itself was previously significant.
                val firstTick = secondsToNanos(1_000_000)
                announcer.announceIfDue(record(identity, 0), nowNanos = firstTick) shouldBe true

                // Only 1 second of MONOTONIC elapsed time has passed - still well under the 300s
                // floor. A wall-clock rewind of any size happening concurrently (which this call
                // never receives as a parameter at all) cannot change this outcome.
                announcer.announceIfDue(record(identity, 1), nowNanos = firstTick + secondsToNanos(1)) shouldBe false

                // Once the monotonic floor genuinely elapses, it is due again - proving the fix
                // didn't disable rate limiting altogether, only removed wall-clock time from the
                // decision.
                val floorNanos = secondsToNanos(PeerPresenceAnnouncer.MIN_REPUBLISH_INTERVAL_SECONDS)
                announcer.announceIfDue(record(identity, 2), nowNanos = firstTick + floorNanos) shouldBe true
            } finally {
                node.stop()
            }
        }
    })
