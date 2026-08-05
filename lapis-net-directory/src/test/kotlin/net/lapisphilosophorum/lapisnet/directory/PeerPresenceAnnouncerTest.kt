package net.lapisphilosophorum.lapisnet.directory

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.multiformats.Multiaddr
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files

private fun testAddress(port: Int): Multiaddr = Multiaddr("/ip4/127.0.0.1/tcp/$port")

private fun record(
    identity: DualKeyIdentity,
    sequenceNumber: Long,
): PeerRecord =
    PeerRecord.create(identity, listOf(testAddress(4001)), setOf(PeerCapability.DM), sequenceNumber, 9_999_999_999L)

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

        test("the first call is always due, even though lastAnnouncedAtEpochSecond starts unset") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("announcer-first-call"))
                val gossip = PeerDirectoryGossip.attach(GossipPubSub.attach(node), storage)
                val announcer = PeerPresenceAnnouncer(gossip)

                announcer.announceIfDue(record(identity, 0), nowEpochSecond = 1000L) shouldBe true
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

                announcer.announceIfDue(record(identity, 0), nowEpochSecond = 1000L) shouldBe true
                announcer.announceIfDue(record(identity, 1), nowEpochSecond = 1050L) shouldBe false
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

                announcer.announceIfDue(record(identity, 0), nowEpochSecond = 1000L) shouldBe true
                announcer.announceIfDue(record(identity, 1), nowEpochSecond = 1299L) shouldBe false
                announcer.announceIfDue(record(identity, 2), nowEpochSecond = 1300L) shouldBe true
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

                announcer.announceIfDue(record(identity, 0), nowEpochSecond = 0L) shouldBe true
                announcer.announceIfDue(record(identity, 1), nowEpochSecond = 3L) shouldBe false
                announcer.announceIfDue(record(identity, 2), nowEpochSecond = 5L) shouldBe true
                announcer.announceIfDue(record(identity, 3), nowEpochSecond = 6L) shouldBe false
                announcer.announceIfDue(record(identity, 4), nowEpochSecond = 10L) shouldBe true
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

                announcer.announceIfDue(record(identity, 0), nowEpochSecond = 1000L) shouldBe true
                val before = gossip.lookup(identity.secp256k1KeyPair.publicKey, nowEpochSecond = 1000L)

                val suppressed = record(identity, 1)
                announcer.announceIfDue(suppressed, nowEpochSecond = 1010L) shouldBe false

                val after = gossip.lookup(identity.secp256k1KeyPair.publicKey, nowEpochSecond = 1010L)
                after shouldBe before
                (after?.sequenceNumber ?: -1) shouldBe 0L // still the first record, not the suppressed one
            } finally {
                node.stop()
            }
        }

        // Security/liveness regression (V0.8.1 sub-wave audit round 2, minor finding 3): a
        // backward wall-clock jump (NTP correction, VM snapshot restore, container clock skew)
        // must not stall the heartbeat. Before the fix, `nowEpochSecond - last < floor` stayed true
        // for a NEGATIVE delta (a rewind), so every call after a rewind was suppressed until
        // wall-clock caught back up past `last + minRepublishIntervalSeconds` - for a large enough
        // jump, a silent, fail-closed presence outage lasting hours or days.
        test("a backward clock jump is treated as immediately due, not suppressed indefinitely") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("announcer-clock-rewind"))
                val gossip = PeerDirectoryGossip.attach(GossipPubSub.attach(node), storage)
                val announcer = PeerPresenceAnnouncer(gossip)

                announcer.announceIfDue(record(identity, 0), nowEpochSecond = 1300L) shouldBe true

                // Wall clock jumps BACKWARDS by 400 seconds - well within what would otherwise be
                // "suppressed" territory (negative delta is always < the 300s floor).
                announcer.announceIfDue(record(identity, 1), nowEpochSecond = 900L) shouldBe true

                // A second call shortly after the rewind (still under the floor relative to the
                // NEW last-announced time) is suppressed normally - proving the fix didn't disable
                // rate limiting altogether, only the indefinite-stall failure mode.
                announcer.announceIfDue(record(identity, 2), nowEpochSecond = 901L) shouldBe false
            } finally {
                node.stop()
            }
        }
    })
