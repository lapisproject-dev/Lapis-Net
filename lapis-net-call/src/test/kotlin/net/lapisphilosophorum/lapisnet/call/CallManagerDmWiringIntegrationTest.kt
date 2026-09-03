package net.lapisphilosophorum.lapisnet.call

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerInfo
import net.lapisphilosophorum.lapisnet.directory.PeerCapability
import net.lapisphilosophorum.lapisnet.directory.PeerDirectoryGossip
import net.lapisphilosophorum.lapisnet.directory.PeerRecord
import net.lapisphilosophorum.lapisnet.directory.PrekeyBundleGossip
import net.lapisphilosophorum.lapisnet.dm.DmAcceptedContacts
import net.lapisphilosophorum.lapisnet.dm.DmContent
import net.lapisphilosophorum.lapisnet.dm.DmInboundMessage
import net.lapisphilosophorum.lapisnet.dm.DmSessionManager
import net.lapisphilosophorum.lapisnet.dm.MailboxGossip
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyStore
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files
import java.time.Duration
import java.time.Instant
import java.util.concurrent.CopyOnWriteArrayList

/**
 * MINOR review-round finding (2026-09-03): every other test in this module drives [CallManager]
 * exclusively via [CallManager.attachToTransport] with a `FakeCallSignalTransport` - the ACTUAL
 * production wiring ([CallManager.attach] over a real [DmSessionManager]/[DmCallSignalTransport])
 * had never been exercised by any test. [WebRtcCallMediaEngine]'s own doc comment already flagged
 * this gap. A bug in [CallManager.attach] itself (e.g. registering the wrong DM listener) would pass
 * this module's entire suite unnoticed without a test like this one.
 *
 * **Round-12 follow-up finding, 2026-09-03**: the first version of this test wired B's
 * [DmSessionManager] with no [DmAcceptedContacts] at all, so it could not catch a
 * [DmCallSignalTransport.send] that hardcoded `marksAcceptance` instead of forwarding it - exactly
 * the failure mode this class's KDoc claimed to cover but did not. Both tests below now pass a real
 * [DmAcceptedContacts] into B's [DmSessionManager.attach] and assert on [DmAcceptedContacts
 * .isAccepted] after the call resolves - the accept-flow test asserts `true`, the reject-flow test
 * asserts `false` (a REJECT must never promote its sender - see `CallManager.rejectCallOnStateThread`'s
 * own doc comment). If [DmCallSignalTransport.send] ever hardcodes `marksAcceptance`, exactly one of
 * these two tests fails no matter which constant was hardcoded.
 *
 * Deliberately NOT reusing `lapis-net-dm`'s own `DmTwoNodeTestHarness.kt` - its `buildDmTestNode`/
 * `connectAndConverge`/`DmTestNode` are `internal` to that module's own test source set and
 * invisible here (same "not reusable across modules" situation `lapis-net-dm`'s own
 * `DmTestFixtures.kt` documents for `lapis-net-ratchet`'s equivalent helpers). This is therefore a
 * deliberately minimal, single-purpose re-implementation - just enough real `LapisNode`/GossipSub/
 * directory/prekey-bundle machinery for two [DmSessionManager]s to establish a session and exchange a
 * `CALL_SIGNAL`, not a general-purpose harness.
 */
class CallManagerDmWiringIntegrationTest :
    FunSpec({
        test(
            "CallManager.attach over a real DmSessionManager: A places a call, B receives it " +
                "through the real DM stack, accepts, both reach ACTIVE, and B's real " +
                "DmAcceptedContacts records A as accepted",
        ) {
            withConnectedCallPair { harness ->
                val callId = harness.managerA.placeCall(harness.bPub)
                awaitCondition(timeoutMs = 30_000) { harness.eventsB.any { it is CallEvent.IncomingCall } }
                val incoming = harness.eventsB.filterIsInstance<CallEvent.IncomingCall>().single()
                incoming.callId shouldBe callId
                incoming.quarantined shouldBe false

                harness.managerB.acceptCall(callId)
                awaitCondition(timeoutMs = 30_000) { harness.eventsA.any { it is CallEvent.Active } }
                awaitCondition(timeoutMs = 30_000) { harness.eventsB.any { it is CallEvent.Active } }
                harness.managerA
                    .activeCalls()
                    .single()
                    .state shouldBe CallState.ACTIVE
                harness.managerB
                    .activeCalls()
                    .single()
                    .state shouldBe CallState.ACTIVE

                // The actual assertion this test exists for (round-12 finding): the real
                // DmCallSignalTransport.send forwarded ACCEPT's marksAcceptance=true all the way
                // through to B's real DmAcceptedContacts, exactly like DmSessionManagerCallSignalTest
                // proves at the DmSessionManager layer alone.
                harness.acceptedContactsB.isAccepted(harness.aPub) shouldBe true
            }
        }

        test(
            "CallManager.attach over a real DmSessionManager: B rejects an incoming call and its " +
                "real DmAcceptedContacts does NOT record A as accepted",
        ) {
            withConnectedCallPair { harness ->
                val callId = harness.managerA.placeCall(harness.bPub)
                awaitCondition(timeoutMs = 30_000) { harness.eventsB.any { it is CallEvent.IncomingCall } }

                harness.managerB.rejectCall(callId)
                awaitCondition(timeoutMs = 30_000) { harness.eventsA.any { it is CallEvent.Ended } }
                awaitCondition(timeoutMs = 30_000) { harness.eventsB.any { it is CallEvent.Ended } }
                harness.managerA.activeCalls() shouldBe emptyList()
                harness.managerB.activeCalls() shouldBe emptyList()

                // The actual assertion this test exists for (round-12 finding): if
                // DmCallSignalTransport.send ever hardcoded marksAcceptance=true instead of
                // forwarding rejectCallOnStateThread's `false`, this is the only assertion in the
                // entire module that would catch it - REJECT must never promote its sender to
                // DmAcceptedContacts (see CallManager.rejectCallOnStateThread's own doc comment).
                harness.acceptedContactsB.isAccepted(harness.aPub) shouldBe false
            }
        }
    })

/** Everything a test body needs to drive one A-places-call-to-B scenario over the real
 * [CallManager.attach] / [DmSessionManager] / [DmCallSignalTransport] production wiring. */
private class ConnectedCallPair(
    val managerA: CallManager,
    val managerB: CallManager,
    val eventsA: CopyOnWriteArrayList<CallEvent>,
    val eventsB: CopyOnWriteArrayList<CallEvent>,
    val aPub: Secp256k1PublicKey,
    val bPub: Secp256k1PublicKey,
    val acceptedContactsB: DmAcceptedContacts,
)

/** Builds two real, connected [LapisNode]s with a converged [DmSessionManager] session between
 * them (a prior TEXT DM establishes it first - a call never begins a first contact, see
 * `DmSessionManager`'s own class doc comment - mirroring `DmSessionManagerCallSignalTest`'s own
 * established "text before call" ordering), wires [CallManager.attach] on both sides (the ACTUAL
 * production entry point - never `attachToTransport`/`FakeCallSignalTransport`), runs [block]
 * against the result, and tears everything down afterwards regardless of outcome. B's
 * [DmSessionManager] is always given a real, fresh [DmAcceptedContacts] so [block] can assert on
 * it (see this file's class doc comment for why). */
private fun withConnectedCallPair(block: (ConnectedCallPair) -> Unit) {
    val identityA = DualKeyIdentity.generate()
    val identityB = DualKeyIdentity.generate()

    val nodeA = LapisNode.create(identityA)
    val nodeB = LapisNode.create(identityB)
    nodeA.start(bootstrapPeers = emptyList())
    nodeB.start(bootstrapPeers = emptyList())

    val storageA = NabuStorage.attach(nodeA, Files.createTempDirectory("call-wiring-storage-a"))
    val storageB = NabuStorage.attach(nodeB, Files.createTempDirectory("call-wiring-storage-b"))
    // GossipPubSub must be attached BEFORE any connect() call - mirrors every DM integration
    // test's own established two-node setup order.
    val pubsubA = GossipPubSub.attach(nodeA)
    val pubsubB = GossipPubSub.attach(nodeB)
    val directoryA = PeerDirectoryGossip.attach(pubsubA, storageA)
    val directoryB = PeerDirectoryGossip.attach(pubsubB, storageB)
    val prekeyGossipA = PrekeyBundleGossip.attach(pubsubA, storageA)
    val prekeyGossipB = PrekeyBundleGossip.attach(pubsubB, storageB)
    val mailboxGossipA = MailboxGossip.attach(pubsubA, storageA, identityA.secp256k1KeyPair.publicKey)
    val mailboxGossipB = MailboxGossip.attach(pubsubB, storageB, identityB.secp256k1KeyPair.publicKey)
    val prekeyStoreA =
        PrekeyStore.create(
            Files.createTempDirectory("call-wiring-prekeystore-a"),
            identityA,
            oneTimePrekeyCount = 5,
        )
    val prekeyStoreB =
        PrekeyStore.create(
            Files.createTempDirectory("call-wiring-prekeystore-b"),
            identityB,
            oneTimePrekeyCount = 5,
        )
    val passphrase = "correct horse battery staple".toCharArray()
    val acceptedContactsB = DmAcceptedContacts()
    val dmA =
        DmSessionManager.attach(
            identityA,
            prekeyStoreA,
            nodeA,
            directoryA,
            prekeyGossipA,
            mailboxGossipA,
            storageA,
            pubsubA,
            Files.createTempDirectory("call-wiring-sessions-a"),
            passphrase,
        )
    val dmB =
        DmSessionManager.attach(
            identityB,
            prekeyStoreB,
            nodeB,
            directoryB,
            prekeyGossipB,
            mailboxGossipB,
            storageB,
            pubsubB,
            Files.createTempDirectory("call-wiring-sessions-b"),
            passphrase,
            acceptedContacts = acceptedContactsB,
        )

    val engineA = FakeCallMediaEngine()
    val engineB = FakeCallMediaEngine()
    // The PRODUCTION entry point under test - never attachToTransport()/FakeCallSignalTransport.
    val managerA = CallManager.attach(dmA, engineA)
    val managerB = CallManager.attach(dmB, engineB)
    val eventsA = CopyOnWriteArrayList<CallEvent>()
    val eventsB = CopyOnWriteArrayList<CallEvent>()
    managerA.addCallListener { eventsA.add(it) }
    managerB.addCallListener { eventsB.add(it) }

    try {
        fun publishSelf(
            node: LapisNode,
            identity: DualKeyIdentity,
            directory: PeerDirectoryGossip,
            prekeyGossip: PrekeyBundleGossip,
            prekeyStore: PrekeyStore,
        ) {
            val record =
                PeerRecord.create(
                    identity = identity,
                    addresses = node.listenAddresses(),
                    capabilities = setOf(PeerCapability.DM),
                    sequenceNumber = System.nanoTime(),
                    notValidAfterEpochSecond = Instant.now().epochSecond + 3600,
                )
            directory.announce(record)
            val bundle = prekeyStore.publishBundle(identity, Instant.now().epochSecond + 3600)
            prekeyGossip.announce(bundle)
        }

        nodeA.connect(PeerInfo(nodeB.peerId, nodeB.listenAddresses()))
        val deadline = Instant.now().plus(Duration.ofSeconds(30))
        while (Instant.now().isBefore(deadline)) {
            publishSelf(nodeA, identityA, directoryA, prekeyGossipA, prekeyStoreA)
            publishSelf(nodeB, identityB, directoryB, prekeyGossipB, prekeyStoreB)
            val aSeesB = directoryA.lookup(identityB.secp256k1KeyPair.publicKey) != null
            val bSeesA = directoryB.lookup(identityA.secp256k1KeyPair.publicKey) != null
            val aSeesBBundle = prekeyGossipA.lookup(identityB.secp256k1KeyPair.publicKey) != null
            val bSeesABundle = prekeyGossipB.lookup(identityA.secp256k1KeyPair.publicKey) != null
            if (aSeesB && bSeesA && aSeesBBundle && bSeesABundle) break
            Thread.sleep(500)
        }

        val aPub = identityA.secp256k1KeyPair.publicKey
        val bPub = identityB.secp256k1KeyPair.publicKey
        val received = CopyOnWriteArrayList<DmInboundMessage>()
        dmB.addInboundListener { received.add(it) }
        val textDeadline = Instant.now().plus(Duration.ofSeconds(30))
        while (received.isEmpty() && Instant.now().isBefore(textDeadline)) {
            runCatching {
                dmA.send(bPub, DmContent(body = "hi"))
            }
            Thread.sleep(1000)
        }
        received.isEmpty() shouldBe false
        // The prior TEXT DM's own auto-accept must not itself satisfy this file's assertions -
        // DmSessionManager.attach was only given acceptedContactsB for B, and dmB never SENT
        // anything above, so acceptedContactsB stays empty until a call signal touches it.
        acceptedContactsB.isAccepted(aPub) shouldBe false

        block(
            ConnectedCallPair(
                managerA = managerA,
                managerB = managerB,
                eventsA = eventsA,
                eventsB = eventsB,
                aPub = aPub,
                bPub = bPub,
                acceptedContactsB = acceptedContactsB,
            ),
        )
    } finally {
        managerA.stop()
        managerB.stop()
        runCatching { dmA.stop() }
        runCatching { dmB.stop() }
        runCatching { mailboxGossipA.stop() }
        runCatching { mailboxGossipB.stop() }
        runCatching { directoryA.stop() }
        runCatching { directoryB.stop() }
        runCatching { prekeyGossipA.stop() }
        runCatching { prekeyGossipB.stop() }
        runCatching { nodeA.stop() }
        runCatching { nodeB.stop() }
    }
}
