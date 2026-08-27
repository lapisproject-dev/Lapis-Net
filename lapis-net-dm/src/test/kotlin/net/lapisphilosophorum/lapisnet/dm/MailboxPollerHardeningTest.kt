package net.lapisphilosophorum.lapisnet.dm

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.directory.PeerCapability
import net.lapisphilosophorum.lapisnet.directory.PeerRecord
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files
import java.time.Instant
import java.util.Collections
import kotlin.random.Random

/** A structurally-valid [DmEnvelope] blob - mirrors `MailboxPollerTest`'s/`MailboxAbuseTest`'s
 * identical fixture, duplicated locally per this codebase's own established file-private
 * convention. */
private fun sampleEnvelopeBytes(senderIdentity: DualKeyIdentity = DualKeyIdentity.generate()): ByteArray {
    val ratchetMessage = dmSampleRatchetMessage()
    val envelope = DmEnvelope(DmMessageType.TEXT, senderIdentity.secp256k1KeyPair.publicKey, null, ratchetMessage)
    return DmEnvelopeCodec.encode(envelope)
}

/** A minimal, real, running [LapisNode] + [NabuStorage] pair, used as a directory-registered but
 * genuinely UNFETCHABLE claimed sender - no `PrekeyStore`/`DmSessionManager` needed, since these
 * tests only need [MailboxPoller.attemptOne]'s real `peerDirectory.lookup` -> `storage.get` path to
 * dispatch a genuine (non-short-circuited) Bitswap fetch attempt that never resolves. */
private class StuckSender(
    val identity: DualKeyIdentity = DualKeyIdentity.generate(),
) {
    val node: LapisNode = LapisNode.create(identity)
    val storage: NabuStorage

    init {
        node.start(bootstrapPeers = emptyList())
        storage = NabuStorage.attach(node, Files.createTempDirectory("mailbox-poller-hardening-stuck"))
    }

    /** Registers this identity's own real (but block-lacking) address as a [PeerRecord] directly
     * into [recipient]'s local directory index - a direct in-process call, not a gossip round trip
     * (`PeerDirectoryGossip.announce`'s own doc comment: `index.add()` runs unconditionally before
     * `pubsub.publish()`, so this is visible to [recipient] immediately regardless of whether
     * anything is even pubsub-connected to receive the broadcast half). */
    fun announceSelfTo(recipient: DmTestNode) {
        val record =
            PeerRecord.create(
                identity = identity,
                addresses = node.listenAddresses(),
                capabilities = setOf(PeerCapability.DM),
                sequenceNumber = 1L,
                notValidAfterEpochSecond = Instant.now().epochSecond + 3600,
            )
        recipient.peerDirectory.announce(record)
    }

    fun stop() = runCatching { node.stop() }
}

/**
 * V0.8.5 security audit round 1/round 2 findings, closed in [MailboxPoller] itself but left with
 * ZERO regression coverage exercising their actual mechanisms - `MailboxAbuseTest`'s case (b) and
 * `MailboxPollerTest`'s own "does not wedge" case both use senders with NO [PeerRecord] at all, so
 * [MailboxPoller.attemptOne] short-circuits at the FREE `peerDirectory.lookup == null` early return
 * (see that method's own doc comment) without ever reaching the REAL `storage.get` Bitswap-timeout
 * path [POLL_PASS_WALL_CLOCK_BUDGET]/[MailboxPoller.MAX_FETCH_ATTEMPTS_PER_SENDER_PER_PASS] were
 * actually built to bound. Confirmed by mutation (see the round-2 rotation test below): reverting
 * [MailboxPoller]'s `passStartOffset` fix left every existing test in this suite green.
 */
class MailboxPollerHardeningTest :
    FunSpec({
        test(
            "round 2 major finding regression: the pass-rotation fix (passStartOffset) prevents " +
                "unfetchable pointers from PERMANENTLY starving a fetchable one behind them, across " +
                "real Bitswap-timeout-bound passes",
        ) {
            val nodeA = buildDmTestNode()
            val nodeB = buildDmTestNode()
            val stuckSenders = listOf(StuckSender(), StuckSender())
            var poller: MailboxPoller? = null
            try {
                connectAndConverge(nodeA, nodeB)
                stuckSenders.forEach { it.announceSelfTo(nodeB) }

                // Two genuinely-registered senders whose blobs nodeB can never fetch: nodeB CAN
                // resolve their address (peerDirectory.lookup succeeds, unlike MailboxAbuseTest (b)'s
                // no-PeerRecord throwaways) and dispatches a REAL storage.get - but each `stuckSender`
                // node's own storage never received the referenced content, so every attempt runs the
                // real NabuStorage.DEFAULT_TIMEOUT (~10s) before giving up. Minted on a THROWAWAY,
                // never-connected node so `stuckSenders[i].storage` genuinely lacks the bytes -
                // mirrors MailboxAbuseTest (a)'s own established "mint CIDs on a separate,
                // never-connected node" technique.
                val mintingNode = LapisNode.create(DualKeyIdentity.generate())
                mintingNode.start(bootstrapPeers = emptyList())
                val mintingStorage =
                    NabuStorage.attach(mintingNode, Files.createTempDirectory("mailbox-poller-hardening-mint"))
                val stuckPointers =
                    stuckSenders.map { stuck ->
                        val cid = mintingStorage.put(Random.nextBytes(64))
                        val pointer =
                            MailboxPointer.create(
                                sender = stuck.identity.secp256k1KeyPair,
                                recipientIdentity = nodeB.identity.secp256k1KeyPair.publicKey,
                                blobCid = cid,
                                notValidAfterEpochSecond = Instant.now().epochSecond + 3600,
                            )
                        publishAndConvergeMailboxPointer(nodeA.pubsub, nodeB.mailboxGossip, pointer)
                        pointer
                    }
                mintingNode.stop()

                // Published LAST, so it sorts at the tail of MailboxPointerIndex's insertion-ordered
                // `pending()` list, exactly the shape the round 2 finding's own reproduction used
                // ("three blockless-but-reachable pointers plus one genuinely fetchable pointer
                // published last").
                val fetchableBlob = sampleEnvelopeBytes(nodeA.identity)
                val fetchableCid = nodeA.storage.put(fetchableBlob)
                val fetchablePointer =
                    MailboxPointer.create(
                        sender = nodeA.identity.secp256k1KeyPair,
                        recipientIdentity = nodeB.identity.secp256k1KeyPair.publicKey,
                        blobCid = fetchableCid,
                        notValidAfterEpochSecond = Instant.now().epochSecond + 3600,
                    )
                publishAndConvergeMailboxPointer(nodeA.pubsub, nodeB.mailboxGossip, fetchablePointer)
                nodeB.mailboxGossip.pending().size shouldBe 3

                val received = Collections.synchronizedList(mutableListOf<DmEnvelope>())
                // attach()'s own synchronous initial pollOnce() pass is PASS 1: at ~10s/real attempt
                // and a 20s POLL_PASS_WALL_CLOCK_BUDGET, it fits both stuck pointers (~20s) and then
                // exhausts the budget BEFORE ever reaching the fetchable one at the tail.
                poller =
                    MailboxPoller.attach(
                        nodeB.mailboxGossip,
                        nodeB.storage,
                        nodeB.peerDirectory,
                        onDecodedEnvelope = { received.add(it) },
                        pollIntervalSeconds = 999_999_999L,
                    )

                received.size shouldBe 0 // fetchable never reached in pass 1 - budget exhausted first
                nodeB.mailboxGossip.pending().size shouldBe 3 // nothing resolved - stuck ones stay pending

                // PASS 2: THE CENTRAL ASSERTION. With passStartOffset rotated to wherever pass 1
                // stopped (the fetchable pointer's own index), pass 2 reaches and delivers it - pass 2
                // still spends real time re-attempting the two still-pending stuck pointers too
                // (pollOnce processes the WHOLE rotated list up to budget, not just one pointer, so
                // this is NOT a fast-pass assertion), but critically the fetchable pointer is reached
                // and resolved THIS pass. Pre-fix (always-start-at-index-0), pass 2 would instead
                // re-attempt the two stuck pointers FIRST, from the head, exhaust the SAME ~20s budget
                // AGAIN before ever reaching index 2, and `received` would stay 0 - repeating
                // identically on every subsequent pass, forever, for as long as the two stuck pointers
                // remain pending (the round 2 finding's own "permanently starved" reproduction).
                poller.pollOnce()

                received.size shouldBe 1
                val stillPending = nodeB.mailboxGossip.pending()
                stillPending.size shouldBe 2 // only the two genuinely-stuck ones remain
                stillPending.map { it.blobCid }.toSet() shouldBe stuckPointers.map { it.blobCid }.toSet()
            } finally {
                poller?.stop()
                stuckSenders.forEach { it.stop() }
                nodeA.stop()
                nodeB.stop()
            }
        }

        test(
            "round 1 major finding regression: MAX_FETCH_ATTEMPTS_PER_SENDER_PER_PASS caps how many " +
                "of ONE sender's pointers a single pass will dispatch, deferring the rest - not " +
                "losing them - to the next pass",
        ) {
            val nodeA = buildDmTestNode()
            val nodeB = buildDmTestNode()
            var poller: MailboxPoller? = null
            try {
                connectAndConverge(nodeA, nodeB)

                // Six pointers, all claiming nodeA as sender (nodeA is already directory-resolvable
                // and directly reachable via connectAndConverge - a REAL, non-short-circuited
                // attemptOne dispatch for every one of them), each referencing a distinct GARBAGE
                // blob nodeA genuinely has and serves FAST (no Bitswap timeout involved at all - this
                // isolates the SENDER CAP from POLL_PASS_WALL_CLOCK_BUDGET, which a real ~10s-per-
                // attempt fetch would otherwise always trip first at only ~2 attempts/pass, making the
                // cap of 4 structurally unreachable within one pass - see this file's class doc
                // comment). A garbage (non-DmEnvelope) blob makes attemptOne's decode step fail and
                // call markResolved immediately - fast, real, and DEFINITIVE, exactly like a
                // genuinely-fetched-but-corrupt mailbox blob would.
                (0 until 6).forEach { i ->
                    val cid = nodeA.storage.put(Random.nextBytes(32 + i))
                    val pointer =
                        MailboxPointer.create(
                            sender = nodeA.identity.secp256k1KeyPair,
                            recipientIdentity = nodeB.identity.secp256k1KeyPair.publicKey,
                            blobCid = cid,
                            notValidAfterEpochSecond = Instant.now().epochSecond + 3600,
                        )
                    publishAndConvergeMailboxPointer(nodeA.pubsub, nodeB.mailboxGossip, pointer)
                }
                nodeB.mailboxGossip.pending().size shouldBe 6

                // attach()'s synchronous initial pollOnce() is PASS 1.
                poller =
                    MailboxPoller.attach(
                        nodeB.mailboxGossip,
                        nodeB.storage,
                        nodeB.peerDirectory,
                        onDecodedEnvelope = { true },
                        pollIntervalSeconds = 999_999_999L,
                    )

                // THE CENTRAL ASSERTION: exactly MAX_FETCH_ATTEMPTS_PER_SENDER_PER_PASS (4) of the 6
                // same-sender pointers were dispatched (and resolved, since every one decodes to
                // garbage) in pass 1 - the other 2 were never even attempted this pass, left pending
                // by the cap, not lost.
                nodeB.mailboxGossip.pending().size shouldBe 2

                // PASS 2: the cap resets per pass - the 2 deferred pointers are dispatched and
                // resolved now, proving the cap only ever deferred them, it did not permanently drop
                // them (mirrors MailboxPoller's own doc comment: "A capped sender's EXCESS pointers
                // are simply left pending for the next pass, never marked resolved").
                poller.pollOnce()
                nodeB.mailboxGossip.pending().size shouldBe 0
            } finally {
                poller?.stop()
                nodeA.stop()
                nodeB.stop()
            }
        }
    })
