package net.lapisphilosophorum.lapisnet.dm

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import java.time.Duration
import java.time.Instant
import java.util.Collections

/** A structurally-valid [DmEnvelope] blob, deliberately NOT decryptable by anything in this test -
 * [MailboxPoller] only needs [DmEnvelopeCodec.decode] to succeed to call [onDecodedEnvelope]; it
 * never decrypts itself (that is [DmSessionManager]'s job, exercised separately by
 * `TwoNodeOfflineMailboxIntegrationTest`/`MailboxAbuseTest`). */
private fun sampleEnvelopeBytes(senderIdentity: DualKeyIdentity = DualKeyIdentity.generate()): ByteArray {
    val ratchetMessage = dmSampleRatchetMessage()
    val envelope = DmEnvelope(DmMessageType.TEXT, senderIdentity.secp256k1KeyPair.publicKey, null, ratchetMessage)
    return DmEnvelopeCodec.encode(envelope)
}

/**
 * Exercises [MailboxPoller] directly, via a real two-node loopback setup ([buildDmTestNode]/
 * [connectAndConverge]) with a SEPARATE, standalone [MailboxPoller] instance constructed against
 * the recipient node's real [MailboxGossip]/[net.lapisphilosophorum.lapisnet.storage.NabuStorage]/
 * [net.lapisphilosophorum.lapisnet.directory.PeerDirectoryGossip] - not the poller
 * [DmSessionManager.attach] already wires up internally (which uses the harness's default 60s
 * interval, far too slow for this suite's bounded-deadline assertions). The recipient node's own
 * internal poller stays running throughout (harmless - see this file's own reasoning: it starts
 * with nothing pending, its next scheduled pass is far in the future relative to this suite's
 * timeouts, and [MailboxPointerIndex.markResolved] is idempotent even if it did race).
 */
class MailboxPollerTest :
    FunSpec({
        test(
            "initial catch-up on attach(): a pointer already pending BEFORE the poller is constructed resolves immediately",
        ) {
            val nodeA = buildDmTestNode()
            val nodeB = buildDmTestNode()
            var poller: MailboxPoller? = null
            try {
                connectAndConverge(nodeA, nodeB)

                val blobBytes = sampleEnvelopeBytes(nodeA.identity)
                val cid = nodeA.storage.put(blobBytes)
                val pointer =
                    MailboxPointer.create(
                        sender = nodeA.identity.secp256k1KeyPair,
                        recipientIdentity = nodeB.identity.secp256k1KeyPair.publicKey,
                        blobCid = cid,
                        notValidAfterEpochSecond = Instant.now().epochSecond + 3600,
                    )
                publishAndConvergeMailboxPointer(nodeA.pubsub, nodeB.mailboxGossip, pointer)
                nodeB.mailboxGossip.pending().size shouldBe 1

                val received = Collections.synchronizedList(mutableListOf<DmEnvelope>())
                // Long poll interval - if this test passes, it is because of the SYNCHRONOUS initial
                // catch-up inside attach()'s own start(), not because a scheduled pass happened to
                // run in the meantime.
                poller =
                    MailboxPoller.attach(
                        nodeB.mailboxGossip,
                        nodeB.storage,
                        nodeB.peerDirectory,
                        onDecodedEnvelope = { received.add(it) },
                        pollIntervalSeconds = 3600L,
                    )

                received.size shouldBe 1
                nodeB.mailboxGossip.pending().size shouldBe 0
            } finally {
                poller?.stop()
                nodeA.stop()
                nodeB.stop()
            }
        }

        test("periodic re-poll catches a pointer that arrives AFTER the poller is already running") {
            val nodeA = buildDmTestNode()
            val nodeB = buildDmTestNode()
            var poller: MailboxPoller? = null
            try {
                connectAndConverge(nodeA, nodeB)

                val received = Collections.synchronizedList(mutableListOf<DmEnvelope>())
                poller =
                    MailboxPoller.attach(
                        nodeB.mailboxGossip,
                        nodeB.storage,
                        nodeB.peerDirectory,
                        onDecodedEnvelope = { received.add(it) },
                        pollIntervalSeconds = 1L,
                    )
                received.size shouldBe 0 // nothing pending yet at attach() time

                val blobBytes = sampleEnvelopeBytes(nodeA.identity)
                val cid = nodeA.storage.put(blobBytes)
                val pointer =
                    MailboxPointer.create(
                        sender = nodeA.identity.secp256k1KeyPair,
                        recipientIdentity = nodeB.identity.secp256k1KeyPair.publicKey,
                        blobCid = cid,
                        notValidAfterEpochSecond = Instant.now().epochSecond + 3600,
                    )
                publishAndConvergeMailboxPointer(nodeA.pubsub, nodeB.mailboxGossip, pointer)

                val deadline = Instant.now().plus(Duration.ofSeconds(30))
                while (received.isEmpty() && Instant.now().isBefore(deadline)) Thread.sleep(500)

                received.size shouldBe 1
            } finally {
                poller?.stop()
                nodeA.stop()
                nodeB.stop()
            }
        }

        test(
            "a pointer whose CID cannot currently be fetched does not wedge the poller for a subsequent, fetchable pointer",
        ) {
            val nodeA = buildDmTestNode()
            val nodeB = buildDmTestNode()
            var poller: MailboxPoller? = null
            try {
                connectAndConverge(nodeA, nodeB)

                // Unreachable: signed by an identity that never published a PeerRecord anywhere -
                // PeerDirectoryGossip.lookup will return null for it forever, so MailboxPoller.attemptOne
                // returns immediately without ever calling storage.get.
                val unreachableSender = DualKeyIdentity.generate()
                val unreachableBlob = sampleEnvelopeBytes(unreachableSender)
                // Minted on nodeA's own storage purely so the pointer references a structurally real
                // CID - nodeB is never going to be able to fetch it regardless, since the signing
                // identity has no directory record.
                val unreachableCid = nodeA.storage.put(unreachableBlob)
                val unreachablePointer =
                    MailboxPointer.create(
                        sender = unreachableSender.secp256k1KeyPair,
                        recipientIdentity = nodeB.identity.secp256k1KeyPair.publicKey,
                        blobCid = unreachableCid,
                        notValidAfterEpochSecond = Instant.now().epochSecond + 3600,
                    )
                // Published via nodeA's own pubsub - GossipSub does not care who signed the payload,
                // only that a connected, subscribed peer receives it.
                publishAndConvergeMailboxPointer(nodeA.pubsub, nodeB.mailboxGossip, unreachablePointer)

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
                nodeB.mailboxGossip.pending().size shouldBe 2

                val received = Collections.synchronizedList(mutableListOf<DmEnvelope>())
                poller =
                    MailboxPoller.attach(
                        nodeB.mailboxGossip,
                        nodeB.storage,
                        nodeB.peerDirectory,
                        onDecodedEnvelope = { received.add(it) },
                        pollIntervalSeconds = 3600L,
                    )

                // The fetchable pointer resolved within the SAME synchronous initial pollOnce() call
                // that also attempted (and could not resolve) the unreachable one.
                received.size shouldBe 1
                val stillPending = nodeB.mailboxGossip.pending()
                stillPending.size shouldBe 1
                stillPending.first().blobCid shouldBe unreachablePointer.blobCid
            } finally {
                poller?.stop()
                nodeA.stop()
                nodeB.stop()
            }
        }
    })
