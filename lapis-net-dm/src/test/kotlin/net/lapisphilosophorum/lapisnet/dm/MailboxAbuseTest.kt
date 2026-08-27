package net.lapisphilosophorum.lapisnet.dm

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.longs.shouldBeLessThan
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.directory.PeerDirectoryGossip
import net.lapisphilosophorum.lapisnet.directory.PrekeyBundleGossip
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.EncryptionKeyBinding
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.networking.deriveLibp2pPeerId
import net.lapisphilosophorum.lapisnet.ratchet.DoubleRatchetSession
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundle
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyStore
import net.lapisphilosophorum.lapisnet.ratchet.X3dh
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files
import java.time.Duration
import java.time.Instant
import java.util.Collections
import kotlin.random.Random

/** Distinct 32-byte digests for distinct [seed]s - simplest possible way to mint many distinct
 * CIDs for a flood test. */
private fun testCid(seed: Int): Cid {
    val digest = ByteArray(32)
    digest[0] = (seed ushr 24).toByte()
    digest[1] = (seed ushr 16).toByte()
    digest[2] = (seed ushr 8).toByte()
    digest[3] = seed.toByte()
    return Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, digest)
}

/** A structurally-valid [DmEnvelope] blob, deliberately NOT decryptable by anything in this test -
 * mirrors `MailboxPollerTest`'s identical fixture, duplicated locally (file-private `private fun`s
 * are not shared across test files in this codebase's own established convention). */
private fun sampleEnvelopeBytes(senderIdentity: DualKeyIdentity = DualKeyIdentity.generate()): ByteArray {
    val ratchetMessage = dmSampleRatchetMessage()
    val envelope = DmEnvelope(DmMessageType.TEXT, senderIdentity.secp256k1KeyPair.publicKey, null, ratchetMessage)
    return DmEnvelopeCodec.encode(envelope)
}

private fun elapsedMillis(block: () -> Unit): Long {
    val start = System.nanoTime()
    block()
    return (System.nanoTime() - start) / 1_000_000
}

/** Security audit round 2 minor finding 4's case (d3): substitutes a FRESH, genuinely-valid X25519
 * public key (a real generated key, not garbage - passes [net.lapisphilosophorum.lapisnet.identity.X25519PublicKey]'s
 * own canonical-encoding/low-order-point checks, exactly what an attacker forging a structurally-
 * valid `ratchetPublicKey` would use) into a raw, encoded [DmEnvelope]'s embedded ratchet message
 * header, leaving EVERY other byte - `senderIdentity`, `messageNumber`, `nonce`, `ciphertext` -
 * untouched, WITH ONE deliberate exception: `previousChainLength` is also overwritten (see below).
 * Offset arithmetic mirrors [DmEnvelopeCodec]'s and `RatchetMessageCodec`'s own wire-layout doc
 * comments exactly (both re-derived here rather than imported, since the offset itself - not a codec
 * API - is the point of this helper): `DmEnvelopeCodec.DM_ENVELOPE_FIXED_PREFIX_SIZE` (178) + the
 * 2-byte `ratchetMessageLength` field = where the embedded `RatchetMessageCodec`-encoded blob starts,
 * and THAT blob's own `ratchetPublicKey` field sits at offset 6 (`magic`(4) + `version`(1) +
 * `flags`(1)), 32 bytes long, immediately followed by `previousChainLength` (4 bytes) and
 * `messageNumber` (4 bytes). `ratchetPublicKey` is the ONE field [DoubleRatchetSession.decrypt]
 * compares against its own current receiving-chain public key to decide same-chain vs.
 * DH-ratchet-step - substituting it (unlike case (d1)'s ciphertext-tail tamper, which never leaves
 * the same-chain branch, and case (d2)'s fresh-session tamper, which `isFreshHandshake` discards
 * either way) is what actually drives a forged pointer through the DH-ratchet-step commit path
 * against a LIVE cached session, the one shape the round 2 auditor found neither existing case
 * exercised.
 *
 * **Why `previousChainLength` must ALSO be overwritten (post-review fix, found by an independent
 * code review of this test after the round-2 security audit passed).** `DoubleRatchetSession.decrypt`'s
 * STEP 1 structural gate rejects `header.previousChainLength < nr` BEFORE any scratch derivation or
 * AEAD attempt ever runs - decided entirely from public data, see that method's own doc comment.
 * By the time this helper's caller forges the SECOND message on an established session, the
 * recipient has already decrypted exactly ONE prior message (the bootstrapping X3DH_INITIAL, whose
 * own zero-based `messageNumber` was 0), so its `nr` is 1. The ORIGINAL, un-forged second message's
 * `previousChainLength` is still 0 (unchanged since [DoubleRatchetSession.initializeSender] - no real
 * DH ratchet step has happened on the sender's side), so `0 < 1` trips the gate and
 * `RatchetMessageRejectedException` is thrown before the forged `ratchetPublicKey` is ever inspected
 * for a DH step - the commit path this case exists to exercise is never reached. This helper instead
 * copies the SAME bytes already sitting in the `messageNumber` field into `previousChainLength`: for
 * the second message on a chain decrypted strictly in order with nothing skipped, that field's value
 * (1, this message's own zero-based sequence number) is EXACTLY the recipient's current `nr` at the
 * moment of decryption - the precise boundary value the STEP 1 gate requires (`previousChainLength >= nr`)
 * without also exceeding [DoubleRatchetSession.MAX_SKIP]. This is not a magic-number hack: it is a
 * genuinely-crafted forged header an attacker able to observe `messageNumber` on the wire (a PUBLIC
 * field, see [RatchetMessageCodec]'s wire-layout doc comment) could construct identically - the STEP 1
 * gate is public-data-only by design, so nothing about clearing it requires secret material. */
private fun withForgedRatchetPublicKey(envelopeBytes: ByteArray): ByteArray {
    val ratchetMessageOffset = DmEnvelopeCodec.DM_ENVELOPE_FIXED_PREFIX_SIZE + 2 // + ratchetMessageLength field
    val ratchetPublicKeyOffset = ratchetMessageOffset + 6 // magic(4) + version(1) + flags(1)
    val previousChainLengthOffset = ratchetPublicKeyOffset + 32 // ratchetPublicKey
    val messageNumberOffset = previousChainLengthOffset + 4 // previousChainLength
    val forgedPublicKeyBytes = X25519KeyPair.generate().publicKey.bytes
    check(forgedPublicKeyBytes.size == 32) { "unexpected X25519 public key size: ${forgedPublicKeyBytes.size}" }
    return envelopeBytes.copyOf().also {
        forgedPublicKeyBytes.copyInto(it, ratchetPublicKeyOffset)
        // Clear DoubleRatchetSession.decrypt's STEP 1 structural gate (previousChainLength >= nr) -
        // see this function's own doc comment for why copying messageNumber's own bytes here is
        // exactly the boundary value needed, not an arbitrary tamper.
        it.copyInto(it, previousChainLengthOffset, messageNumberOffset, messageNumberOffset + 4)
    }
}

/** Builds a fresh, standalone X3DH_INITIAL [DmEnvelope] against [recipientBundle], driven directly
 * through [X3dh.initiate]/[DoubleRatchetSession.initializeSender] - mirrors
 * `DmTestFixtures.dmEstablishedPair`'s own initiator half, but exposed here so
 * [MailboxAbuseTest]'s case (d2) can build TWO independent first-contact attempts against the SAME
 * recipient bundle with EXPLICITLY DISTINCT one-time prekey ids (avoiding the ~1-in-N flakiness a
 * random pick could otherwise introduce when the SAME bundle object is reused for two attempts). */
private fun buildX3dhInitialEnvelope(
    senderIdentity: DualKeyIdentity,
    senderStore: PrekeyStore,
    recipientBundle: PrekeyBundle,
    plaintext: ByteArray,
    preferredOneTimePrekeyId: Int?,
): DmEnvelope {
    val ownBinding = EncryptionKeyBinding.create(senderIdentity.secp256k1KeyPair, senderStore.x25519IdentityPublicKey)
    val ownX25519Private = senderStore.x25519IdentityPrivateKey()
    val initiation =
        try {
            X3dh.initiate(
                initiatorIdentity = senderIdentity.secp256k1KeyPair.publicKey,
                initiatorEncryptionBinding = ownBinding,
                initiatorX25519IdentityPrivateKey = ownX25519Private,
                bundle = recipientBundle,
                preferredOneTimePrekeyId = preferredOneTimePrekeyId,
            )
        } finally {
            ownX25519Private.destroy()
        }
    val session = DoubleRatchetSession.initializeSender(initiation.session, recipientBundle.signedPrekey)
    initiation.session.destroy()
    val ratchetMessage = session.encrypt(plaintext)
    return DmEnvelope(
        DmMessageType.X3DH_INITIAL,
        senderIdentity.secp256k1KeyPair.publicKey,
        initiation.header,
        ratchetMessage,
    )
}

/**
 * The mandatory, central V0.8.5 security spec. Cases (a)-(e) mirror the plan's own numbering.
 * Case (d3) was added for security audit round 2 minor finding 4: (d1)/(d2) alone left the "forged
 * ratchetPublicKey against a live cached session" shape - the one an attacker actually uses -
 * entirely unexercised at this layer; see [withForgedRatchetPublicKey]'s own doc comment.
 */
class MailboxAbuseTest :
    FunSpec({
        test("(a) a flood of mailbox pointers is bounded by the index's two-cap structure, not grown unboundedly") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("mailbox-abuse-a"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val maxTracked = 10
                val maxPersisted = 5
                val index = MailboxPointerIndex(maxTracked = maxTracked, maxPersisted = maxPersisted)
                val localIdentity = identity.secp256k1KeyPair.publicKey
                val sender = DualKeyIdentity.generate().secp256k1KeyPair

                val floodSize = maxTracked * 3
                val pointerBytesList =
                    (0 until floodSize).map { i ->
                        val pointer =
                            MailboxPointer.create(
                                sender = sender,
                                recipientIdentity = localIdentity,
                                blobCid = testCid(i),
                                notValidAfterEpochSecond = 1_000_000L,
                                nowEpochSecond = 0,
                            )
                        MailboxPointerCodec.encode(pointer)
                    }
                pointerBytesList.forEach { bytes ->
                    MailboxGossip.onGossipMessage(bytes, from, storage, index, localIdentity)
                }

                index.size() shouldBe maxTracked

                // Prove non-persistence past the persistence cap: mint the LAST flooded pointer's
                // bytes' CID independently on a separate, never-connected node and confirm this
                // node's storage lacks it - mirrors MailEnvelopeAbuseTest's established
                // "mint CIDs on a separate never-connected node" technique. Deliberately the LAST
                // one, not the first: tryReservePersistence's cap is exhausted by the FIRST
                // maxPersisted (5) pointers in arrival order, so those five (unlike the rest of the
                // flood) genuinely ARE durably persisted - the last of `floodSize` (30) is
                // unambiguously past both caps.
                val mintingNode = LapisNode.create(DualKeyIdentity.generate())
                mintingNode.start(bootstrapPeers = emptyList())
                try {
                    val mintingStorage =
                        NabuStorage.attach(
                            mintingNode,
                            Files.createTempDirectory("mailbox-abuse-a-mint"),
                        )
                    storage.get(mintingStorage.put(pointerBytesList.last())) shouldBe null
                } finally {
                    mintingNode.stop()
                }
            } finally {
                node.stop()
            }
        }

        test(
            "(b) an adversarial flood of unfetchable mailbox pointers does not wedge MailboxPoller.pollOnce, and " +
                "a genuinely fetchable pointer mixed into the SAME flood still resolves within the same pass",
        ) {
            val nodeA = buildDmTestNode()
            val nodeB = buildDmTestNode()
            var poller: MailboxPoller? = null
            try {
                connectAndConverge(nodeA, nodeB)

                // A flood of pointers signed by throwaway identities that NEVER published a
                // PeerRecord anywhere - PeerDirectoryGossip.lookup returns null for every one of
                // them, so MailboxPoller.attemptOne returns immediately without ever calling
                // storage.get. This exercises the loop-over-many-pending-pointers dispatch path
                // itself under flood volume; it deliberately does NOT also exercise NabuStorage's
                // own per-attempt timeout at scale (a directory-registered-but-non-responding peer
                // for each of many flooded pointers would multiply this test's runtime by
                // NabuStorage.DEFAULT_TIMEOUT per pointer, impractical for a fast test suite) -
                // MailboxPollerTest's own smaller-scale case already proves ONE such pointer does
                // not block a fetchable sibling within the same pass structurally.
                repeat(200) {
                    val unreachableSender = DualKeyIdentity.generate()
                    // Arbitrary bytes, deliberately NOT a real DmEnvelope - attemptOne short-circuits
                    // at the peerDirectory.lookup(senderIdentity) == null check, well before it would
                    // ever fetch or decode this blob's actual content, so its content is irrelevant
                    // here (unlike the ONE fetchable pointer below, whose blob genuinely must decode).
                    val cid = nodeA.storage.put(Random.nextBytes(64))
                    val pointer =
                        MailboxPointer.create(
                            sender = unreachableSender.secp256k1KeyPair,
                            recipientIdentity = nodeB.identity.secp256k1KeyPair.publicKey,
                            blobCid = cid,
                            notValidAfterEpochSecond = Instant.now().epochSecond + 3600,
                        )
                    publishAndConvergeMailboxPointer(nodeA.pubsub, nodeB.mailboxGossip, pointer)
                }

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
                nodeB.mailboxGossip.pending().size shouldBe 201

                val received = Collections.synchronizedList(mutableListOf<DmEnvelope>())
                var elapsed = 0L
                poller =
                    MailboxPoller.attach(
                        nodeB.mailboxGossip,
                        nodeB.storage,
                        nodeB.peerDirectory,
                        onDecodedEnvelope = { received.add(it) },
                        pollIntervalSeconds = 3600L,
                    )
                // The synchronous initial catch-up inside attach()/start() already ran the pass
                // this test cares about - measuring a SECOND explicit pollOnce() call directly
                // gives a clean, isolated timing measurement of the loop itself.
                val pollerRef = poller
                elapsed = elapsedMillis { pollerRef.pollOnce() }

                received.size shouldBe 1
                elapsed shouldBeLessThan 10_000L
                nodeB.mailboxGossip.pending().size shouldBe 200
            } finally {
                poller?.stop()
                nodeA.stop()
                nodeB.stop()
            }
        }

        test(
            "(c) an already-delivered message, re-delivered via handleOfflineEnvelope a second time, is not delivered twice",
        ) {
            val sender = buildDmTestNode()
            val recipient = buildDmTestNode()
            try {
                connectAndConverge(sender, recipient)
                val recipientPub = recipient.identity.secp256k1KeyPair.publicKey
                val plaintext = Random.nextBytes(256)

                var deposited = false
                val depositDeadline = Instant.now().plus(Duration.ofSeconds(30))
                while (!deposited && Instant.now().isBefore(depositDeadline)) {
                    deposited = runCatching { sender.dmSessionManager.sendOffline(recipientPub, plaintext) }.isSuccess
                    if (!deposited) Thread.sleep(1000)
                }
                deposited shouldBe true

                val pointerDeadline = Instant.now().plus(Duration.ofSeconds(30))
                var pointer: MailboxPointer? = null
                while (pointer == null && Instant.now().isBefore(pointerDeadline)) {
                    pointer = recipient.mailboxGossip.pending().firstOrNull()
                    if (pointer == null) Thread.sleep(500)
                }
                val resolvedPointer = pointer.shouldNotBeNull()

                recipient.storage.registerPeerAddress(
                    sender.node
                        .listenAddresses()
                        .first()
                        .withP2P(sender.node.peerId),
                )
                val blobBytes = recipient.storage.get(resolvedPointer.blobCid, peers = setOf(sender.node.peerId))
                val resolvedBlobBytes = blobBytes.shouldNotBeNull()
                val envelope = DmEnvelopeCodec.decode(resolvedBlobBytes)

                val received = Collections.synchronizedList(mutableListOf<DmInboundMessage>())
                recipient.dmSessionManager.addInboundListener { received.add(it) }

                recipient.dmSessionManager.handleOfflineEnvelope(envelope)
                recipient.dmSessionManager.handleOfflineEnvelope(envelope) // replay - must not double-deliver

                received.size shouldBe 1
                received[0].plaintext shouldBe plaintext
            } finally {
                sender.stop()
                recipient.stop()
            }
        }

        test(
            "(d1) THE CENTRAL TEST - a tampered TEXT mailbox blob (existing session) is discarded cleanly, and a " +
                "SUBSEQUENT genuinely-valid message on the SAME session still decrypts correctly afterward",
        ) {
            val sender = buildDmTestNode()
            val recipient = buildDmTestNode(mailboxPollIntervalSeconds = 999_999_999L)
            try {
                connectAndConverge(sender, recipient)
                val recipientPub = recipient.identity.secp256k1KeyPair.publicKey
                val received = Collections.synchronizedList(mutableListOf<DmInboundMessage>())
                recipient.dmSessionManager.addInboundListener { received.add(it) }

                // Establish the session: one successful sendOffline() (X3DH_INITIAL), fetched and
                // delivered manually.
                val plaintext1 = Random.nextBytes(64)
                var deposited = false
                val depositDeadline1 = Instant.now().plus(Duration.ofSeconds(30))
                while (!deposited && Instant.now().isBefore(depositDeadline1)) {
                    deposited = runCatching { sender.dmSessionManager.sendOffline(recipientPub, plaintext1) }.isSuccess
                    if (!deposited) Thread.sleep(1000)
                }
                deposited shouldBe true
                val pointer1 = awaitPendingPointer(recipient)
                recipient.storage.registerPeerAddress(
                    sender.node
                        .listenAddresses()
                        .first()
                        .withP2P(sender.node.peerId),
                )
                val bytes1 = recipient.storage.get(pointer1.blobCid, peers = setOf(sender.node.peerId))!!
                recipient.dmSessionManager.handleOfflineEnvelope(DmEnvelopeCodec.decode(bytes1))
                received.size shouldBe 1
                received[0].plaintext shouldBe plaintext1

                // Second message: TEXT on the now-established session. Deposit it, fetch the RAW
                // bytes, TAMPER a ciphertext byte, and feed the tampered bytes.
                val plaintext2 = Random.nextBytes(64)
                sender.dmSessionManager.sendOffline(recipientPub, plaintext2)
                val pointer2 = awaitPendingPointer(recipient, excluding = setOf(pointer1))
                val bytes2 = recipient.storage.get(pointer2.blobCid, peers = setOf(sender.node.peerId))!!
                val tampered2 = bytes2.copyOf()
                tampered2[tampered2.size - 1] = (tampered2[tampered2.size - 1] + 1).toByte()
                val tamperedEnvelope2 = DmEnvelopeCodec.decode(tampered2) // structurally valid, ciphertext corrupted

                recipient.dmSessionManager.handleOfflineEnvelope(tamperedEnvelope2)
                received.size shouldBe 1 // no new delivery - the tampered attempt was discarded cleanly

                // Third message: a genuinely valid TEXT message on the SAME (untouched) session -
                // proves the tampered attempt above left the ratchet exactly where a successful
                // decrypt would have left it.
                val plaintext3 = Random.nextBytes(64)
                sender.dmSessionManager.sendOffline(recipientPub, plaintext3)
                val pointer3 = awaitPendingPointer(recipient, excluding = setOf(pointer1, pointer2))
                val bytes3 = recipient.storage.get(pointer3.blobCid, peers = setOf(sender.node.peerId))!!
                recipient.dmSessionManager.handleOfflineEnvelope(DmEnvelopeCodec.decode(bytes3))

                received.size shouldBe 2
                received[1].plaintext shouldBe plaintext3
            } finally {
                sender.stop()
                recipient.stop()
            }
        }

        test(
            "(d2) a tampered X3DH_INITIAL mailbox blob (first contact) is discarded cleanly, and a SEPARATE, " +
                "genuinely-valid first-contact attempt against the SAME recipient still establishes correctly",
        ) {
            val senderIdentity = DualKeyIdentity.generate()
            val senderStore =
                PrekeyStore.create(
                    Files.createTempDirectory("mailbox-abuse-d2-sender-prekeystore"),
                    senderIdentity,
                    oneTimePrekeyCount = 5,
                )
            val recipient = buildDmTestNode(mailboxPollIntervalSeconds = 999_999_999L)
            try {
                val received = Collections.synchronizedList(mutableListOf<DmInboundMessage>())
                recipient.dmSessionManager.addInboundListener { received.add(it) }

                recipient.publishSelf()
                val recipientBundle =
                    recipient.prekeyBundleGossip.lookup(recipient.identity.secp256k1KeyPair.publicKey)
                        ?: error("recipient's own just-announced prekey bundle must resolve locally")
                val oneTimePrekeyIds = recipientBundle.oneTimePrekeys.map { it.id }
                (oneTimePrekeyIds.size >= 2) shouldBe true

                val plaintext1 = Random.nextBytes(48)
                val envelope1 =
                    buildX3dhInitialEnvelope(
                        senderIdentity,
                        senderStore,
                        recipientBundle,
                        plaintext1,
                        oneTimePrekeyIds[0],
                    )
                val bytes1 = DmEnvelopeCodec.encode(envelope1).copyOf()
                bytes1[bytes1.size - 1] = (bytes1[bytes1.size - 1] + 1).toByte() // tamper the ciphertext tail
                val tamperedEnvelope1 = DmEnvelopeCodec.decode(bytes1)

                recipient.dmSessionManager.handleOfflineEnvelope(tamperedEnvelope1)
                received.size shouldBe 0

                val plaintext2 = Random.nextBytes(48)
                val envelope2 =
                    buildX3dhInitialEnvelope(
                        senderIdentity,
                        senderStore,
                        recipientBundle,
                        plaintext2,
                        oneTimePrekeyIds[1],
                    )
                recipient.dmSessionManager.handleOfflineEnvelope(envelope2)

                received.size shouldBe 1
                received[0].plaintext shouldBe plaintext2
                received[0].sender shouldBe senderIdentity.secp256k1KeyPair.publicKey
            } finally {
                recipient.stop()
            }
        }

        test(
            "(d3) a forged, structurally-valid ratchetPublicKey arriving through the OFFLINE path " +
                "against a LIVE cached session is discarded cleanly, and a SUBSEQUENT genuine message " +
                "on the SAME session still decrypts correctly afterward - security audit round 2 " +
                "minor finding 4: neither (d1) nor (d2) exercises the forged-DH-ratchet-step-against-" +
                "a-live-session shape an attacker actually uses",
        ) {
            val sender = buildDmTestNode()
            val recipient = buildDmTestNode(mailboxPollIntervalSeconds = 999_999_999L)
            try {
                connectAndConverge(sender, recipient)
                val recipientPub = recipient.identity.secp256k1KeyPair.publicKey
                val received = Collections.synchronizedList(mutableListOf<DmInboundMessage>())
                recipient.dmSessionManager.addInboundListener { received.add(it) }

                // Establish the session: one successful sendOffline() (X3DH_INITIAL), fetched and
                // delivered manually - identical setup to (d1).
                val plaintext1 = Random.nextBytes(64)
                var deposited = false
                val depositDeadline1 = Instant.now().plus(Duration.ofSeconds(30))
                while (!deposited && Instant.now().isBefore(depositDeadline1)) {
                    deposited = runCatching { sender.dmSessionManager.sendOffline(recipientPub, plaintext1) }.isSuccess
                    if (!deposited) Thread.sleep(1000)
                }
                deposited shouldBe true
                val pointer1 = awaitPendingPointer(recipient)
                recipient.storage.registerPeerAddress(
                    sender.node
                        .listenAddresses()
                        .first()
                        .withP2P(sender.node.peerId),
                )
                val bytes1 = recipient.storage.get(pointer1.blobCid, peers = setOf(sender.node.peerId))!!
                recipient.dmSessionManager.handleOfflineEnvelope(DmEnvelopeCodec.decode(bytes1))
                received.size shouldBe 1
                received[0].plaintext shouldBe plaintext1

                // Second message: TEXT on the now-established session. Deposit it, fetch the RAW
                // bytes, then substitute a FRESH, genuinely-valid X25519 public key into the embedded
                // ratchet header's `ratchetPublicKey` field, PLUS bump `previousChainLength` past
                // DoubleRatchetSession.decrypt's STEP 1 structural gate (see withForgedRatchetPublicKey's
                // own doc comment for exactly why and how) - the AEAD ciphertext/tag itself is
                // untouched. Unlike (d1)'s ciphertext-tail tamper, `ratchetPublicKey` is what
                // DoubleRatchetSession.decrypt inspects FIRST to decide same-chain vs. DH-ratchet-step
                // - a different, unrecognized public key forces the DH-ratchet-step branch, exactly
                // the shape a forged pointer against a LIVE cached session exercises, all the way into
                // scratch derivation and a real AEAD attempt (which then fails, as it must).
                val plaintext2 = Random.nextBytes(64)
                sender.dmSessionManager.sendOffline(recipientPub, plaintext2)
                val pointer2 = awaitPendingPointer(recipient, excluding = setOf(pointer1))
                val bytes2 = recipient.storage.get(pointer2.blobCid, peers = setOf(sender.node.peerId))!!
                val forgedBytes2 = withForgedRatchetPublicKey(bytes2)
                val forgedEnvelope2 = DmEnvelopeCodec.decode(forgedBytes2) // structurally valid - a real X25519 key

                recipient.dmSessionManager.handleOfflineEnvelope(forgedEnvelope2)
                received.size shouldBe 1 // no new delivery - the forged DH-ratchet-step attempt was discarded cleanly

                // Third message: a genuinely valid TEXT message on the SAME (untouched) session -
                // proves the forged DH-ratchet-step attempt above left the session exactly where a
                // successful decrypt would have left it, on the live cached session the offline path
                // shares with the online path.
                val plaintext3 = Random.nextBytes(64)
                sender.dmSessionManager.sendOffline(recipientPub, plaintext3)
                val pointer3 = awaitPendingPointer(recipient, excluding = setOf(pointer1, pointer2))
                val bytes3 = recipient.storage.get(pointer3.blobCid, peers = setOf(sender.node.peerId))!!
                recipient.dmSessionManager.handleOfflineEnvelope(DmEnvelopeCodec.decode(bytes3))

                received.size shouldBe 2
                received[1].plaintext shouldBe plaintext3
            } finally {
                sender.stop()
                recipient.stop()
            }
        }

        test(
            "(e) the same message delivered once online and once via a stale offline pointer is delivered exactly once",
        ) {
            val sender = buildDmTestNode()
            val recipient = buildDmTestNode(mailboxPollIntervalSeconds = 999_999_999L)
            try {
                connectAndConverge(sender, recipient)
                val recipientPub = recipient.identity.secp256k1KeyPair.publicKey
                val received = Collections.synchronizedList(mutableListOf<DmInboundMessage>())
                recipient.dmSessionManager.addInboundListener { received.add(it) }

                // Establish a real session via a real online send() first.
                val bootstrapPlaintext = Random.nextBytes(32)
                val bootstrapDeadline = Instant.now().plus(Duration.ofSeconds(30))
                while (received.isEmpty() && Instant.now().isBefore(bootstrapDeadline)) {
                    runCatching { sender.dmSessionManager.send(recipientPub, bootstrapPlaintext) }
                    Thread.sleep(1000)
                }
                received.size shouldBe 1

                // Encrypt ONE further message directly via the established session (test-visibility
                // hook, mirrors DmStreamAbuseTest's own established pattern), so the SAME encoded
                // bytes can be delivered through BOTH the online and offline paths.
                val session = sender.dmSessionManager.liveSessionForTest(recipientPub)!!
                val plaintext = Random.nextBytes(64)
                val ratchetMessage = session.encrypt(plaintext)
                val envelope =
                    DmEnvelope(DmMessageType.TEXT, sender.identity.secp256k1KeyPair.publicKey, null, ratchetMessage)
                val bytes = DmEnvelopeCodec.encode(envelope)

                // Deliver once "online" - a direct call to handleInboundEnvelope with these exact
                // bytes, simulating what DmProtocol's real stream handler would have handed it.
                recipient.dmSessionManager.handleInboundEnvelope(sender.node.peerId, bytes)
                received.size shouldBe 2

                // Deliver the IDENTICAL bytes again via the offline path.
                recipient.dmSessionManager.handleOfflineEnvelope(DmEnvelopeCodec.decode(bytes))

                received.size shouldBe 2 // no second delivery
            } finally {
                sender.stop()
                recipient.stop()
            }
        }

        test(
            "(f) a TEXT mailbox pointer that outraces its own bootstrapping X3DH_INITIAL pointer is retried, " +
                "not permanently lost - MailboxPoller must not mark it resolved on a not-yet-processable rejection",
        ) {
            val senderIdentity = DualKeyIdentity.generate()
            val senderStore =
                PrekeyStore.create(
                    Files.createTempDirectory("mailbox-abuse-f-sender-prekeystore"),
                    senderIdentity,
                    oneTimePrekeyCount = 5,
                )
            val senderNode = buildDmTestNode(senderIdentity)
            val recipient = buildDmTestNode(mailboxPollIntervalSeconds = 999_999_999L)
            var standalonePoller: MailboxPoller? = null
            try {
                connectAndConverge(senderNode, recipient)
                val recipientBundle =
                    recipient.prekeyBundleGossip.lookup(recipient.identity.secp256k1KeyPair.publicKey)
                        ?: error("recipient's own just-announced prekey bundle must resolve locally")

                // Bootstraps ONE sender-side session by hand (mirrors buildX3dhInitialEnvelope's own
                // logic, but keeps the session object around afterward - unlike that helper - so a
                // SECOND message can be encrypted on the SAME ratchet chain for the TEXT envelope
                // below).
                val ownBinding =
                    EncryptionKeyBinding.create(senderIdentity.secp256k1KeyPair, senderStore.x25519IdentityPublicKey)
                val ownX25519Private = senderStore.x25519IdentityPrivateKey()
                val initiation =
                    try {
                        X3dh.initiate(
                            initiatorIdentity = senderIdentity.secp256k1KeyPair.publicKey,
                            initiatorEncryptionBinding = ownBinding,
                            initiatorX25519IdentityPrivateKey = ownX25519Private,
                            bundle = recipientBundle,
                            preferredOneTimePrekeyId = recipientBundle.oneTimePrekeys.first().id,
                        )
                    } finally {
                        ownX25519Private.destroy()
                    }
                val session = DoubleRatchetSession.initializeSender(initiation.session, recipientBundle.signedPrekey)
                initiation.session.destroy()

                val plaintext1 = Random.nextBytes(48)
                val x3dhInitialEnvelope =
                    DmEnvelope(
                        DmMessageType.X3DH_INITIAL,
                        senderIdentity.secp256k1KeyPair.publicKey,
                        initiation.header,
                        session.encrypt(plaintext1),
                    )
                val plaintext2 = Random.nextBytes(48)
                // Message #2 on the SAME sender-side ratchet chain - exactly what a second, real
                // sendOffline() call to the same still-offline recipient would produce as a TEXT
                // envelope once the first call had already bootstrapped this session.
                val textEnvelope =
                    DmEnvelope(
                        DmMessageType.TEXT,
                        senderIdentity.secp256k1KeyPair.publicKey,
                        null,
                        session.encrypt(plaintext2),
                    )

                val x3dhInitialCid = senderNode.storage.put(DmEnvelopeCodec.encode(x3dhInitialEnvelope))
                val textCid = senderNode.storage.put(DmEnvelopeCodec.encode(textEnvelope))
                val recipientPub = recipient.identity.secp256k1KeyPair.publicKey
                val x3dhInitialPointer =
                    MailboxPointer.create(
                        sender = senderIdentity.secp256k1KeyPair,
                        recipientIdentity = recipientPub,
                        blobCid = x3dhInitialCid,
                        notValidAfterEpochSecond = Instant.now().epochSecond + 3600,
                    )
                val textPointer =
                    MailboxPointer.create(
                        sender = senderIdentity.secp256k1KeyPair,
                        recipientIdentity = recipientPub,
                        blobCid = textCid,
                        notValidAfterEpochSecond = Instant.now().epochSecond + 3600,
                    )

                // Publish the TEXT pointer FIRST, and wait for it to fully converge, BEFORE
                // publishing the X3DH_INITIAL pointer that establishes the session it needs -
                // MailboxPointerIndex is insertion-ordered (LinkedHashMap), so this deterministically
                // reproduces the exact "TEXT arrives before its own bootstrapping X3DH_INITIAL"
                // ordering `MailboxPoller.pending()`'s own doc comment warns is possible in practice
                // (gossip arrival order, not send order).
                publishAndConvergeMailboxPointer(senderNode.pubsub, recipient.mailboxGossip, textPointer)
                publishAndConvergeMailboxPointer(senderNode.pubsub, recipient.mailboxGossip, x3dhInitialPointer)
                recipient.mailboxGossip.pending().map { it.blobCid } shouldBe
                    listOf(textPointer.blobCid, x3dhInitialPointer.blobCid)

                val received = Collections.synchronizedList(mutableListOf<DmInboundMessage>())
                recipient.dmSessionManager.addInboundListener { received.add(it) }

                // MailboxPoller.attach() runs ONE synchronous pollOnce() pass over BOTH currently-
                // pending pointers, in the order established above: TEXT first (no session yet -
                // must be fetched+decoded but left PENDING, not marked resolved), then X3DH_INITIAL
                // (establishes the session and delivers plaintext1).
                standalonePoller =
                    MailboxPoller.attach(
                        recipient.mailboxGossip,
                        recipient.storage,
                        recipient.peerDirectory,
                        onDecodedEnvelope = recipient.dmSessionManager::handleOfflineEnvelope,
                        pollIntervalSeconds = 999_999_999L,
                    )

                received.size shouldBe 1
                received[0].plaintext shouldBe plaintext1
                // THE CENTRAL ASSERTION: the TEXT pointer must still be pending here. Before this
                // fix, MailboxPoller.attemptOne unconditionally called markResolved after ANY
                // non-throwing dispatch through handleOfflineEnvelope - including this exact
                // "rejected for now, not permanently" case - which would have made this assertion
                // fail (pending() would already be empty) and plaintext2 would never be delivered by
                // any later poll.
                recipient.mailboxGossip.pending().map { it.blobCid } shouldBe listOf(textPointer.blobCid)

                // A later poll pass retries the still-pending TEXT pointer - now that the session
                // exists, it succeeds.
                standalonePoller.pollOnce()

                received.size shouldBe 2
                received[1].plaintext shouldBe plaintext2
                recipient.mailboxGossip.pending().size shouldBe 0
            } finally {
                standalonePoller?.stop()
                senderNode.stop()
                recipient.stop()
            }
        }

        test(
            "(g) THE SECURITY-AUDIT-ROUND-1 REGRESSION - a replayed X3DH_INITIAL naming NO one-time " +
                "prekey does not resurrect a message after DmSessionManager restarts over the SAME " +
                "identity/session directory/prekey store",
        ) {
            // Mirrors the security audit's own probe exactly: a recipient bundle with ZERO one-time
            // prekeys, so X3dh.initiate degrades to signed-prekey-only (header.oneTimePrekeyId ==
            // null) - the one case PrekeyStore's own durable consumption tracking never runs for,
            // and, before this fix, the one case nothing durable stood in the way of a replay.
            val senderIdentity = DualKeyIdentity.generate()
            val senderStore =
                PrekeyStore.create(
                    Files.createTempDirectory("mailbox-abuse-g-sender-prekeystore"),
                    senderIdentity,
                    oneTimePrekeyCount = 5,
                )
            val recipientIdentity = DualKeyIdentity.generate()
            val recipientPrekeyStore =
                PrekeyStore.create(
                    Files.createTempDirectory("mailbox-abuse-g-recipient-prekeystore"),
                    recipientIdentity,
                    oneTimePrekeyCount = 0,
                )
            val recipientBundle =
                recipientPrekeyStore.publishBundle(recipientIdentity, Instant.now().epochSecond + 3600)
            recipientBundle.oneTimePrekeys.isEmpty() shouldBe true

            val plaintext = Random.nextBytes(48)
            val envelope = buildX3dhInitialEnvelope(senderIdentity, senderStore, recipientBundle, plaintext, null)
            envelope.x3dhInitialHeader?.oneTimePrekeyId shouldBe null

            // sessionStoreDirectory and recipientPrekeyStore are the two pieces of durable state a
            // real process restart preserves - everything else below (LapisNode/storage/pubsub/
            // directory/bundle-gossip/mailbox-gossip) is rebuilt FRESH for "boot 2", exactly like a
            // real restart would (a real restart never reuses in-memory Host/libp2p objects - only
            // files on disk survive). recipientPrekeyStore is reused as the SAME object rather than
            // reopened, which is fine: DmSessionManager.stop() never touches/closes it (its own doc
            // comment: caller-constructed, caller-stopped, exactly like peerDirectory/mailboxGossip).
            val sessionStoreDirectory = Files.createTempDirectory("mailbox-abuse-g-recipient-sessions")

            fun bootRecipient(): Triple<DmSessionManager, LapisNode, List<AutoCloseable>> {
                val node = LapisNode.create(recipientIdentity)
                node.start(bootstrapPeers = emptyList())
                val storage = NabuStorage.attach(node, Files.createTempDirectory("mailbox-abuse-g-recipient-storage"))
                val pubsub = GossipPubSub.attach(node)
                val peerDirectory = PeerDirectoryGossip.attach(pubsub, storage)
                val prekeyBundleGossip = PrekeyBundleGossip.attach(pubsub, storage)
                val mailboxGossip = MailboxGossip.attach(pubsub, storage, recipientIdentity.secp256k1KeyPair.publicKey)
                val manager =
                    DmSessionManager.attach(
                        recipientIdentity,
                        recipientPrekeyStore,
                        node,
                        peerDirectory,
                        prekeyBundleGossip,
                        mailboxGossip,
                        storage,
                        pubsub,
                        sessionStoreDirectory,
                        dmTestPassphrase(),
                        mailboxPollIntervalSeconds = 999_999_999L,
                    )
                val collaborators =
                    listOf(
                        AutoCloseable { prekeyBundleGossip.stop() },
                        AutoCloseable { peerDirectory.stop() },
                        AutoCloseable { mailboxGossip.stop() },
                    )
                return Triple(manager, node, collaborators)
            }

            var boot1: Triple<DmSessionManager, LapisNode, List<AutoCloseable>>? = null
            var boot2: Triple<DmSessionManager, LapisNode, List<AutoCloseable>>? = null
            try {
                boot1 = bootRecipient()
                val received1 = Collections.synchronizedList(mutableListOf<DmInboundMessage>())
                boot1.first.addInboundListener { received1.add(it) }

                boot1.first.handleOfflineEnvelope(envelope)
                received1.size shouldBe 1
                received1[0].plaintext shouldBe plaintext

                // "Restart": stop boot 1 entirely (which empties recentlyDeliveredDedupKeys, the
                // in-memory-only cross-path dedup cache), then boot a wholly fresh recipient
                // environment against the SAME sessionStoreDirectory/recipientPrekeyStore.
                boot1.first.stop()
                boot1.third.forEach { runCatching { it.close() } }
                runCatching { boot1.second.stop() }

                boot2 = bootRecipient()
                val received2 = Collections.synchronizedList(mutableListOf<DmInboundMessage>())
                boot2.first.addInboundListener { received2.add(it) }

                // THE CENTRAL ASSERTION: replaying the IDENTICAL X3DH_INITIAL bytes after a restart
                // must NOT resurrect the message. Before the durable per-peer ephemeral-key replay
                // registry (DmSessionManager.recordAcceptedX3dhInitialEphemeralKey), this delivered a
                // SECOND time, silently overwriting the already-advanced persisted session.
                boot2.first.handleOfflineEnvelope(envelope)
                received2.size shouldBe 0
            } finally {
                boot2?.let {
                    runCatching { it.first.stop() }
                    it.third.forEach { closeable -> runCatching { closeable.close() } }
                    runCatching { it.second.stop() }
                }
                boot1?.let {
                    runCatching { it.first.stop() }
                    it.third.forEach { closeable -> runCatching { closeable.close() } }
                    runCatching { it.second.stop() }
                }
            }
        }
    })

private fun awaitPendingPointer(
    node: DmTestNode,
    excluding: Set<MailboxPointer> = emptySet(),
    timeout: Duration = Duration.ofSeconds(30),
): MailboxPointer {
    val excludedIds = excluding.map { it.contentId().toList() }.toSet()
    val deadline = Instant.now().plus(timeout)
    while (Instant.now().isBefore(deadline)) {
        val candidate = node.mailboxGossip.pending().firstOrNull { it.contentId().toList() !in excludedIds }
        if (candidate != null) return candidate
        Thread.sleep(500)
    }
    error("no new pending mailbox pointer converged within $timeout")
}
