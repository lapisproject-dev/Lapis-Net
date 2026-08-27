package net.lapisphilosophorum.lapisnet.dm

import io.ipfs.cid.Cid
import net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.EncryptionKeyBinding
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.ratchet.DoubleRatchetSession
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyStore
import net.lapisphilosophorum.lapisnet.ratchet.RatchetMessage
import net.lapisphilosophorum.lapisnet.ratchet.X3dh
import java.nio.file.Files
import java.security.SecureRandom

/** `correct horse battery staple`, as a fresh [CharArray] every call - mirrors
 * `lapis-net-ratchet`'s own `testPassphrase()` (not reusable across modules, `internal`). */
internal fun dmTestPassphrase(): CharArray = "correct horse battery staple".toCharArray()

/** One party's full material for a real, end-to-end X3DH+ratchet handshake, built entirely through
 * this codebase's PUBLIC API (no test-only seams) - mirrors `lapis-net-ratchet`'s own
 * `RatchetTestParty`/`handshake`/`establishedPair` helpers, which this module's test sources cannot
 * see (they are `internal` to a different module's test source set). */
internal class DmTestParty(
    val identity: DualKeyIdentity = DualKeyIdentity.generate(),
    val store: PrekeyStore =
        PrekeyStore.create(
            Files.createTempDirectory("dm-test-prekeystore"),
            identity,
            oneTimePrekeyCount = 3,
        ),
) {
    val encryptionBinding: EncryptionKeyBinding =
        EncryptionKeyBinding.create(identity.secp256k1KeyPair, store.x25519IdentityPublicKey)

    fun publishBundle(notValidAfterEpochSecond: Long = 500_000L) =
        store.publishBundle(identity, notValidAfterEpochSecond, nowEpochSecond = 0)
}

/** A ready-to-use `(alice=sender, bob=receiver)` [DoubleRatchetSession] pair from a fresh, real X3DH
 * handshake between two brand-new [DmTestParty]s - mirrors `lapis-net-ratchet`'s own
 * `establishedPair()` exactly, rebuilt here since that one is `internal` to a different module. */
internal fun dmEstablishedPair(
    random: SecureRandom = SecureRandom(),
): Pair<DoubleRatchetSession, DoubleRatchetSession> {
    val alice = DmTestParty()
    val bob = DmTestParty()
    val bundle = bob.publishBundle()
    val initiation =
        X3dh.initiate(
            initiatorIdentity = alice.identity.secp256k1KeyPair.publicKey,
            initiatorEncryptionBinding = alice.encryptionBinding,
            initiatorX25519IdentityPrivateKey = alice.store.x25519IdentityPrivateKey(),
            bundle = bundle,
            nowEpochSecond = 0,
        )
    val oneTimePrekeyId = initiation.header.oneTimePrekeyId
    val consumed = oneTimePrekeyId?.let { bob.store.consumeOneTimePrekey(it) }
    val responderSecret =
        X3dh.respond(
            responderIdentity = bob.identity.secp256k1KeyPair.publicKey,
            responderEncryptionBinding = bob.encryptionBinding,
            responderX25519IdentityPrivateKey = bob.store.x25519IdentityPrivateKey(),
            responderSignedPrekeyId = bob.store.signedPrekeyId,
            responderSignedPrekeyPublicKey = bob.store.signedPrekeyPublicKey,
            responderSignedPrekeyPrivateKey = bob.store.signedPrekeyPrivateKey(),
            header = initiation.header,
            consumedOneTimePrekey = consumed,
        )
    val responderSignedPrekeyPair = X25519KeyPair.fromPrivateKeyBytes(bob.store.signedPrekeyPrivateKey().bytes)
    val aliceSession =
        DoubleRatchetSession.initializeSender(
            initiation.session,
            bob.store.signedPrekeyPublicKey,
            random,
        )
    val bobSession = DoubleRatchetSession.initializeReceiver(responderSecret, responderSignedPrekeyPair, random)
    return aliceSession to bobSession
}

/** A structurally-valid, arbitrary [RatchetMessage] - callers that only need SOME valid embedded
 * ratchet message (e.g. [DmEnvelopeCodecTest]'s truncation/tamper cases) don't need a full two-party
 * handshake fixture spelled out at every call site. */
internal fun dmSampleRatchetMessage(plaintext: ByteArray = "hello".toByteArray()): RatchetMessage {
    val (alice, _) = dmEstablishedPair()
    return alice.encrypt(plaintext)
}

/** Same domain tag `MailboxPointer`'s own private `signingDigest()` uses - re-declared here rather
 * than exposed from production code, purely as a test seam for hand-crafting a pointer that bypasses
 * [MailboxPointer.create]'s own [MailboxPointer.MAX_TTL_WINDOW_SECONDS] guard. */
private const val TEST_MAILBOX_POINTER_DOMAIN_TAG = "LapisNet:mailbox-pointer:v1"

/**
 * Builds a GENUINELY, validly signed [MailboxPointer] whose [MailboxPointer.notValidAfterEpochSecond]
 * exceeds [MailboxPointer.MAX_TTL_WINDOW_SECONDS] - the shape [MailboxPointer.create] itself refuses
 * to sign (see that companion's own doc comment), but which a hand-crafted/modified client could
 * still produce and broadcast, since neither [MailboxPointerCodec.decode] nor
 * [MailboxGossip.onGossipMessage] range-check this field. V0.8.5 hardening pass test seam - used by
 * `MailboxPointerIndexTest`/`MailboxPollerHardeningTest` to prove the caps that DO bound such a
 * pointer (index size/LRU, [MailboxPoller]'s per-pass wall-clock and per-sender budgets) still hold
 * regardless of how extreme the claimed TTL is.
 */
internal fun mailboxPointerWithUncappedTtl(
    sender: Secp256k1KeyPair,
    recipientIdentity: Secp256k1PublicKey,
    blobCid: Cid,
    notValidAfterEpochSecond: Long,
): MailboxPointer {
    val body =
        MailboxPointerCodec.encodeSignedBody(
            recipientIdentity = recipientIdentity,
            senderIdentity = sender.publicKey,
            blobCid = blobCid,
            notValidAfterEpochSecond = notValidAfterEpochSecond,
        )
    val digest = domainSeparatedDigest(TEST_MAILBOX_POINTER_DOMAIN_TAG, body)
    return MailboxPointer.fromDecoded(
        recipientIdentity = recipientIdentity,
        senderIdentity = sender.publicKey,
        blobCid = blobCid,
        notValidAfterEpochSecond = notValidAfterEpochSecond,
        signature = sender.sign(digest),
    )
}
