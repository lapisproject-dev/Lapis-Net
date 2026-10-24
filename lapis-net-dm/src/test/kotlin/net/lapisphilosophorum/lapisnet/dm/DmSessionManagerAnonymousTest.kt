package net.lapisphilosophorum.lapisnet.dm

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.libp2p.core.pubsub.ValidationResult
import net.lapisphilosophorum.lapisnet.directory.PrekeyBundleGossip
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.EncryptionKeyBinding
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.identity.X25519PrivateKey
import net.lapisphilosophorum.lapisnet.ratchet.X3dhPreKeyMessageHeader
import java.security.SecureRandom
import java.time.Instant
import java.util.Collections

/** Fake transport: resolution and online delivery are scripted, deposited bytes are recorded. */
private class FakeAnonymousTransport(
    private val sealingKeyFor: (Secp256k1PublicKey) -> net.lapisphilosophorum.lapisnet.identity.X25519PublicKey,
) : AnonymousDmTransport {
    @Volatile var resolveFailure: DmAnonymousFailure? = null

    @Volatile var online: Boolean = true

    @Volatile var onlineSucceeds: Boolean = true
    val onlineBytes: MutableList<ByteArray> = Collections.synchronizedList(mutableListOf())
    val depositedBytes: MutableList<ByteArray> = Collections.synchronizedList(mutableListOf())

    override fun resolve(recipient: Secp256k1PublicKey): AnonymousDmTarget {
        resolveFailure?.let { throw DmAnonymousDeliveryException(it) }
        return AnonymousDmTarget(recipient, sealingKeyFor(recipient), null, online)
    }

    override fun deliverOnline(
        target: AnonymousDmTarget,
        envelopeBytes: ByteArray,
        deadline: Instant,
    ): Boolean {
        if (!onlineSucceeds) return false
        onlineBytes.add(envelopeBytes)
        return true
    }

    override fun depositOffline(
        target: AnonymousDmTarget,
        envelopeBytes: ByteArray,
        notValidAfterEpochSecond: Long,
    ) {
        depositedBytes.add(envelopeBytes)
    }

    override fun close() = Unit
}

class DmSessionManagerAnonymousTest :
    FunSpec({
        fun nodePair(): Triple<DmTestNode, DmTestNode, FakeAnonymousTransport> {
            val a = buildDmTestNode(anonymous = true)
            val b = buildDmTestNode(anonymous = true)
            connectAndConverge(a, b)
            val transport =
                FakeAnonymousTransport { who ->
                    requireNotNull(a.prekeyBundleGossip.lookup(who)).x25519IdentityKey
                }
            return Triple(a, b, transport)
        }

        test("a resolve failure leaves no session behind and no transport call (no phantom session)") {
            val (a, b, transport) = nodePair()
            try {
                a.dmSessionManager.installAnonymousTransport(transport)
                transport.resolveFailure = DmAnonymousFailure.RECIPIENT_NOT_REACHABLE_ANONYMOUSLY
                val bPub = b.identity.secp256k1KeyPair.publicKey
                val e =
                    shouldThrow<DmAnonymousDeliveryException> { a.dmSessionManager.send(bPub, DmContent(body = "x")) }
                e.message shouldBe "recipient-not-reachable-anonymously"
                a.dmSessionManager.liveSessionForTest(bPub) shouldBe null
                transport.onlineBytes shouldHaveSize 0
                transport.depositedBytes shouldHaveSize 0
            } finally {
                a.stop()
                b.stop()
            }
        }

        test("without an installed transport a send fails with anonymity-not-ready and never falls back") {
            val (a, b, _) = nodePair()
            try {
                val bPub = b.identity.secp256k1KeyPair.publicKey
                shouldThrow<DmAnonymousDeliveryException> {
                    a.dmSessionManager.sendAuto(bPub, DmContent(body = "x"))
                }.failure shouldBe DmAnonymousFailure.ANONYMITY_NOT_READY
                a.dmSessionManager.liveSessionForTest(bPub) shouldBe null
            } finally {
                a.stop()
                b.stop()
            }
        }

        test("an oversized message is refused before any session work") {
            val (a, b, transport) = nodePair()
            try {
                a.dmSessionManager.installAnonymousTransport(transport)
                val bPub = b.identity.secp256k1KeyPair.publicKey
                shouldThrow<DmAnonymousDeliveryException> {
                    a.dmSessionManager.sendAuto(bPub, DmContent(body = "x".repeat(6_000)))
                }.failure shouldBe DmAnonymousFailure.MESSAGE_TOO_LARGE
                a.dmSessionManager.liveSessionForTest(bPub) shouldBe null
            } finally {
                a.stop()
                b.stop()
            }
        }

        test("a message at the size limit fits a sealed item (first contact and follow-up)") {
            val (a, b, transport) = nodePair()
            try {
                a.dmSessionManager.installAnonymousTransport(transport)
                val bPub = b.identity.secp256k1KeyPair.publicKey
                val limit = SealedMailboxItemCodec.MAX_ENVELOPE_BYTES - SealedMailboxItemCodec.ENVELOPE_OVERHEAD_BYTES
                // Find the largest body whose encoded content still fits the limit.
                var body = "y".repeat(limit)
                while (DmContentCodec.encode(DmContent(body = body)).size > limit) body = body.dropLast(1)
                transport.onlineSucceeds = false
                a.dmSessionManager.sendAuto(bPub, DmContent(body = body)) shouldBe DmSendOutcome.QUEUED_FOR_PICKUP
                transport.depositedBytes shouldHaveSize 1
                (transport.depositedBytes[0].size <= SealedMailboxItemCodec.MAX_ENVELOPE_BYTES) shouldBe true
            } finally {
                a.stop()
                b.stop()
            }
        }

        test("online failure deposits the SAME envelope offline, without re-encrypting; recipient gets it once") {
            val (a, b, transport) = nodePair()
            try {
                a.dmSessionManager.installAnonymousTransport(transport)
                val received = Collections.synchronizedList(mutableListOf<DmInboundMessage>())
                b.dmSessionManager.addInboundListener { received.add(it) }
                val bPub = b.identity.secp256k1KeyPair.publicKey

                transport.onlineSucceeds = false
                a.dmSessionManager.sendAuto(bPub, DmContent(body = "queued")) shouldBe DmSendOutcome.QUEUED_FOR_PICKUP
                transport.onlineBytes shouldHaveSize 0
                transport.depositedBytes shouldHaveSize 1

                // Seal for B exactly as the adapter would and hand it to B's sealed-item door, twice.
                val bPrivate: X25519PrivateKey = b.prekeyStore.x25519IdentityPrivateKey()
                val sealingKey = requireNotNull(a.prekeyBundleGossip.lookup(bPub)).x25519IdentityKey
                val sink = b.dmSessionManager.inboundSink()
                repeat(2) {
                    sink.acceptSealedMailboxItem(
                        SealedMailboxItemCodec.seal(
                            transport.depositedBytes[0],
                            sealingKey,
                            Instant.now().epochSecond + 3600,
                        ),
                    )
                }
                bPrivate.destroy()
                received shouldHaveSize 1
                received[0].content.body shouldBe "queued"
            } finally {
                a.stop()
                b.stop()
            }
        }

        test("circuit door delivers once, replay is deduplicated, a CALL_SIGNAL is rejected") {
            val (a, b, transport) = nodePair()
            try {
                a.dmSessionManager.installAnonymousTransport(transport)
                val received = Collections.synchronizedList(mutableListOf<DmInboundMessage>())
                b.dmSessionManager.addInboundListener { received.add(it) }
                val calls = Collections.synchronizedList(mutableListOf<DmInboundCallSignal>())
                b.dmSessionManager.addCallSignalListener { calls.add(it) }
                val bPub = b.identity.secp256k1KeyPair.publicKey

                a.dmSessionManager.sendAuto(bPub, DmContent(body = "online")) shouldBe DmSendOutcome.SENT_ONLINE
                val bytes = transport.onlineBytes[0]
                val sink = b.dmSessionManager.inboundSink()
                sink.acceptCircuitEnvelope(bytes)
                sink.acceptCircuitEnvelope(bytes)
                sink.acceptCircuitEnvelope(ByteArray(40))
                received shouldHaveSize 1
                received[0].content.body shouldBe "online"

                // A CALL_SIGNAL envelope (structurally valid: same sender, ratchet message of the
                // real envelope, no X3DH header) must be dropped at BOTH inbound doors before any
                // decryption, and must never reach the call-signal listener or the message listener.
                a.dmSessionManager.routeMode() shouldBe DmRoute.CIRCUIT
                // The ratchet message must be FRESH (really encrypted under the A->B session, never
                // delivered to B): a replayed one would be absorbed by the dedup check regardless of
                // the CALL_SIGNAL rejection and the test would pass vacuously.
                a.dmSessionManager.sendAuto(bPub, DmContent(body = "fresh")) shouldBe DmSendOutcome.SENT_ONLINE
                transport.onlineBytes.size shouldBe 2
                val real = DmEnvelopeCodec.decode(transport.onlineBytes[1])
                val callBytes =
                    DmEnvelopeCodec.encode(
                        DmEnvelope(DmMessageType.CALL_SIGNAL, real.senderIdentity, null, real.ratchetMessage),
                    )
                sink.acceptCircuitEnvelope(callBytes)
                val bPrivate = b.prekeyStore.x25519IdentityPrivateKey()
                val sealingKey = requireNotNull(a.prekeyBundleGossip.lookup(bPub)).x25519IdentityKey
                sink.acceptSealedMailboxItem(
                    SealedMailboxItemCodec.seal(callBytes, sealingKey, Instant.now().epochSecond + 3600),
                )
                bPrivate.destroy()
                calls shouldHaveSize 0
                received shouldHaveSize 1
            } finally {
                a.stop()
                b.stop()
            }
        }

        test("no direct DM protocol, no direct mailbox pointer, no dht outbox entry in anonymity mode") {
            val (a, b, transport) = nodePair()
            try {
                a.dmSessionManager.installAnonymousTransport(transport)
                transport.onlineSucceeds = false
                val bPub = b.identity.secp256k1KeyPair.publicKey
                val pointersSeen = Collections.synchronizedList(mutableListOf<Any>())
                b.mailboxGossip.pending().let { pointersSeen.addAll(it) }
                a.dmSessionManager.sendAuto(bPub, DmContent(body = "z")) shouldBe DmSendOutcome.QUEUED_FOR_PICKUP
                Thread.sleep(1500)
                // The direct mailbox topic must stay silent: nothing pending at B.
                b.mailboxGossip.pending() shouldHaveSize 0

                // The libp2p DM protocol is not registered: a dial of /lapis/dm/1.x on A fails.
                val unsupported =
                    runCatching {
                        DmProtocol
                            .attach(b.node) { _, _ -> }
                            .let { p ->
                                val promise = p.dial(a.node, a.node.peerId, *a.node.listenAddresses().toTypedArray())
                                promise.controller.get(5, java.util.concurrent.TimeUnit.SECONDS)
                            }
                    }.isFailure
                unsupported shouldBe true
            } finally {
                a.stop()
                b.stop()
            }
        }

        test("sendCallSignal is refused up front in anonymity mode and consumes no ratchet step") {
            val (a, b, transport) = nodePair()
            try {
                a.dmSessionManager.installAnonymousTransport(transport)
                val bPub = b.identity.secp256k1KeyPair.publicKey
                a.dmSessionManager.sendAuto(bPub, DmContent(body = "hi")) shouldBe DmSendOutcome.SENT_ONLINE
                val e =
                    shouldThrow<DmSessionException> {
                        a.dmSessionManager.sendCallSignal(bPub, ByteArray(4), marksAcceptance = false)
                    }
                e.message shouldBe "call signalling is not available in anonymity mode"
                transport.onlineBytes shouldHaveSize 1
            } finally {
                a.stop()
                b.stop()
            }
        }

        test("installAnonymousTransport is single-shot and rejected on a direct-mode manager") {
            val direct = buildDmTestNode()
            val anon = buildDmTestNode(anonymous = true)
            try {
                val t = FakeAnonymousTransport { error("unused") }
                shouldThrow<IllegalStateException> { direct.dmSessionManager.installAnonymousTransport(t) }
                shouldThrow<IllegalStateException> { direct.dmSessionManager.inboundSink() }
                anon.dmSessionManager.installAnonymousTransport(t)
                shouldThrow<IllegalStateException> { anon.dmSessionManager.installAnonymousTransport(t) }
                direct.dmSessionManager.routeMode() shouldBe DmRoute.DIRECT
            } finally {
                direct.stop()
                anon.stop()
            }
        }

        test(
            "draining the one-time prekey pool below the watermark refills it locally and never publishes " +
                "on the prekey-bundle gossip topic in anonymity mode",
        ) {
            val victim = buildDmTestNode(anonymous = true)
            val observer = buildDmTestNode()
            try {
                connectAndConverge(victim, observer)
                val leaked = Collections.synchronizedList(mutableListOf<ByteArray>())
                observer.pubsub.subscribe(PrekeyBundleGossip.PREKEY_BUNDLE_GOSSIP_TOPIC) { bytes, _ ->
                    leaked.add(bytes)
                    ValidationResult.Valid
                }
                Thread.sleep(1_000)
                val random = SecureRandom()
                val initialCount = victim.prekeyStore.availableOneTimePrekeyCount()
                victim.prekeyStore.availableOneTimePrekeyIds().forEach { targetId ->
                    val attacker = DualKeyIdentity.generate()
                    val attackerX25519 = X25519KeyPair.generate(random)
                    val header =
                        X3dhPreKeyMessageHeader(
                            initiatorIdentity = attacker.secp256k1KeyPair.publicKey,
                            initiatorEncryptionBinding =
                                EncryptionKeyBinding.create(attacker.secp256k1KeyPair, attackerX25519.publicKey),
                            ephemeralPublicKey = X25519KeyPair.generate(random).publicKey,
                            signedPrekeyId = victim.prekeyStore.signedPrekeyId,
                            oneTimePrekeyId = targetId,
                        )
                    val envelope =
                        DmEnvelope(
                            DmMessageType.X3DH_INITIAL,
                            attacker.secp256k1KeyPair.publicKey,
                            header,
                            dmSampleRatchetMessage(),
                        )
                    victim.dmSessionManager.inboundSink().acceptCircuitEnvelope(DmEnvelopeCodec.encode(envelope))
                }
                val deadline = System.currentTimeMillis() + 20_000
                while (victim.prekeyStore.availableOneTimePrekeyCount() <= initialCount &&
                    System.currentTimeMillis() < deadline
                ) {
                    Thread.sleep(200)
                }
                // the pool really was refilled (so the replenishment path ran) ...
                (victim.prekeyStore.availableOneTimePrekeyCount() > initialCount) shouldBe true
                // ... and gossip had time to deliver anything that would have been published
                Thread.sleep(2_000)
                leaked shouldHaveSize 0
            } finally {
                victim.stop()
                observer.stop()
            }
        }
    })
