package net.lapisphilosophorum.lapisnet.dmonion

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.directory.AnonymousCapability
import net.lapisphilosophorum.lapisnet.directory.DirectoryReachability
import net.lapisphilosophorum.lapisnet.dm.AnonymousDmTarget
import net.lapisphilosophorum.lapisnet.dm.DmAnonymousDeliveryException
import net.lapisphilosophorum.lapisnet.dm.DmAnonymousFailure
import net.lapisphilosophorum.lapisnet.dm.DmInboundSink
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.time.Instant
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.TimeUnit

private class CollectingSink : DmInboundSink {
    val envelopes = CopyOnWriteArrayList<ByteArray>()

    override fun acceptCircuitEnvelope(envelopeBytes: ByteArray) {
        envelopes += envelopeBytes
    }

    override fun acceptSealedMailboxItem(itemBytes: ByteArray) = Unit
}

class OnionDmTransportTest :
    FunSpec({
        class Rig {
            val port = FakePort()
            val recipient = Peer()
            val bundles = HashMap<Secp256k1PublicKey, net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundle>()
            val redelivery = AnonymousMailboxRedelivery(port, tickMillis = 3_600_000)
            val transport = OnionDmTransport(port, { bundles[it] }, redelivery, sweepMillis = 30)
            val sink = CollectingSink()
            val inbound = OnionDmInboundHandler(sink)

            init {
                bundles[recipient.key] = recipient.bundle
                port.onConnect = { inbound.handleChannel(it) }
            }

            fun hidden() {
                val record = recipient.record()
                val descriptor = recipient.descriptor()
                port.reachability = { DirectoryReachability.Hidden(record, descriptor) }
            }

            fun close() {
                transport.close()
                inbound.close()
            }
        }

        fun deadline() = Instant.now().plusSeconds(10)

        test("every way a recipient can be unreachable gives the same refusal, counts it and never connects") {
            val r = Rig()
            try {
                val noDm = r.recipient.record(setOf(AnonymousCapability.MAIL))
                val cases: List<() -> DirectoryReachability> =
                    listOf(
                        { DirectoryReachability.Unknown },
                        { DirectoryReachability.Revoked },
                        {
                            DirectoryReachability.Direct(
                                net.lapisphilosophorum.lapisnet.directory.PeerRecord.create(
                                    r.recipient.identity,
                                    emptyList(),
                                    setOf(),
                                    1,
                                    Instant.now().epochSecond + 100,
                                ),
                            )
                        },
                        { DirectoryReachability.Hidden(noDm, r.recipient.descriptor()) },
                        { DirectoryReachability.HiddenDescriptorMissing(noDm) },
                    )
                for (c in cases) {
                    r.port.reachability = { c() }
                    shouldThrow<DmAnonymousDeliveryException> { r.transport.resolve(r.recipient.key) }.message shouldBe
                        "recipient-not-reachable-anonymously"
                }
                // a missing prekey bundle is the same answer
                r.hidden()
                r.bundles.clear()
                shouldThrow<DmAnonymousDeliveryException> { r.transport.resolve(r.recipient.key) }.message shouldBe
                    "recipient-not-reachable-anonymously"
                r.port.unreachable.get() shouldBe 6
                r.port.connects.get() shouldBe 0
            } finally {
                r.close()
            }
        }

        test("a runtime that is not ready refuses with anonymity-not-ready and does not look anything up") {
            val r = Rig()
            try {
                r.hidden()
                r.port.ready = false
                shouldThrow<DmAnonymousDeliveryException> { r.transport.resolve(r.recipient.key) }.failure shouldBe
                    DmAnonymousFailure.ANONYMITY_NOT_READY
                r.port.unreachable.get() shouldBe 0
            } finally {
                r.close()
            }
        }

        test("a hidden recipient resolves online, a recipient without a descriptor resolves offline-only") {
            val r = Rig()
            try {
                r.hidden()
                r.transport.resolve(r.recipient.key).online shouldBe true
                val record = r.recipient.record()
                r.port.reachability = { DirectoryReachability.HiddenDescriptorMissing(record) }
                val t = r.transport.resolve(r.recipient.key)
                t.online shouldBe false
                t.sealingKey shouldBe r.recipient.bundle.x25519IdentityKey
                t.toString() shouldBe "AnonymousDmTarget(REDACTED)"
            } finally {
                r.close()
            }
        }

        test("online delivery sends the envelope, gets the ack and reuses the stream for the same address") {
            val r = Rig()
            try {
                r.hidden()
                val target = r.transport.resolve(r.recipient.key)
                val e1 = ByteArray(4_000) { 1 }
                val e2 = ByteArray(100) { 2 }
                r.transport.deliverOnline(target, e1, deadline()) shouldBe true
                r.transport.deliverOnline(target, e2, deadline()) shouldBe true
                r.port.connects.get() shouldBe 1
                r.transport.openStreams() shouldBe 1
                val deadlineAt = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
                while (r.sink.envelopes.size < 2 && System.nanoTime() < deadlineAt) Thread.sleep(10)
                r.sink.envelopes.map { it.size } shouldBe listOf(4_000, 100)
            } finally {
                r.close()
            }
        }

        test("a missing ack, a failed connect and an oversize envelope are reported as failures, never thrown") {
            val r = Rig()
            try {
                r.hidden()
                val target = r.transport.resolve(r.recipient.key)
                r.port.onConnect = { server -> server.dropSends = true } // the receiver never answers
                r.transport.deliverOnline(target, ByteArray(10) { 1 }, Instant.now().plusMillis(300)) shouldBe false
                r.transport.openStreams() shouldBe 0
                r.port.connectFails = true
                r.transport.deliverOnline(target, ByteArray(10) { 1 }, deadline()) shouldBe false
                r.transport.deliverOnline(target, ByteArray(70_000), deadline()) shouldBe false
            } finally {
                r.close()
            }
        }

        test("at most two streams are cached, an idle stream is closed, close() leaves nothing open") {
            val r = Rig()
            try {
                val targets =
                    List(3) {
                        val p = Peer()
                        r.bundles[p.key] = p.bundle
                        val record = p.record()
                        val descriptor = p.descriptor()
                        r.port.reachability = { DirectoryReachability.Hidden(record, descriptor) }
                        r.transport.resolve(p.key)
                    }
                targets.forEach { r.transport.deliverOnline(it, ByteArray(10) { 1 }, deadline()) shouldBe true }
                (r.transport.openStreams() <= 2) shouldBe true
                r.port.clientEnds.count { !it.isClosed } shouldBe r.transport.openStreams()
                r.transport.close()
                r.transport.openStreams() shouldBe 0
                r.port.clientEnds.all { it.isClosed } shouldBe true
            } finally {
                r.close()
            }
        }

        test("an idle stream is closed after the idle time") {
            val port = FakePort()
            val recipient = Peer()
            val redelivery = AnonymousMailboxRedelivery(port, tickMillis = 3_600_000)
            val inbound = OnionDmInboundHandler(CollectingSink())
            port.onConnect = { inbound.handleChannel(it) }
            val record = recipient.record()
            val descriptor = recipient.descriptor()
            port.reachability = { DirectoryReachability.Hidden(record, descriptor) }
            val transport = OnionDmTransport(port, { recipient.bundle }, redelivery, idleMillis = 200, sweepMillis = 30)
            try {
                val target: AnonymousDmTarget = transport.resolve(recipient.key)
                transport.deliverOnline(target, ByteArray(10) { 1 }, deadline()) shouldBe true
                val end = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
                while (transport.openStreams() > 0 && System.nanoTime() < end) Thread.sleep(20)
                transport.openStreams() shouldBe 0
            } finally {
                transport.close()
                inbound.close()
            }
        }

        test("depositOffline queues the same envelope for announcement") {
            val r = Rig()
            try {
                r.hidden()
                val target = r.transport.resolve(r.recipient.key)
                r.transport.depositOffline(target, ByteArray(500) { 3 }, Instant.now().epochSecond + 3600)
                r.redelivery.pendingCount() shouldBe 1
            } finally {
                r.close()
            }
        }
    })
