package net.lapisphilosophorum.lapisnet.mailonion

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.directory.AnonymousCapability
import net.lapisphilosophorum.lapisnet.directory.DirectoryReachability
import net.lapisphilosophorum.lapisnet.dmonion.AnonymousMailboxRedelivery
import net.lapisphilosophorum.lapisnet.dmonion.FakePort
import net.lapisphilosophorum.lapisnet.dmonion.Peer
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.mail.AnonymousMailSizeClass
import net.lapisphilosophorum.lapisnet.mail.AnonymousMailSizing
import net.lapisphilosophorum.lapisnet.mail.MailAnonymousDeliveryException
import net.lapisphilosophorum.lapisnet.mail.MailAnonymousFailure
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundle
import java.time.Duration
import java.time.Instant

class OnionMailTransportTest :
    FunSpec({
        class Rig(
            deliveryTimeout: Duration = Duration.ofSeconds(5),
        ) {
            val port = FakeMailPort()
            val dmPort = FakePort()
            val me = Peer()
            val recipient = Peer()
            val bundles = HashMap<Secp256k1PublicKey, PrekeyBundle>()
            val redelivery = AnonymousMailboxRedelivery(dmPort, tickMillis = 3_600_000)
            val retry = OnionMailRetryQueue(tickMillis = 3_600_000)
            val transport =
                OnionMailTransport(
                    port,
                    me.key,
                    { bundles[it] },
                    redelivery,
                    retry,
                    deliveryTimeout = deliveryTimeout,
                )
            val sink = CollectingMailSink()
            val inbound = OnionMailInboundHandler(sink)
            val frame = ByteArray(400) { (it % 200).toByte() }

            init {
                bundles[recipient.key] = recipient.bundle
                port.onConnect = { inbound.handleChannel(it) }
            }

            fun hidden(peer: Peer = recipient) {
                val record = peer.record(setOf(AnonymousCapability.DM, AnonymousCapability.MAIL))
                val descriptor = peer.descriptor()
                port.reachability =
                    {
                        if (it ==
                            peer.key
                        ) {
                            DirectoryReachability.Hidden(record, descriptor)
                        } else {
                            DirectoryReachability.Unknown
                        }
                    }
            }

            fun close() {
                transport.close()
                inbound.close()
            }
        }

        test("every way a recipient can be unreachable gives the same refusal, counts it and never connects") {
            val r = Rig()
            try {
                val noMail = r.recipient.record(setOf(AnonymousCapability.DM))
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
                        { DirectoryReachability.Hidden(noMail, r.recipient.descriptor()) },
                        { DirectoryReachability.HiddenDescriptorMissing(noMail) },
                    )
                for (c in cases) {
                    r.port.reachability = { c() }
                    shouldThrow<MailAnonymousDeliveryException> {
                        r.transport.preflight(listOf(r.recipient.key), 100, emptyList())
                    }.message shouldBe "recipient-not-reachable-anonymously"
                }
                // a missing prekey bundle is the same answer
                r.hidden()
                r.bundles.clear()
                shouldThrow<MailAnonymousDeliveryException> {
                    r.transport.preflight(listOf(r.recipient.key), 100, emptyList())
                }.message shouldBe "recipient-not-reachable-anonymously"
                r.port.unreachable.get() shouldBe 6
                r.port.connects.get() shouldBe 0
            } finally {
                r.close()
            }
        }

        test("a runtime that is not ready refuses with anonymity-not-ready and looks nothing up") {
            val r = Rig()
            try {
                r.hidden()
                r.port.ready = false
                shouldThrow<MailAnonymousDeliveryException> {
                    r.transport.preflight(listOf(r.recipient.key), 100, emptyList())
                }.failure shouldBe MailAnonymousFailure.ANONYMITY_NOT_READY
                r.port.unreachable.get() shouldBe 0
            } finally {
                r.close()
            }
        }

        test("an oversize bundle is refused by the pre-flight and no circuit is built") {
            val r = Rig()
            try {
                r.hidden()
                shouldThrow<MailAnonymousDeliveryException> {
                    r.transport.preflight(
                        listOf(r.recipient.key),
                        100,
                        listOf(AnonymousMailSizing.MAX_CIRCUIT_BUNDLE_BYTES),
                    )
                }.failure shouldBe MailAnonymousFailure.MAIL_TOO_LARGE_ANONYMOUS
                r.port.connects.get() shouldBe 0
                r.port.unreachable.get() shouldBe 0
            } finally {
                r.close()
            }
        }

        test("multi-recipient is all or nothing and does not say which recipient failed") {
            val r = Rig()
            try {
                r.hidden()
                val stranger = DualKeyIdentity.generate().secp256k1KeyPair.publicKey
                val ex =
                    shouldThrow<MailAnonymousDeliveryException> {
                        r.transport.preflight(listOf(r.recipient.key, stranger), 100, emptyList())
                    }
                ex.message shouldBe "recipient-not-reachable-anonymously"
                r.port.connects.get() shouldBe 0
            } finally {
                r.close()
            }
        }

        test("an online delivery is acknowledged, reaches the sink and queues nothing; the circuit is closed") {
            val r = Rig()
            try {
                r.hidden()
                val sizeClass = r.transport.preflight(listOf(r.recipient.key), r.frame.size, emptyList())
                sizeClass shouldBe AnonymousMailSizeClass.INLINE
                r.transport.deliver(listOf(r.recipient.key), r.frame, emptyList(), sizeClass)
                waitFor { r.sink.received.size == 1 } shouldBe true
                r.sink.received
                    .single()
                    .frame
                    .contentEquals(r.frame) shouldBe true
                waitFor { r.port.clientEnds.all { it.isClosed } } shouldBe true
                r.redelivery.pendingCount() shouldBe 0
                r.retry.pendingCount() shouldBe 0
                r.port.connects.get() shouldBe 1
            } finally {
                r.close()
            }
        }

        test("a CIRCUIT bundle carries its blobs in band") {
            val r = Rig()
            try {
                r.hidden()
                val blob = ByteArray(5000) { (it % 97).toByte() }
                val sizeClass = r.transport.preflight(listOf(r.recipient.key), r.frame.size, listOf(blob.size))
                sizeClass shouldBe AnonymousMailSizeClass.CIRCUIT
                r.transport.deliver(listOf(r.recipient.key), r.frame, listOf(blob), sizeClass)
                waitFor { r.sink.received.size == 1 } shouldBe true
                r.sink.received
                    .single()
                    .blobs
                    .single()
                    .contentEquals(blob) shouldBe true
                r.retry.pendingCount() shouldBe 0
            } finally {
                r.close()
            }
        }

        test("each delivery builds its own circuit (no stream cache)") {
            val r = Rig()
            try {
                r.hidden()
                repeat(2) {
                    r.transport.deliver(
                        listOf(r.recipient.key),
                        r.frame.copyOf().also { f ->
                            f[0] = it.toByte()
                        },
                        emptyList(),
                        AnonymousMailSizeClass.INLINE,
                    )
                }
                waitFor { r.sink.received.size == 2 } shouldBe true
                r.port.connects.get() shouldBe 2
            } finally {
                r.close()
            }
        }

        test(
            "without an acknowledgement a small mail is handed to the sealed-item redelivery, a bundle to the retry queue",
        ) {
            val r = Rig(deliveryTimeout = Duration.ofMillis(300))
            try {
                r.hidden()
                r.port.onConnect = { } // nobody answers
                r.transport.deliver(listOf(r.recipient.key), r.frame, emptyList(), AnonymousMailSizeClass.INLINE)
                waitFor { r.redelivery.pendingCount() == 1 } shouldBe true
                r.retry.pendingCount() shouldBe 0
                r.transport.deliver(
                    listOf(r.recipient.key),
                    r.frame,
                    listOf(ByteArray(10)),
                    AnonymousMailSizeClass.CIRCUIT,
                )
                waitFor { r.retry.pendingCount() == 1 } shouldBe true
                // the abandoned circuits were closed
                waitFor { r.port.clientEnds.all { it.isClosed } } shouldBe true
            } finally {
                r.close()
            }
        }

        test("a failing connect queues instead of failing the call") {
            val r = Rig()
            try {
                r.hidden()
                r.port.connectFails = true
                r.transport.deliver(listOf(r.recipient.key), r.frame, emptyList(), AnonymousMailSizeClass.INLINE)
                waitFor { r.redelivery.pendingCount() == 1 } shouldBe true
            } finally {
                r.close()
            }
        }

        test("a recipient without a descriptor is queued directly without any connect") {
            val r = Rig()
            try {
                val record = r.recipient.record(setOf(AnonymousCapability.MAIL))
                r.port.reachability = { DirectoryReachability.HiddenDescriptorMissing(record) }
                r.transport.deliver(listOf(r.recipient.key), r.frame, emptyList(), AnonymousMailSizeClass.INLINE)
                waitFor { r.redelivery.pendingCount() == 1 } shouldBe true
                r.transport.deliver(
                    listOf(r.recipient.key),
                    r.frame,
                    listOf(ByteArray(3)),
                    AnonymousMailSizeClass.CIRCUIT,
                )
                waitFor { r.retry.pendingCount() == 1 } shouldBe true
                r.port.connects.get() shouldBe 0
            } finally {
                r.close()
            }
        }

        test("the sender itself is skipped as a recipient: no lookup, no circuit, nothing queued") {
            val r = Rig()
            try {
                r.transport.preflight(listOf(r.me.key), 100, emptyList()) shouldBe AnonymousMailSizeClass.INLINE
                r.transport.deliver(listOf(r.me.key), r.frame, emptyList(), AnonymousMailSizeClass.INLINE)
                Thread.sleep(150)
                r.port.connects.get() shouldBe 0
                r.redelivery.pendingCount() shouldBe 0
                r.retry.pendingCount() shouldBe 0
            } finally {
                r.close()
            }
        }

        test("INLINE mail with attachments is refused at deliver, and a closed transport refuses everything") {
            val r = Rig()
            try {
                shouldThrow<IllegalArgumentException> {
                    r.transport.deliver(
                        listOf(r.recipient.key),
                        r.frame,
                        listOf(ByteArray(1)),
                        AnonymousMailSizeClass.INLINE,
                    )
                }
                r.transport.close()
                shouldThrow<MailAnonymousDeliveryException> {
                    r.transport.preflight(listOf(r.recipient.key), 100, emptyList())
                }.failure shouldBe MailAnonymousFailure.ANONYMITY_NOT_READY
                r.transport.toString() shouldBe "OnionMailTransport(REDACTED)"
            } finally {
                r.close()
            }
        }
    })
