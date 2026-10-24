@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.mailonion

import net.lapisphilosophorum.lapisnet.directory.AnonymousCapability
import net.lapisphilosophorum.lapisnet.dmonion.DmOnionNode
import net.lapisphilosophorum.lapisnet.dmonion.FrameChannel
import net.lapisphilosophorum.lapisnet.dmonion.RelayHost
import net.lapisphilosophorum.lapisnet.dmonion.SyntheticLocator
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.mail.HybridEcies
import net.lapisphilosophorum.lapisnet.mail.InboxAnonymousSink
import net.lapisphilosophorum.lapisnet.mail.InboxGossip
import net.lapisphilosophorum.lapisnet.mail.InboxMessage
import net.lapisphilosophorum.lapisnet.mail.InboxPayload
import net.lapisphilosophorum.lapisnet.mail.MailAcceptanceCheck
import net.lapisphilosophorum.lapisnet.mail.MailSender
import net.lapisphilosophorum.lapisnet.mail.MessageBody
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptor
import net.lapisphilosophorum.lapisnet.onionwire.OnionServiceApp
import net.lapisphilosophorum.lapisnet.trust.TrustGraph
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList

/** Wraps the production port: counts connects and records the plaintext chunks handed to rendezvous streams. */
class RecordingMailPort(
    private val delegate: OnionMailRuntimePort,
) : OnionMailRuntimePort by delegate {
    val frames = CopyOnWriteArrayList<ByteArray>()
    val connects =
        java.util.concurrent.atomic
            .AtomicInteger()

    override fun connect(
        descriptor: OnionServiceDescriptor,
        timeout: Duration,
    ): CompletableFuture<FrameChannel> {
        connects.incrementAndGet()
        return delegate.connect(descriptor, timeout).thenApply { inner ->
            object : FrameChannel by inner {
                override fun send(data: ByteArray): Boolean {
                    frames += data.copyOf()
                    return inner.send(data)
                }
            }
        }
    }
}

/** The mail stack of one anonymity-mode node, rebuilt at every (re)start of the node, like [BrowserServer] does. */
class MailStack(
    val n: DmOnionNode,
) {
    val contacts: MutableSet<Secp256k1PublicKey> = ConcurrentHashMap.newKeySet()
    val port = RecordingMailPort(AnonymityRuntimeMailPort(n.runtime))
    val inbox: InboxGossip = InboxGossip.attachAnonymous(n.pubsub, n.storage, n.key, null)
    val sender = MailSender(n.pubsub, n.storage, anonymous = true)
    val retry = OnionMailRetryQueue(tickMillis = 500, intervalMillis = 4_000, jitterMillis = 500)
    val transport =
        OnionMailTransport(
            port,
            n.key,
            { id -> n.bundleGossip.lookup(id)?.takeIf { it.identity == id } },
            n.redelivery,
            retry,
            connectTimeout = Duration.ofSeconds(25),
            deliveryTimeout = Duration.ofSeconds(40),
        )
    val sink =
        InboxAnonymousSink(inbox, n.storage) { message ->
            val sealed = (message.payload as? InboxPayload.Sealed)?.sealedBody
            sealed?.let {
                runCatching {
                    HybridEcies
                        .open(message.envelope, it, n.identity.secp256k1KeyPair)
                        .attachments
                        .map { a -> a.cid }
                        .toSet()
                }.getOrNull()
            }
        }
    val handler = OnionMailInboundHandler(sink)
    val subscriber: AnonymousMailSubscriber

    init {
        sender.installAnonymousTransport(transport)
        n.runtime.serviceRouter().register(OnionServiceApp.MAIL, handler::handle)
        subscriber =
            AnonymousMailSubscriber.attach(
                checkNotNull(n.runtime.mailboxGossip()),
                { n.prekeys.x25519IdentityPrivateKey() },
                sink,
            )
    }

    fun requireVeritasPath() {
        inbox.updateAcceptanceCheck(
            MailAcceptanceCheck(
                gates = listOf(net.lapisphilosophorum.lapisnet.mail.MailAcceptanceGate.VeritasPath),
                trustGraph = TrustGraph.fromEdges(emptyList()),
                karmaScoreOf = { 0.0 },
                isAcceptedContact = { it in contacts },
            ),
        )
    }

    fun openMessage(message: InboxMessage): MessageBody =
        HybridEcies.open(
            message.envelope,
            (message.payload as InboxPayload.Sealed).sealedBody,
            n.identity.secp256k1KeyPair,
        )

    fun subjects(): List<String> = inbox.messages().map { openMessage(it).subject }

    fun close() {
        runCatching { subscriber.close() }
        runCatching { handler.close() }
        runCatching { transport.close() }
        runCatching { inbox.stop() }
    }
}

/** An anonymity-mode node with the DM stack of the fixtures plus the mail stack (MAIL capability advertised). */
class MailOnionNode(
    relays: List<RelayHost>,
    locator: SyntheticLocator,
) {
    val n = DmOnionNode(relays, locator, capabilities = setOf(AnonymousCapability.DM, AnonymousCapability.MAIL))

    @Volatile lateinit var mail: MailStack

    init {
        n.onStarted = { mail = MailStack(it) }
        n.onStopping = { if (this::mail.isInitialized) mail.close() }
    }

    val key: Secp256k1PublicKey get() = n.key
}
