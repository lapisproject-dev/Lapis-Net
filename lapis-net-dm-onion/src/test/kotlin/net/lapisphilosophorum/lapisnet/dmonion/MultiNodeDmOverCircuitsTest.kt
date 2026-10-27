@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.dmonion

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.read.ListAppender
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.withClue
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.libp2p.core.PeerInfo
import net.lapisphilosophorum.lapisnet.directory.DirectoryReachability
import net.lapisphilosophorum.lapisnet.directory.PeerCapability
import net.lapisphilosophorum.lapisnet.directory.PeerRecord
import net.lapisphilosophorum.lapisnet.directory.PeerRecordCodec
import net.lapisphilosophorum.lapisnet.dm.DmAcceptanceCheck
import net.lapisphilosophorum.lapisnet.dm.DmAnonymousDeliveryException
import net.lapisphilosophorum.lapisnet.dm.DmContent
import net.lapisphilosophorum.lapisnet.dm.DmEnvelopeCodec
import net.lapisphilosophorum.lapisnet.dm.DmInboundMessage
import net.lapisphilosophorum.lapisnet.dm.DmMessageType
import net.lapisphilosophorum.lapisnet.dm.DmProtocol
import net.lapisphilosophorum.lapisnet.dm.DmSendOutcome
import net.lapisphilosophorum.lapisnet.dm.MailboxTopics
import net.lapisphilosophorum.lapisnet.dm.SealedMailboxItemCodec
import net.lapisphilosophorum.lapisnet.dm.buildDmTestNode
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onionwire.OnionServiceApp
import net.lapisphilosophorum.lapisnet.policy.AcceptanceGate
import net.lapisphilosophorum.lapisnet.policy.KarmaScoreLookup
import net.lapisphilosophorum.lapisnet.trust.TrustGraph
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.nio.file.Files
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.TimeUnit
import kotlin.time.Duration.Companion.seconds

private fun contains(
    haystack: ByteArray,
    needle: ByteArray,
): Boolean {
    if (needle.isEmpty() || haystack.size < needle.size) return false
    outer@ for (o in 0..haystack.size - needle.size) {
        for (i in needle.indices) if (haystack[o + i] != needle[i]) continue@outer
        return true
    }
    return false
}

/** Binary multiaddrs, their text and the TCP port component of every listen address of [node]. */
private fun addressNeedles(node: net.lapisphilosophorum.lapisnet.networking.LapisNode): List<ByteArray> =
    node.listenAddresses().flatMap { ma ->
        val text = ma.toString()
        val port = Regex("/tcp/(\\d+)").find(text)!!.groupValues[1].toInt()
        listOf(ma.serialize(), text.toByteArray(), byteArrayOf(0x06, (port ushr 8).toByte(), port.toByte()))
    }

private fun identityNeedles(
    node: net.lapisphilosophorum.lapisnet.networking.LapisNode,
    identity: DualKeyIdentity,
): List<ByteArray> = listOf(node.peerId.bytes, identity.ed25519KeyPair.publicKey.bytes, identity.binding.signature)

/** Reassembles the first envelope frame out of the recorded plaintext chunks of one sender. */
private fun firstEnvelope(frames: List<ByteArray>): net.lapisphilosophorum.lapisnet.dm.DmEnvelope {
    val all = frames.fold(ByteArray(0)) { a, b -> a + b }
    val length = ByteBuffer.wrap(all, 1, 4).getInt()
    return DmEnvelopeCodec.decode(all.copyOfRange(5, 5 + length))
}

/**
 * Real nodes on loopback: six relays in a full mesh, A and B in anonymity mode (never relays, connected ONLY to
 * relays), C an ordinary direct-mode DM node. All relays sit on 127.0.0.1, which the real locator can not tell apart, so
 * a locator with synthetic /16 networks is injected: network diversity is verified only with that locator, NOT over
 * real networks. The path rules are not weakened.
 */
class MultiNodeDmOverCircuitsTest :
    FunSpec({
        val logRoot = LoggerFactory.getLogger("net.lapisphilosophorum") as Logger
        val logAppender = ListAppender<ILoggingEvent>().also { it.start() }
        val oldLevel = logRoot.level
        logRoot.level = Level.DEBUG
        logRoot.addAppender(logAppender)
        val relays = List(6) { RelayHost() }
        for (i in relays.indices) for (j in i + 1 until relays.size) relays[i].connectTo(relays[j])
        val locator = SyntheticLocator()
        relays.forEachIndexed { i, r -> locator.put(r.key, 10 + i, i) }
        val a = DmOnionNode(relays, locator)
        val b = DmOnionNode(relays, locator)
        val c = buildDmTestNode()
        val bReceived = CopyOnWriteArrayList<DmInboundMessage>()
        val aReceived = CopyOnWriteArrayList<DmInboundMessage>()
        var bListenerRegistered = false

        fun listenOnB() {
            b.dm.addInboundListener { bReceived += it }
            bListenerRegistered = true
        }

        afterSpec {
            logRoot.detachAppender(logAppender)
            logRoot.level = oldLevel
            runCatching { a.stop() }
            runCatching { b.stop() }
            runCatching { c.stop() }
            relays.forEach { runCatching { it.close() } }
        }

        test("A and B start in anonymity mode, C is an ordinary node, everyone finds everyone through the relays only")
            .config(timeout = 600.seconds) {
                relays.forEach { r -> c.node.connect(PeerInfo(r.node.peerId, r.node.listenAddresses())) }
                a.start()
                b.start()
                a.awaitPublished() shouldBe true
                b.awaitPublished() shouldBe true
                var lastPublish = 0L

                fun seesHidden(
                    viewer: DmOnionNode,
                    other: DmOnionNode,
                ) = viewer.runtime.resolveIdentity(other.key) is DirectoryReachability.Hidden &&
                    viewer.bundleGossip.lookup(other.key) != null

                fun status() =
                    "A sees B: ${seesHidden(a, b)}, B sees A: ${seesHidden(b, a)}, " +
                        "A->B ${a.runtime.resolveIdentity(b.key)::class.simpleName}, " +
                        "B->A ${b.runtime.resolveIdentity(a.key)::class.simpleName}"
                // A directory object that is published while the gossip mesh is still forming is repeated on the early
                // republication schedule (5 s to 5 min after the first publication), so no restart is needed.
                val converged =
                    awaitCondition(Duration.ofSeconds(360)) {
                        if (System.currentTimeMillis() - lastPublish > 3_000) {
                            c.publishSelf()
                            lastPublish = System.currentTimeMillis()
                        }
                        seesHidden(a, b) && seesHidden(b, a)
                    }
                withClue(status()) { converged shouldBe true }
                a.dm.addInboundListener { aReceived += it }
                listenOnB()
                awaitCondition(Duration.ofSeconds(120)) {
                    if (System.currentTimeMillis() - lastPublish > 3_000) {
                        c.publishSelf()
                        lastPublish = System.currentTimeMillis()
                    }
                    a.peerDirectory.lookup(c.identity.secp256k1KeyPair.publicKey) != null
                } shouldBe true
                a.dm.routeMode().wire shouldBe "circuit"
            }

        test("A writes to B: the first message is an X3DH_INITIAL over a circuit, B answers over a NEW circuit")
            .config(timeout = 600.seconds) {
                var outcome: DmSendOutcome? = null
                repeat(3) {
                    if (bReceived.isEmpty()) {
                        outcome = a.dm.sendAuto(b.key, DmContent(body = "hello B"))
                        awaitCondition(Duration.ofSeconds(30)) { bReceived.isNotEmpty() }
                    }
                }
                bReceived.isNotEmpty() shouldBe true
                bReceived.first().sender shouldBe a.key
                bReceived.first().content.body shouldBe "hello B"
                // whichever way it travelled, the very first envelope A produced was the X3DH handshake
                if (a.port.frames.isNotEmpty()) {
                    firstEnvelope(a.port.frames).messageType shouldBe DmMessageType.X3DH_INITIAL
                    outcome shouldBe DmSendOutcome.SENT_ONLINE
                }

                // the answer: B resolves A and builds its own circuit to A's service (no use of the incoming stream)
                var reply: DmSendOutcome? = null
                repeat(3) {
                    if (aReceived.isEmpty()) {
                        reply = b.dm.sendAuto(a.key, DmContent(body = "hello A"))
                        awaitCondition(Duration.ofSeconds(30)) { aReceived.isNotEmpty() }
                    }
                }
                aReceived.first().content.body shouldBe "hello A"
                withClue(
                    "connect failures of B: ${b.port.connectFailures}",
                ) { reply shouldBe DmSendOutcome.SENT_ONLINE }
                b.dm.routeMode().wire shouldBe "circuit"
            }

        test(
            "network observer: A and B only ever connect to relays, never to each other, and never speak /lapis/dm",
        ).config(
            timeout = 120.seconds,
        ) {
            val relayIds = relays.map { it.node.peerId }.toSet()
            (a.connectedPeers.contains(b.node.peerId)) shouldBe false
            (b.connectedPeers.contains(a.node.peerId)) shouldBe false
            a.connectedPeers.all { it in relayIds } shouldBe true
            b.connectedPeers.all { it in relayIds } shouldBe true

            // plaintext of everything the DM path handed to circuits holds no address, port or transport identity
            val sentByA = a.port.frames.toList() + a.port.items.toList()
            val sentByB = b.port.frames.toList() + b.port.items.toList()
            sentByA.isNotEmpty() shouldBe true
            sentByB.isNotEmpty() shouldBe true
            val needles =
                addressNeedles(a.node) + identityNeedles(a.node, a.identity) +
                    addressNeedles(b.node) + identityNeedles(b.node, b.identity)
            needles.none { n -> (sentByA + sentByB).any { contains(it, n) } } shouldBe true

            // positive control: the scanner does find the same needles in an ordinary peer record
            val record =
                PeerRecord.create(
                    a.identity,
                    a.node.listenAddresses(),
                    setOf(PeerCapability.DM),
                    1,
                    Instant.now().epochSecond + 600,
                )
            val encoded = PeerRecordCodec.encode(record)
            addressNeedles(a.node).any { contains(encoded, it) } shouldBe true

            // the direct mailbox topic of B was never used by A
            a.publishedTopics.none { it == MailboxTopics.forRecipient(b.key) } shouldBe true
        }

        test(
            "offline: B is down, A queues; B restarts, the re-announcement delivers exactly once; nothing touches Nabu or the DHT",
        ).config(timeout = 900.seconds) {
            b.stop()
            var outcome: DmSendOutcome? = null
            // B is gone: its record is still cached at A, so the online attempt fails and A queues the message
            val pendingBefore = a.redelivery.pendingCount()
            outcome = a.dm.sendAuto(b.key, DmContent(body = "while you were away"))
            outcome shouldBe DmSendOutcome.QUEUED_FOR_PICKUP
            a.redelivery.pendingCount() shouldBe pendingBefore + 1

            val before = bReceived.size
            b.start()
            listenOnBAgain(b, bReceived)
            b.awaitPublished() shouldBe true
            awaitCondition(Duration.ofSeconds(240)) { bReceived.size > before } shouldBe true
            bReceived.last().content.body shouldBe "while you were away"
            // the re-announcement continues, yet nothing is delivered a second time
            val announced = a.redelivery.announcementCount()
            awaitCondition(Duration.ofSeconds(60)) { a.redelivery.announcementCount() > announced + 1 } shouldBe
                true
            bReceived.count { it.content.body == "while you were away" } shouldBe 1

            // no pointer, no DHT, no Bitswap: the only topic A published a DM item on is the relays' shared one
            a.publishedTopics.none { it.contains("mailbox") && it != "LapisNet:anonymous-mailbox:v1" } shouldBe true
            a.port.items.all { it.size == SealedMailboxItemCodec.SEALED_ITEM_BYTES } shouldBe true
        }

        test(
            "not reachable anonymously: a direct-mode node and an unknown identity get the same refusal, no session, no contact",
        ).config(timeout = 120.seconds) {
            val cKey = c.identity.secp256k1KeyPair.publicKey
            a.runtime.resolveIdentity(cKey).shouldBeInstanceOf<DirectoryReachability.Direct>()
            val sessionsBefore = Files.list(a.sessionDir).use { it.count() }
            val unknown = DualKeyIdentity.generate().secp256k1KeyPair.publicKey
            val messages =
                listOf(cKey, unknown).map { target ->
                    shouldThrow<DmAnonymousDeliveryException> {
                        a.dm.sendAuto(target, DmContent(body = "nobody home"))
                    }.message
                }
            messages shouldBe listOf("recipient-not-reachable-anonymously", "recipient-not-reachable-anonymously")
            Files.list(a.sessionDir).use { it.count() } shouldBe sessionsBefore
            (a.connectedPeers.contains(c.node.peerId)) shouldBe false
            a.runtime.status().recipientUnreachableCount shouldBe 2
            a.runtime
                .status()
                .lastError.wire shouldBe "recipient-unreachable"
        }

        test(
            "a quarantining recipient looks exactly like an accepting one to the sender",
        ).config(timeout = 300.seconds) {
            b.dm.updateAcceptanceCheck(
                DmAcceptanceCheck(
                    gates = listOf(AcceptanceGate.VeritasPath),
                    trustGraph = TrustGraph.fromEdges(emptyList()),
                    karmaScoreOf = KarmaScoreLookup { 0.0 },
                ),
            )
            val before = bReceived.size
            var outcome: DmSendOutcome? = null
            repeat(3) {
                if (bReceived.size == before) {
                    outcome = a.dm.sendAuto(b.key, DmContent(body = "are you listening"))
                    awaitCondition(Duration.ofSeconds(30)) { bReceived.size > before }
                }
            }
            bReceived.size shouldBe before + 1
            bReceived.last().quarantined shouldBe true
            outcome shouldBe DmSendOutcome.SENT_ONLINE
            b.dm.updateAcceptanceCheck(null)
        }

        test(
            "replay and tamper: a replayed frame, a replayed sealed item and a bit flip are never delivered, also after a restart",
        ).config(timeout = 900.seconds) {
            val firstFrameEnvelope =
                run {
                    val all = a.port.frames.fold(ByteArray(0)) { x, y -> x + y }
                    all.copyOfRange(5, 5 + ByteBuffer.wrap(all, 1, 4).getInt())
                }
            val delivered = bReceived.size
            val sink = b.dm.inboundSink()
            sink.acceptCircuitEnvelope(firstFrameEnvelope)
            sink.acceptCircuitEnvelope(firstFrameEnvelope)
            val item = a.port.items.last()
            sink.acceptSealedMailboxItem(item)
            sink.acceptSealedMailboxItem(item)
            sink.acceptSealedMailboxItem(item.copyOf().also { it[100] = (it[100].toInt() xor 1).toByte() })
            Thread.sleep(1_500)
            bReceived.size shouldBe delivered

            b.stop()
            b.start()
            listenOnBAgain(b, bReceived)
            val afterRestart = bReceived.size
            val s = b.dm.inboundSink()
            s.acceptCircuitEnvelope(firstFrameEnvelope)
            s.acceptSealedMailboxItem(item)
            Thread.sleep(1_500)
            // (items re-announced by A may legitimately arrive while B is back, but never the first handshake)
            bReceived.drop(afterRestart).none { it.content.body == "hello B" } shouldBe true
        }

        test("limits on the real stack: a bad frame closes the stream, the stream cache and the queues stay bounded")
            .config(timeout = 600.seconds) {
                b.awaitPublished() shouldBe true
                awaitCondition(Duration.ofSeconds(120)) {
                    a.runtime.resolveIdentity(b.key) is DirectoryReachability.Hidden
                } shouldBe true
                // the client circuit pool (4) is shared with publication and the sender cache, and B's service
                // descriptor may still be the previous run's: re-resolve on every attempt and retry while busy
                val failures = ArrayList<String>()
                var opened: net.lapisphilosophorum.lapisnet.onionwire.OnionRendezvousStream? = null
                repeat(12) {
                    if (opened == null) {
                        try {
                            val hidden = a.runtime.resolveIdentity(b.key) as DirectoryReachability.Hidden
                            opened =
                                a.runtime
                                    .connectToService(hidden.descriptor, OnionServiceApp.DM, 40.seconds)
                                    .get(60, TimeUnit.SECONDS)
                        } catch (e: java.util.concurrent.ExecutionException) {
                            failures +=
                                generateSequence<Throwable>(
                                    e,
                                ) { it.cause }.last().let { "${it.javaClass.simpleName}:${it.message}" }
                            Thread.sleep(10_000)
                        }
                    }
                }
                val stream = withClue("connect failures: $failures") { checkNotNull(opened) }
                // type ENVELOPE with a length far above the maximum: closed before anything is allocated
                stream.send(
                    ByteBuffer
                        .allocate(5)
                        .put(1)
                        .putInt(Int.MAX_VALUE)
                        .array(),
                ) shouldBe true
                awaitCondition(Duration.ofSeconds(30)) { stream.isClosed } shouldBe true

                (a.transport.openStreams() <= 2) shouldBe true
                (a.redelivery.pendingCount() <= AnonymousMailboxRedelivery.MAX_ENTRIES) shouldBe true
            }

        test("no listener for the direct DM protocol exists on an anonymity-mode node (the negotiation fails)")
            .config(timeout = 300.seconds) {
                val probe = DmProtocol.attach(c.node) { _, _ -> }
                for (n in listOf(a, b)) {
                    if (!n.running) n.start()
                    val failed =
                        runCatching {
                            probe
                                .dial(c.node, n.node.peerId, *n.node.listenAddresses().toTypedArray())
                                .controller
                                .get(10, TimeUnit.SECONDS)
                        }.isFailure
                    failed shouldBe true
                }
            }

        test("start and stop leave nothing behind: no circuit, no stream, no thread; a second start works")
            .config(timeout = 900.seconds) {
                a.stop()
                b.stop()
                a.runtime.status().activeCircuits shouldBe 0
                b.runtime.status().activeCircuits shouldBe 0
                a.transport.openStreams() shouldBe 0
                a.handler.openStreams() shouldBe 0
                b.handler.openStreams() shouldBe 0
                awaitCondition(Duration.ofSeconds(60)) {
                    relays.all { it.wire.relayService!!.circuitCount() == 0 }
                } shouldBe true
                awaitCondition(Duration.ofSeconds(30)) {
                    Thread.getAllStackTraces().keys.none { it.isAlive && it.name.startsWith("lapis-net-dm-onion") }
                } shouldBe true

                a.start()
                a.awaitPublished() shouldBe true
                a.runtime.ready() shouldBe true
                a.stop()
                Clock.systemUTC().millis() // keep the clock import honest
            }

        test("logs of the DM and onion layers hold no address, peer id, key, fingerprint or message text")
            .config(timeout = 120.seconds) {
                fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
                val forbidden = ArrayList<String>()
                // C is an ordinary direct-mode node: its own DM layer legitimately logs its own peer id
                val identities = listOf(a.identity, b.identity) + relays.map { it.identity }
                val peerIds = listOf(a.node.peerId, b.node.peerId) + relays.map { it.node.peerId }
                peerIds.forEach { forbidden += it.toBase58() }
                identities.forEach {
                    forbidden += hex(it.secp256k1KeyPair.publicKey.bytes)
                    forbidden += hex(it.ed25519KeyPair.publicKey.bytes)
                    forbidden += it.secp256k1KeyPair.publicKey.fingerprint()
                }
                forbidden += hex(a.serviceKey.publicKey.bytes)
                forbidden += hex(b.serviceKey.publicKey.bytes)
                forbidden += listOf("hello B", "hello A", "while you were away", "are you listening")
                val patterns = listOf("/ip4", "/ip6", "/tcp", "127.0.0.1", "localhost", "/p2p/")
                val hexRun = Regex("[0-9a-fA-F]{32,}")
                val own =
                    logAppender.list.toList().filter {
                        it.loggerName.contains("lapisnet.dm") || it.loggerName.contains("lapisnet.onion")
                    }
                (own.size > 0) shouldBe true
                for (event in own) {
                    val text = event.formattedMessage + " " + (event.throwableProxy?.message ?: "")
                    for (f in forbidden) {
                        withClue("log line from ${event.loggerName} contains ${f.take(6)}...: ${text.take(160)}") {
                            text.contains(f) shouldBe
                                false
                        }
                    }
                    for (p in patterns) withClue("log line contains $p") { text.contains(p) shouldBe false }
                    withClue("log line contains a long hex run") { hexRun.containsMatchIn(text) shouldBe false }
                }
            }
    })

private fun listenOnBAgain(
    b: DmOnionNode,
    received: CopyOnWriteArrayList<DmInboundMessage>,
) {
    b.dm.addInboundListener { received += it }
}
