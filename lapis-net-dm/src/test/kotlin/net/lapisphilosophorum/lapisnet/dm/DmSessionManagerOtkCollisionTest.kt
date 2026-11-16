package net.lapisphilosophorum.lapisnet.dm

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.read.ListAppender
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.ints.shouldBeInRange
import io.kotest.matchers.longs.shouldBeGreaterThan
import io.kotest.matchers.longs.shouldBeGreaterThanOrEqual
import io.kotest.matchers.longs.shouldBeLessThanOrEqual
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.EncryptionKeyBinding
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.identity.X25519PublicKey
import net.lapisphilosophorum.lapisnet.ratchet.X3dhPreKeyMessageHeader
import org.slf4j.LoggerFactory
import java.nio.file.Files
import java.nio.file.Path
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneId
import java.time.ZoneOffset
import java.util.Collections
import java.util.concurrent.CopyOnWriteArrayList

private fun awaitTrue(
    timeout: Duration,
    condition: () -> Boolean,
): Boolean {
    val deadline = Instant.now().plus(timeout)
    while (Instant.now().isBefore(deadline)) {
        if (condition()) return true
        Thread.sleep(100)
    }
    return condition()
}

private class MutableClock(
    @Volatile var now: Instant,
) : Clock() {
    override fun getZone(): ZoneId = ZoneOffset.UTC

    override fun withZone(zone: ZoneId?): Clock = this

    override fun instant(): Instant = now

    fun advance(d: Duration) {
        now = now.plus(d)
    }
}

/** Routes anonymity-mode deliveries straight into the target manager's circuit door. */
private class RoutingAnonymousTransport(
    private val nodes: () -> List<DmTestNode>,
) : AnonymousDmTransport {
    val delivered = CopyOnWriteArrayList<ByteArray>()

    override fun resolve(recipient: Secp256k1PublicKey): AnonymousDmTarget {
        val node = nodes().first { it.identity.secp256k1KeyPair.publicKey == recipient }
        return AnonymousDmTarget(recipient, node.prekeyStore.x25519IdentityPublicKey, null, true)
    }

    override fun deliverOnline(
        target: AnonymousDmTarget,
        envelopeBytes: ByteArray,
        deadline: Instant,
    ): Boolean {
        delivered += envelopeBytes
        val node = nodes().first { it.identity.secp256k1KeyPair.publicKey == target.recipient }
        node.dmSessionManager.inboundSink().acceptCircuitEnvelope(envelopeBytes)
        return true
    }

    override fun depositOffline(
        target: AnonymousDmTarget,
        envelopeBytes: ByteArray,
        notValidAfterEpochSecond: Long,
    ) = Unit

    override fun close() = Unit
}

private class Trio(
    val a: DmTestNode,
    val b: DmTestNode,
    val c: DmTestNode,
) {
    val bKey: Secp256k1PublicKey = b.identity.secp256k1KeyPair.publicKey
    val cKey: Secp256k1PublicKey = c.identity.secp256k1KeyPair.publicKey
    val received: MutableList<DmInboundMessage> = Collections.synchronizedList(mutableListOf())

    fun stop() {
        a.stop()
        b.stop()
        c.stop()
    }

    fun bodiesFrom(sender: Secp256k1PublicKey): List<String> =
        synchronized(received) { received.filter { it.sender == sender }.map { it.content.body } }
}

/** A, B, C in direct mode, A and C forced to pick the same one-time prekey of B. */
private fun collidingTrio(
    bOneTimePrekeys: Int = 50,
    cSessionDir: Path = Files.createTempDirectory("dm-otk-c"),
    anonymous: Boolean = false,
): Pair<Trio, Int> {
    val b = buildDmTestNode(oneTimePrekeyCount = bOneTimePrekeys, anonymous = anonymous)
    val a = buildDmTestNode(anonymous = anonymous)
    val c = buildDmTestNode(sessionStoreDirectory = cSessionDir, anonymous = anonymous)
    connectAndConverge(a, b)
    connectAndConverge(c, b)
    val trio = Trio(a, b, c)
    val sharedId =
        a.prekeyBundleGossip
            .lookup(trio.bKey)!!
            .oneTimePrekeys
            .first()
            .id
    a.dmSessionManager.oneTimePrekeyChooserForTest = { sharedId }
    c.dmSessionManager.oneTimePrekeyChooserForTest = { sharedId }
    b.dmSessionManager.addInboundListener { trio.received.add(it) }
    return trio to sharedId
}

/**
 * [connectAndConverge] republishes [responder]'s prekey bundle every 500 ms until [viewer] sees one, so bundles with a
 * higher sequence number can still be in flight when it returns (measured under CPU load: [viewer] saw sequence 1 on
 * return and sequence 2 a few milliseconds later). Publishes one more bundle and waits until [viewer] holds exactly that
 * one. The bundle index keeps the highest sequence number and [responder] publishes nothing else (its pool stays far
 * above the replenish watermark), so no newer bundle can arrive afterwards. Returns that sequence number.
 */
private fun settleBundle(
    responder: DmTestNode,
    viewer: DmTestNode,
): Long {
    val key = responder.identity.secp256k1KeyPair.publicKey
    val bundle = responder.prekeyStore.publishBundle(responder.identity, Instant.now().epochSecond + 3600)
    responder.prekeyBundleGossip.announce(bundle)
    awaitTrue(Duration.ofSeconds(30)) {
        viewer.prekeyBundleGossip.lookup(key)?.sequenceNumber == bundle.sequenceNumber
    } shouldBe true
    return bundle.sequenceNumber
}

/** Rebuilds [genuine] (an X3DH_INITIAL) with a fresh ephemeral key and the given one-time prekey id. */
private fun forgedInitial(
    genuine: DmEnvelope,
    otkId: Int?,
    senderIdentity: DualKeyIdentity? = null,
    signedPrekeyIdOffset: Int = 0,
): DmEnvelope {
    val header = genuine.x3dhInitialHeader!!
    val identity = senderIdentity?.secp256k1KeyPair?.publicKey ?: header.initiatorIdentity
    val binding =
        senderIdentity?.let {
            EncryptionKeyBinding.create(it.secp256k1KeyPair, X25519KeyPair.generate().publicKey)
        } ?: header.initiatorEncryptionBinding
    val forgedHeader =
        X3dhPreKeyMessageHeader(
            identity,
            binding,
            X25519KeyPair.generate().publicKey,
            header.signedPrekeyId + signedPrekeyIdOffset,
            otkId,
        )
    return DmEnvelope(DmMessageType.X3DH_INITIAL, identity, forgedHeader, genuine.ratchetMessage)
}

class DmSessionManagerOtkCollisionTest :
    FunSpec({
        test(
            "two first-contact senders choosing the same one-time prekey: the second session recovers without restart",
        ) {
            val (t, sharedId) = collidingTrio()
            try {
                val cChoices = CopyOnWriteArrayList<Int?>()
                t.c.dmSessionManager.onOneTimePrekeyChosenForTest = { _, id, _ -> cChoices += id }
                t.a.dmSessionManager.send(t.bKey, DmContent(body = "from a"))
                awaitTrue(Duration.ofSeconds(30)) { t.bodiesFrom(t.a.identity.secp256k1KeyPair.publicKey).isNotEmpty() }
                t.c.dmSessionManager.send(t.bKey, DmContent(body = "from c 1"))
                awaitTrue(Duration.ofSeconds(30)) { t.bodiesFrom(t.cKey).contains("from c 1") } shouldBe true
                t.c.dmSessionManager.send(t.bKey, DmContent(body = "from c 2"))
                awaitTrue(Duration.ofSeconds(30)) { t.bodiesFrom(t.cKey).contains("from c 2") } shouldBe true
                Thread.sleep(1_000)
                t.bodiesFrom(t.cKey).count { it == "from c 1" } shouldBe 1
                t.bodiesFrom(t.cKey).count { it == "from c 2" } shouldBe 1
                t.b.dmSessionManager
                    .diagnostics()
                    .x3dhInitialRejectedOtkConsumed shouldBe 1L
                t.b.dmSessionManager
                    .diagnostics()
                    .rejectionsSent shouldBe 1L
                t.c.dmSessionManager
                    .diagnostics()
                    .rejectionsAccepted shouldBe 1L
                t.c.dmSessionManager
                    .diagnostics()
                    .rebootstrapsAfterRejection shouldBe 1L
                cChoices.first() shouldBe sharedId
                cChoices.last() shouldNotBe sharedId
                // B -> C works over the recovered session, and acknowledges it.
                val toC = CopyOnWriteArrayList<DmInboundMessage>()
                t.c.dmSessionManager.addInboundListener { toC.add(it) }
                t.b.dmSessionManager.send(t.cKey, DmContent(body = "from b"))
                awaitTrue(Duration.ofSeconds(30)) { toC.any { it.content.body == "from b" } } shouldBe true
                t.c.dmSessionManager.hasPendingInitiationForTest(t.bKey) shouldBe false
            } finally {
                t.stop()
            }
        }

        test("a bundle with a single one-time prekey: the second sender waits for a fresher bundle and then recovers") {
            // 21 one-time prekeys: one consumption reaches the low watermark, so B republishes a fresh bundle.
            val b = buildDmTestNode(oneTimePrekeyCount = 21)
            val a = buildDmTestNode()
            val c = buildDmTestNode()
            try {
                connectAndConverge(a, b)
                connectAndConverge(c, b)
                val bKey = b.identity.secp256k1KeyPair.publicKey
                b.prekeyBundleGossip.announce(
                    b.prekeyStore.publishBundle(b.identity, Instant.now().epochSecond + 3600, maxOneTimePrekeys = 1),
                )
                awaitTrue(Duration.ofSeconds(30)) {
                    a.prekeyBundleGossip
                        .lookup(bKey)
                        ?.oneTimePrekeys
                        ?.size == 1 &&
                        c.prekeyBundleGossip
                            .lookup(bKey)
                            ?.oneTimePrekeys
                            ?.size == 1
                } shouldBe true
                val received = CopyOnWriteArrayList<DmInboundMessage>()
                b.dmSessionManager.addInboundListener { received.add(it) }
                a.dmSessionManager.send(bKey, DmContent(body = "from a"))
                c.dmSessionManager.send(bKey, DmContent(body = "from c"))
                awaitTrue(Duration.ofSeconds(90)) {
                    received.any { it.sender == c.identity.secp256k1KeyPair.publicKey && it.content.body == "from c" }
                } shouldBe true
                c.dmSessionManager.diagnostics().rejectionsAccepted shouldBe 1L
            } finally {
                a.stop()
                b.stop()
                c.stop()
            }
        }

        test("anonymity mode: the rejection travels through the circuit door and logs carry no identities") {
            val logRoot = LoggerFactory.getLogger("net.lapisphilosophorum") as Logger
            val appender = ListAppender<ILoggingEvent>().also { it.start() }
            val oldLevel = logRoot.level
            logRoot.level = Level.DEBUG
            logRoot.addAppender(appender)
            val (t, _) = collidingTrio(anonymous = true)
            try {
                val all = listOf(t.a, t.b, t.c)
                all.forEach { it.dmSessionManager.installAnonymousTransport(RoutingAnonymousTransport { all }) }
                appender.list.clear()
                t.a.dmSessionManager.send(t.bKey, DmContent(body = "from a"))
                t.c.dmSessionManager.send(t.bKey, DmContent(body = "from c"))
                awaitTrue(Duration.ofSeconds(30)) { t.bodiesFrom(t.cKey).contains("from c") } shouldBe true
                t.c.dmSessionManager
                    .diagnostics()
                    .rejectionsAccepted shouldBe 1L
                val secrets =
                    all.flatMap { n ->
                        val k = n.identity.secp256k1KeyPair.publicKey
                        listOf(k.fingerprint(), k.bytes.joinToString("") { "%02x".format(it) })
                    }
                val leaks =
                    appender.list
                        .filter { e ->
                            e.loggerName.startsWith("net.lapisphilosophorum.lapisnet.dm")
                        }.filter { e ->
                            val text = e.formattedMessage + (e.throwableProxy?.message ?: "")
                            secrets.any { text.contains(it) }
                        }
                leaks.map { it.formattedMessage } shouldBe emptyList()
            } finally {
                logRoot.detachAppender(appender)
                logRoot.level = oldLevel
                t.stop()
            }
        }

        test("forged, replayed and misdirected rejections are ignored without any state change") {
            val (t, _) = collidingTrio()
            try {
                val genuine = CopyOnWriteArrayList<DmX3dhRejection>()
                t.c.dmSessionManager.onX3dhRejectionReceivedForTest = { genuine += it }
                t.a.dmSessionManager.send(t.bKey, DmContent(body = "from a"))
                awaitTrue(Duration.ofSeconds(30)) { t.received.isNotEmpty() }
                // Hold the re-send so the session state between the checks is observable.
                val held = CopyOnWriteArrayList<() -> Unit>()
                t.c.dmSessionManager.scheduleForTest = { _, task -> held += task }
                t.c.dmSessionManager.send(t.bKey, DmContent(body = "from c"))
                awaitTrue(Duration.ofSeconds(30)) { genuine.size == 1 } shouldBe true
                held.forEach { it() }
                awaitTrue(Duration.ofSeconds(30)) { t.bodiesFrom(t.cKey).contains("from c") } shouldBe true
                val c = t.c.dmSessionManager
                val ignoredBefore = c.diagnostics().rejectionsIgnored
                val pendingBefore = c.pendingInitiationForTest(t.bKey)!!.encode()

                // (5) the genuine rejection replayed after the re-bootstrap: old ephemeral, ignored.
                c.handleX3dhRejectionForTest(genuine.single())
                // (4) a rejection for the CURRENT initiation, tagged with a third party's key.
                val current = c.pendingInitiationForTest(t.bKey)!!
                val third = X25519KeyPair.generate()
                val forged =
                    DmX3dhRejectionCodec.create(
                        third.privateKey,
                        t.c.prekeyStore.x25519IdentityPublicKey,
                        t.cKey,
                        DmX3dhRejectionCodec.Fields(
                            t.bKey,
                            X25519PublicKey(current.ephemeralPublicKey),
                            current.signedPrekeyId,
                            current.oneTimePrekeyId,
                            DmX3dhRejectionReason.ONE_TIME_PREKEY_CONSUMED,
                            Instant.now().epochSecond,
                        ),
                    )
                c.handleX3dhRejectionForTest(forged)
                c.diagnostics().rejectionsIgnored shouldBe ignoredBefore + 2
                c.pendingInitiationForTest(t.bKey)!!.encode().contentEquals(pendingBefore) shouldBe true
                c.liveSessionForTest(t.bKey) shouldNotBe null

                // (6) once B answered, the session is acknowledged: a rejection is ignored, the session stays.
                val toC = CopyOnWriteArrayList<DmInboundMessage>()
                c.addInboundListener { toC.add(it) }
                t.b.dmSessionManager.send(t.cKey, DmContent(body = "ack"))
                awaitTrue(Duration.ofSeconds(30)) { toC.isNotEmpty() } shouldBe true
                c.handleX3dhRejectionForTest(forged)
                c.diagnostics().rejectionsIgnored shouldBe ignoredBefore + 3
                c.liveSessionForTest(t.bKey) shouldNotBe null

                // (7) the mailbox door and the sealed door decode with DmEnvelopeCodec.decode: type 4 is malformed.
                val bytes = DmX3dhRejectionCodec.encode(forged)
                runCatching { DmEnvelopeCodec.decode(bytes) }.exceptionOrNull()!!::class shouldBe
                    MalformedDmEnvelopeException::class
            } finally {
                t.stop()
            }
        }

        test("persistent rejection: at most three re-bootstraps with the backoff, then no further X3DH_INITIAL") {
            val clock = MutableClock(Instant.now())
            val (t, _) = collidingTrio()
            try {
                listOf(t.b, t.c).forEach { it.dmSessionManager.clock = clock }
                // B consumes every one-time prekey C can see: every initiation is refused.
                t.c.prekeyBundleGossip.lookup(t.bKey)!!.oneTimePrekeys.forEach {
                    t.b.prekeyStore.consumeOneTimePrekey(it.id)
                }
                t.c.dmSessionManager.oneTimePrekeyChooserForTest = null
                val initials = CopyOnWriteArrayList<Int?>()
                t.c.dmSessionManager.onOneTimePrekeyChosenForTest = { _, id, _ -> initials += id }
                val scheduled = CopyOnWriteArrayList<Pair<Long, () -> Unit>>()
                t.c.dmSessionManager.scheduleForTest = { delay, task -> scheduled += delay to task }
                t.c.dmSessionManager.send(t.bKey, DmContent(body = "from c"))
                val expected = listOf(0L..0L, 24_000L..36_000L, 96_000L..144_000L)
                for (round in 0 until 3) {
                    awaitTrue(Duration.ofSeconds(30)) { scheduled.size == round + 1 } shouldBe true
                    scheduled[round].first shouldBeGreaterThanOrEqual expected[round].first
                    scheduled[round].first shouldBeLessThanOrEqual expected[round].last
                    clock.advance(Duration.ofSeconds(301))
                    scheduled[round].second()
                }
                awaitTrue(Duration.ofSeconds(30)) {
                    t.c.dmSessionManager
                        .pendingInitiationForTest(t.bKey)
                        ?.gaveUp == true
                } shouldBe
                    true
                Thread.sleep(1_000)
                scheduled.size shouldBe 3
                initials.size shouldBe 4
                initials.toSet().size shouldBe 4
            } finally {
                t.stop()
            }
        }

        test("responder rate limits: one rejection per claimed sender per interval, global cap, bounded queue") {
            val (t, sharedId) = collidingTrio()
            try {
                val frames = CopyOnWriteArrayList<ByteArray>()
                t.c.dmSessionManager.onDirectFrameSentForTest = { frames += it }
                t.c.dmSessionManager.scheduleForTest = { _, _ -> }
                t.a.dmSessionManager.send(t.bKey, DmContent(body = "from a"))
                awaitTrue(Duration.ofSeconds(30)) { t.received.isNotEmpty() }
                t.c.dmSessionManager.send(t.bKey, DmContent(body = "from c"))
                awaitTrue(Duration.ofSeconds(30)) {
                    t.b.dmSessionManager
                        .diagnostics()
                        .rejectionsSent == 1L
                } shouldBe
                    true
                val genuine = DmEnvelopeCodec.decode(frames.first())
                val bm = t.b.dmSessionManager
                // Flood "from C" (C's public binding, fresh ephemerals, the consumed id): one per sender and interval.
                repeat(30) {
                    bm.handleInboundEnvelope(t.c.node.peerId, DmEnvelopeCodec.encode(forgedInitial(genuine, sharedId)))
                }
                Thread.sleep(500)
                bm.diagnostics().rejectionsSent shouldBe 1L
                // Flood from 30 throwaway identities with valid self-signed bindings and a stale signed-prekey id
                // (no one-time prekey, so the consumption limiter does not apply): the global cap holds.
                repeat(30) {
                    bm.handleInboundEnvelope(
                        t.c.node.peerId,
                        DmEnvelopeCodec.encode(forgedInitial(genuine, null, DualKeyIdentity.generate(), 1_000)),
                    )
                }
                Thread.sleep(2_000)
                bm.diagnostics().x3dhInitialRejectedSpkMismatch shouldBe 30L
                // The genuine collision rejection plus at most one SPK-mismatch budget.
                bm.diagnostics().rejectionsSent shouldBeLessThanOrEqual
                    1L + DmSessionManager.MAX_REJECTIONS_PER_WINDOW.toLong()
                bm.diagnostics().rejectionsSuppressedByRateLimit shouldBeGreaterThanOrEqual 20L
            } finally {
                t.stop()
            }
        }

        test("a flood of signed-prekey-mismatch initials does not use up the one-time-prekey rejection budget") {
            val (t, sharedId) = collidingTrio()
            try {
                val frames = CopyOnWriteArrayList<ByteArray>()
                t.c.dmSessionManager.onDirectFrameSentForTest = { frames += it }
                t.c.dmSessionManager.scheduleForTest = { _, _ -> }
                t.a.dmSessionManager.send(t.bKey, DmContent(body = "from a"))
                awaitTrue(Duration.ofSeconds(30)) { t.received.isNotEmpty() }
                t.c.dmSessionManager.send(t.bKey, DmContent(body = "from c"))
                awaitTrue(Duration.ofSeconds(30)) {
                    t.b.dmSessionManager
                        .diagnostics()
                        .rejectionsSent == 1L
                } shouldBe
                    true
                val genuine = DmEnvelopeCodec.decode(frames.first())
                val bm = t.b.dmSessionManager
                // Cheap frames: throwaway identities, stale signed-prekey id, no one-time prekey. Twice the budget.
                repeat(2 * DmSessionManager.MAX_REJECTIONS_PER_WINDOW) {
                    bm.handleInboundEnvelope(
                        t.c.node.peerId,
                        DmEnvelopeCodec.encode(forgedInitial(genuine, null, DualKeyIdentity.generate(), 1_000)),
                    )
                }
                val spkBudget = DmSessionManager.MAX_REJECTIONS_PER_WINDOW.toLong()
                awaitTrue(Duration.ofSeconds(30)) { bm.diagnostics().rejectionsSent == 1L + spkBudget } shouldBe true
                Thread.sleep(500)
                bm.diagnostics().rejectionsSent shouldBe 1L + spkBudget
                // A real one-time-prekey collision (a new sender naming the consumed id) is still answered.
                bm.handleInboundEnvelope(
                    t.c.node.peerId,
                    DmEnvelopeCodec.encode(forgedInitial(genuine, sharedId, DualKeyIdentity.generate())),
                )
                awaitTrue(Duration.ofSeconds(30)) {
                    bm.diagnostics().rejectionsSent == 2L + spkBudget
                } shouldBe true
            } finally {
                t.stop()
            }
        }

        test("the pending record of a new initiation cannot be stored: the session is rolled back, nothing is sent") {
            val cDir = Files.createTempDirectory("dm-otk-c-io")
            val (t, _) = collidingTrio(cSessionDir = cDir)
            try {
                val frames = CopyOnWriteArrayList<ByteArray>()
                t.c.dmSessionManager.onDirectFrameSentForTest = { frames += it }
                val hex = t.bKey.bytes.joinToString("") { "%02x".format(it) }
                // A non-empty directory where the pending record belongs: the atomic move fails with an IOException.
                val blocked = Files.createDirectories(cDir.resolve("$hex.lndm.x3dhpending"))
                Files.write(blocked.resolve("keep"), byteArrayOf(1))
                shouldThrow<DmSessionException> {
                    t.c.dmSessionManager.send(t.bKey, DmContent(body = "from c"))
                }
                frames.size shouldBe 0
                Files.exists(cDir.resolve("$hex.lndm")) shouldBe false
                Files.list(cDir).use { s -> s.filter { it.fileName.toString().endsWith(".tmp") }.count() } shouldBe 0L
                t.c.dmSessionManager.replayBufferSizeForTest(t.bKey) shouldBe 0
                // Once the obstacle is gone, the next send bootstraps normally.
                Files.delete(blocked.resolve("keep"))
                Files.delete(blocked)
                t.c.dmSessionManager.send(t.bKey, DmContent(body = "from c, again"))
                t.c.dmSessionManager.hasPendingInitiationForTest(t.bKey) shouldBe true
                awaitTrue(Duration.ofSeconds(30)) { t.bodiesFrom(t.cKey).contains("from c, again") } shouldBe true
            } finally {
                t.stop()
            }
        }

        test("an accepted INITIAL replayed byte for byte triggers no rejection") {
            val (t, _) = collidingTrio()
            try {
                val aFrames = CopyOnWriteArrayList<ByteArray>()
                t.a.dmSessionManager.onDirectFrameSentForTest = { aFrames += it }
                t.a.dmSessionManager.send(t.bKey, DmContent(body = "from a"))
                awaitTrue(Duration.ofSeconds(30)) { t.received.isNotEmpty() } shouldBe true
                val before = t.b.dmSessionManager.diagnostics()
                t.b.dmSessionManager.handleInboundEnvelope(t.a.node.peerId, aFrames.first())
                Thread.sleep(500)
                t.b.dmSessionManager.diagnostics() shouldBe before
            } finally {
                t.stop()
            }
        }

        test(
            "fallback: an unacknowledged session is rebuilt once after the thresholds, at most twice; never when acknowledged",
        ) {
            val clock = MutableClock(Instant.now())
            val b = buildDmTestNode(oneTimePrekeyCount = 50)
            val c = buildDmTestNode()
            try {
                connectAndConverge(c, b)
                val bKey = b.identity.secp256k1KeyPair.publicKey
                val cKey = c.identity.secp256k1KeyPair.publicKey
                val cm = c.dmSessionManager
                cm.clock = clock
                val initials = CopyOnWriteArrayList<Int?>()
                cm.onOneTimePrekeyChosenForTest = { _, id, _ -> initials += id }
                val atB = CopyOnWriteArrayList<DmInboundMessage>()
                b.dmSessionManager.addInboundListener { atB.add(it) }

                fun sendN(
                    n: Int,
                    body: String = "m",
                ) = repeat(n) { cm.send(bKey, DmContent(body = body)) }
                sendN(4) // INITIAL + 3 TEXT
                initials.size shouldBe 1
                clock.advance(Duration.ofMinutes(16))
                sendN(1)
                initials.size shouldBe 2
                cm.diagnostics().rebootstrapsUnacked shouldBe 1L
                sendN(3)
                clock.advance(Duration.ofMinutes(16))
                sendN(1)
                initials.size shouldBe 3
                // Each rebuild excludes the id the previous chain used (B has consumed it, its bundle still offers it).
                initials.toSet().size shouldBe 3
                cm.pendingInitiationForTest(bKey)!!.excludedIds shouldBe setOf(initials[0]!!, initials[1]!!)
                sendN(3)
                clock.advance(Duration.ofMinutes(16))
                sendN(1, body = "last before ack")
                initials.size shouldBe 3 // MAX_UNACKED_REBOOTSTRAPS reached
                // B must have processed C's last frame before it sends: B's inbound handler takes B's peer lock for C
                // on the Netty event loop, while B's send holds that lock and waits for a stream open that needs the
                // same event loop - the send would stall until DIAL_TIMEOUT (pre-existing, see the commit message).
                awaitTrue(Duration.ofSeconds(30)) {
                    atB.any { it.sender == cKey && it.content.body == "last before ack" }
                } shouldBe true
                b.dmSessionManager.liveSessionForTest(cKey) shouldNotBe null
                // Once B answers, no fallback any more.
                val toC = CopyOnWriteArrayList<DmInboundMessage>()
                cm.addInboundListener { toC.add(it) }
                b.dmSessionManager.send(cKey, DmContent(body = "ack"))
                awaitTrue(Duration.ofSeconds(30)) { toC.isNotEmpty() } shouldBe true
                cm.hasPendingInitiationForTest(bKey) shouldBe false
                sendN(4)
                clock.advance(Duration.ofMinutes(60))
                sendN(1)
                initials.size shouldBe 3
            } finally {
                b.stop()
                c.stop()
            }
        }

        test("fallback with only the used one-time prekey on offer: the working session is kept, not destroyed") {
            val clock = MutableClock(Instant.now())
            // 50 one-time prekeys: one consumption stays far above the low watermark, so B does not republish and
            // C's cached bundle keeps offering exactly the id C's own chain already consumed.
            val b = buildDmTestNode(oneTimePrekeyCount = 50)
            val c = buildDmTestNode()
            try {
                connectAndConverge(c, b)
                val bKey = b.identity.secp256k1KeyPair.publicKey
                val cKey = c.identity.secp256k1KeyPair.publicKey
                b.prekeyBundleGossip.announce(
                    b.prekeyStore.publishBundle(b.identity, Instant.now().epochSecond + 3600, maxOneTimePrekeys = 1),
                )
                awaitTrue(Duration.ofSeconds(30)) {
                    c.prekeyBundleGossip
                        .lookup(bKey)
                        ?.oneTimePrekeys
                        ?.size == 1
                } shouldBe true
                val received = CopyOnWriteArrayList<DmInboundMessage>()
                b.dmSessionManager.addInboundListener { received.add(it) }
                val cm = c.dmSessionManager
                cm.clock = clock
                val initials = CopyOnWriteArrayList<Int?>()
                cm.onOneTimePrekeyChosenForTest = { _, id, _ -> initials += id }
                repeat(4) { cm.send(bKey, DmContent(body = "m$it")) } // INITIAL + 3 TEXT
                awaitTrue(Duration.ofSeconds(30)) { received.count { it.sender == cKey } == 4 } shouldBe true
                initials.size shouldBe 1
                clock.advance(Duration.ofMinutes(16))
                cm.send(bKey, DmContent(body = "after the threshold"))
                awaitTrue(Duration.ofSeconds(30)) {
                    received.any { it.sender == cKey && it.content.body == "after the threshold" }
                } shouldBe true
                initials.size shouldBe 1
                cm.diagnostics().rebootstrapsUnacked shouldBe 0L
                cm.liveSessionForTest(bKey) shouldNotBe null
                val pending = cm.pendingInitiationForTest(bKey)!!
                pending.unackedRebootstraps shouldBe 0
                pending.oneTimePrekeyId shouldBe initials.single()
                // Once a fresh bundle arrives, the next send rebuilds around the consumed id.
                b.prekeyBundleGossip.announce(b.prekeyStore.publishBundle(b.identity, Instant.now().epochSecond + 3600))
                awaitTrue(Duration.ofSeconds(30)) {
                    (
                        c.prekeyBundleGossip
                            .lookup(bKey)
                            ?.oneTimePrekeys
                            ?.size ?: 0
                    ) > 1
                } shouldBe true
                cm.send(bKey, DmContent(body = "rebuilt"))
                initials.size shouldBe 2
                initials.last() shouldNotBe initials.first()
                cm.diagnostics().rebootstrapsUnacked shouldBe 1L
                awaitTrue(Duration.ofSeconds(30)) {
                    received.any { it.sender == cKey && it.content.body == "rebuilt" }
                } shouldBe true
            } finally {
                b.stop()
                c.stop()
            }
        }

        test("stale signed prekey: the re-send waits for a newer bundle, retries, and recovers once one arrives") {
            val b = buildDmTestNode(oneTimePrekeyCount = 50)
            val c = buildDmTestNode()
            try {
                connectAndConverge(c, b)
                // Without this, a late bundle from connectAndConverge can arrive after the rejection and count as "newer".
                val settled = settleBundle(b, c)
                val bKey = b.identity.secp256k1KeyPair.publicKey
                val cKey = c.identity.secp256k1KeyPair.publicKey
                val received = CopyOnWriteArrayList<DmInboundMessage>()
                b.dmSessionManager.addInboundListener { received.add(it) }
                val cm = c.dmSessionManager
                val chosen = CopyOnWriteArrayList<Pair<Int?, Long>>()
                cm.onOneTimePrekeyChosenForTest = { _, id, seq -> chosen += id to seq }
                val scheduled = CopyOnWriteArrayList<Pair<Long, () -> Unit>>()
                cm.scheduleForTest = { delay, task -> scheduled += delay to task }
                cm.send(bKey, DmContent(body = "spk"))
                awaitTrue(Duration.ofSeconds(30)) { received.any { it.sender == cKey } } shouldBe true
                val pending = cm.pendingInitiationForTest(bKey)!!
                val staleSequence = pending.bundleSequence
                staleSequence shouldBe settled
                // B's authenticated SIGNED_PREKEY_MISMATCH for exactly this initiation (tagged with B's real key).
                val bPrivate = b.prekeyStore.x25519IdentityPrivateKey()
                val rejection =
                    try {
                        DmX3dhRejectionCodec.create(
                            bPrivate,
                            c.prekeyStore.x25519IdentityPublicKey,
                            cKey,
                            DmX3dhRejectionCodec.Fields(
                                bKey,
                                X25519PublicKey(pending.ephemeralPublicKey),
                                pending.signedPrekeyId,
                                pending.oneTimePrekeyId,
                                DmX3dhRejectionReason.SIGNED_PREKEY_MISMATCH,
                                Instant.now().epochSecond,
                            ),
                        )
                    } finally {
                        bPrivate.destroy()
                    }
                cm.handleX3dhRejectionForTest(rejection)
                cm.diagnostics().rejectionsAccepted shouldBe 1L
                cm.liveSessionForTest(bKey) shouldBe null
                cm.pendingInitiationForTest(bKey)!!.awaitBundleNewerThan shouldBe staleSequence
                scheduled.size shouldBe 1
                scheduled[0].first shouldBe 0L

                // No newer bundle known yet: a user send refuses, and the re-send postpones itself by 30 s.
                shouldThrow<DmHandshakeFailedException> { cm.send(bKey, DmContent(body = "too early")) }
                    .message!! shouldContain "waiting for a newer prekey bundle"
                scheduled[0].second()
                scheduled.size shouldBe 2
                scheduled[1].first shouldBe DmSessionManager.RESEND_RETRY_DELAY.toMillis()
                chosen.size shouldBe 1
                cm.diagnostics().rebootstrapsAfterRejection shouldBe 0L
                cm.pendingInitiationForTest(bKey)!!.gaveUp shouldBe false

                // B republishes (higher sequence number): the next attempt bootstraps against it and replays.
                b.prekeyBundleGossip.announce(b.prekeyStore.publishBundle(b.identity, Instant.now().epochSecond + 3600))
                awaitTrue(Duration.ofSeconds(30)) {
                    (c.prekeyBundleGossip.lookup(bKey)?.sequenceNumber ?: -1) > staleSequence
                } shouldBe true
                scheduled[1].second()
                scheduled.size shouldBe 2
                chosen.size shouldBe 2
                chosen.last().second shouldBeGreaterThan staleSequence
                cm.diagnostics().rebootstrapsAfterRejection shouldBe 1L
                cm.pendingInitiationForTest(bKey)!!.awaitBundleNewerThan shouldBe -1L
                awaitTrue(Duration.ofSeconds(30)) {
                    received.count { it.sender == cKey && it.content.body == "spk" } == 2
                } shouldBe true
                received.none { it.content.body == "too early" } shouldBe true
            } finally {
                b.stop()
                c.stop()
            }
        }

        test("stale signed prekey and no newer bundle: the re-send gives up after the attempt cap") {
            val b = buildDmTestNode(oneTimePrekeyCount = 50)
            val c = buildDmTestNode()
            try {
                connectAndConverge(c, b)
                // Without this, a late bundle from connectAndConverge lets the first re-send attempt succeed.
                val settled = settleBundle(b, c)
                val bKey = b.identity.secp256k1KeyPair.publicKey
                val cKey = c.identity.secp256k1KeyPair.publicKey
                val cm = c.dmSessionManager
                val scheduled = CopyOnWriteArrayList<Pair<Long, () -> Unit>>()
                cm.scheduleForTest = { delay, task -> scheduled += delay to task }
                cm.send(bKey, DmContent(body = "spk"))
                val pending = cm.pendingInitiationForTest(bKey)!!
                pending.bundleSequence shouldBe settled
                val bPrivate = b.prekeyStore.x25519IdentityPrivateKey()
                val rejection =
                    try {
                        DmX3dhRejectionCodec.create(
                            bPrivate,
                            c.prekeyStore.x25519IdentityPublicKey,
                            cKey,
                            DmX3dhRejectionCodec.Fields(
                                bKey,
                                X25519PublicKey(pending.ephemeralPublicKey),
                                pending.signedPrekeyId,
                                pending.oneTimePrekeyId,
                                DmX3dhRejectionReason.SIGNED_PREKEY_MISMATCH,
                                Instant.now().epochSecond,
                            ),
                        )
                    } finally {
                        bPrivate.destroy()
                    }
                cm.handleX3dhRejectionForTest(rejection)
                for (attempt in 1..DmSessionManager.MAX_RESEND_ATTEMPTS) {
                    scheduled.size shouldBe attempt
                    if (attempt > 1) {
                        scheduled[attempt - 1].first shouldBe
                            DmSessionManager.RESEND_RETRY_DELAY.toMillis() * (attempt - 1)
                    }
                    scheduled[attempt - 1].second()
                }
                scheduled.size shouldBe DmSessionManager.MAX_RESEND_ATTEMPTS
                cm.pendingInitiationForTest(bKey)!!.gaveUp shouldBe true
                cm.diagnostics().rebootstrapsAfterRejection shouldBe 0L
            } finally {
                b.stop()
                c.stop()
            }
        }

        test("the pending-initiation record round-trips and rejects structural corruption") {
            val record =
                DmPendingInitiation(
                    responderX25519IdentityKey = ByteArray(32) { it.toByte() },
                    ephemeralPublicKey = ByteArray(32) { (it + 1).toByte() },
                    signedPrekeyId = 7,
                    oneTimePrekeyId = 42,
                    bundleSequence = 9L,
                    initiatedAtEpochSecond = 1_700_000_000L,
                    sendsSinceInitiation = 3,
                    rejectionRebootstraps = 1,
                    unackedRebootstraps = 2,
                    gaveUp = true,
                    awaitBundleNewerThan = 9L,
                    excludedIds = setOf(3, 42),
                )
            val bytes = record.encode()
            val decoded = DmPendingInitiation.decode(bytes)!!
            decoded.encode().contentEquals(bytes) shouldBe true
            decoded.oneTimePrekeyId shouldBe 42
            decoded.excludedIds shouldBe setOf(3, 42)
            decoded.awaitBundleNewerThan shouldBe 9L
            DmPendingInitiation.decode(bytes.copyOf(bytes.size - 1)) shouldBe null
            DmPendingInitiation.decode(bytes + byteArrayOf(0)) shouldBe null
            DmPendingInitiation.decode(bytes.copyOf().also { it[0] = 0 }) shouldBe null
        }

        test("restart of C between INITIAL and rejection: the record is reloaded and the next send excludes the id") {
            val cDir = Files.createTempDirectory("dm-otk-c-restart")
            val (t, sharedId) = collidingTrio(cSessionDir = cDir)
            var c2: DmTestNode? = null
            try {
                t.a.dmSessionManager.send(t.bKey, DmContent(body = "from a"))
                awaitTrue(Duration.ofSeconds(30)) { t.received.isNotEmpty() }
                val captured = CopyOnWriteArrayList<DmX3dhRejection>()
                t.c.dmSessionManager.onX3dhRejectionReceivedForTest = { captured += it }
                t.c.dmSessionManager.scheduleForTest = { _, _ -> } // the rejection is captured, its re-send dropped
                t.c.dmSessionManager.send(t.bKey, DmContent(body = "lost"))
                awaitTrue(Duration.ofSeconds(30)) { captured.isNotEmpty() } shouldBe true
                // Restart C over the same session directory; the pending record must survive it.
                val cIdentity = t.c.identity
                t.c.stop()
                Files.list(cDir).use { s ->
                    s.filter { it.fileName.toString().endsWith(".x3dhpending") }.count()
                } shouldBe
                    1L
                c2 = buildDmTestNode(identity = cIdentity, sessionStoreDirectory = cDir)
                connectAndConverge(c2, t.b)
                // The rejection was accepted before the restart (its in-memory re-send is gone with the process);
                // the durable record keeps the excluded id, so the next user send bootstraps around it.
                val chosen = CopyOnWriteArrayList<Int?>()
                c2.dmSessionManager.onOneTimePrekeyChosenForTest = { _, id, _ -> chosen += id }
                c2.dmSessionManager.send(t.bKey, DmContent(body = "after restart"))
                awaitTrue(Duration.ofSeconds(30)) { t.bodiesFrom(t.cKey).contains("after restart") } shouldBe true
                chosen.single() shouldNotBe sharedId
            } finally {
                t.a.stop()
                t.b.stop()
                c2?.stop()
            }
        }

        test("glare: a peer's own X3DH_INITIAL acknowledges the pending initiation") {
            val b = buildDmTestNode(oneTimePrekeyCount = 50)
            val c = buildDmTestNode(oneTimePrekeyCount = 50)
            try {
                connectAndConverge(c, b)
                val bKey = b.identity.secp256k1KeyPair.publicKey
                val cKey = c.identity.secp256k1KeyPair.publicKey
                // C's INITIAL goes to the mailbox (B polls only every 60 s), so B has no session yet and initiates too.
                c.dmSessionManager.sendOffline(bKey, DmContent(body = "c first"))
                c.dmSessionManager.hasPendingInitiationForTest(bKey) shouldBe true
                c.dmSessionManager.replayBufferSizeForTest(bKey) shouldBe 1
                val toC = CopyOnWriteArrayList<DmInboundMessage>()
                c.dmSessionManager.addInboundListener { toC.add(it) }
                b.dmSessionManager.send(cKey, DmContent(body = "b first"))
                awaitTrue(Duration.ofSeconds(30)) { toC.isNotEmpty() } shouldBe true
                c.dmSessionManager.hasPendingInitiationForTest(bKey) shouldBe false
                c.dmSessionManager.replayBufferSizeForTest(bKey) shouldBe 0
            } finally {
                b.stop()
                c.stop()
            }
        }

        test("X3dh exclusion is honoured on the sender: excluded ids are never chosen") {
            val (t, sharedId) = collidingTrio()
            try {
                t.c.dmSessionManager.oneTimePrekeyChooserForTest = null
                val ids = CopyOnWriteArrayList<Int?>()
                t.c.dmSessionManager.onOneTimePrekeyChosenForTest = { _, id, _ -> ids += id }
                t.a.dmSessionManager.send(t.bKey, DmContent(body = "from a"))
                awaitTrue(Duration.ofSeconds(30)) { t.received.isNotEmpty() }
                t.c.dmSessionManager.send(t.bKey, DmContent(body = "from c"))
                awaitTrue(Duration.ofSeconds(30)) { t.bodiesFrom(t.cKey).isNotEmpty() } shouldBe true
                ids.size shouldBeInRange 1..2
                if (ids.size == 2) ids.last() shouldNotBe sharedId
            } finally {
                t.stop()
            }
        }
    })
