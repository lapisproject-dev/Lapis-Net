package net.lapisphilosophorum.lapisnet.dm

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.identity.X25519PublicKey
import java.nio.file.Files
import java.time.Duration
import java.time.Instant
import java.util.Collections
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

private fun awaitCondition(
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

/**
 * Routes anonymity-mode deliveries straight into the target manager's circuit door (online and "offline" alike).
 * [succeedThenFailOnline] >= 0 lets that many online deliveries through, then fails exactly one (returns `false`), and
 * the offline deposit that follows it throws: a dispatch failure of exactly that item.
 */
private class FlakyAnonymousTransport(
    private val nodes: () -> List<DmTestNode>,
) : AnonymousDmTransport {
    val succeedThenFailOnline = AtomicInteger(-1)
    private val failNextDeposit = AtomicBoolean(false)
    val onlineCalls = AtomicInteger()
    val depositCalls = AtomicInteger()

    /** What the failing deposit throws; by default the transport's own documented failure. */
    @Volatile var depositFailure: () -> RuntimeException = {
        DmAnonymousDeliveryException(DmAnonymousFailure.RECIPIENT_NOT_REACHABLE_ANONYMOUSLY)
    }

    override fun resolve(recipient: Secp256k1PublicKey): AnonymousDmTarget {
        val node = nodes().first { it.identity.secp256k1KeyPair.publicKey == recipient }
        return AnonymousDmTarget(recipient, node.prekeyStore.x25519IdentityPublicKey, null, true)
    }

    override fun deliverOnline(
        target: AnonymousDmTarget,
        envelopeBytes: ByteArray,
        deadline: Instant,
    ): Boolean {
        onlineCalls.incrementAndGet()
        val remaining = succeedThenFailOnline.get()
        if (remaining == 0) {
            succeedThenFailOnline.set(-1)
            failNextDeposit.set(true)
            return false
        }
        if (remaining > 0) succeedThenFailOnline.decrementAndGet()
        deliver(target, envelopeBytes)
        return true
    }

    override fun depositOffline(
        target: AnonymousDmTarget,
        envelopeBytes: ByteArray,
        notValidAfterEpochSecond: Long,
    ) {
        depositCalls.incrementAndGet()
        if (failNextDeposit.getAndSet(false)) {
            throw depositFailure()
        }
        deliver(target, envelopeBytes)
    }

    private fun deliver(
        target: AnonymousDmTarget,
        envelopeBytes: ByteArray,
    ) {
        val node = nodes().first { it.identity.secp256k1KeyPair.publicKey == target.recipient }
        node.dmSessionManager.inboundSink().acceptCircuitEnvelope(envelopeBytes)
    }

    override fun close() = Unit
}

/** B's authenticated rejection of C's CURRENT pending initiation (tagged with B's real key). */
private fun rejectionOfCurrentInitiation(
    b: DmTestNode,
    c: DmTestNode,
): DmX3dhRejection {
    val bKey = b.identity.secp256k1KeyPair.publicKey
    val cKey = c.identity.secp256k1KeyPair.publicKey
    val pending = c.dmSessionManager.pendingInitiationForTest(bKey)!!
    val bPrivate = b.prekeyStore.x25519IdentityPrivateKey()
    try {
        return DmX3dhRejectionCodec.create(
            bPrivate,
            c.prekeyStore.x25519IdentityPublicKey,
            cKey,
            DmX3dhRejectionCodec.Fields(
                bKey,
                X25519PublicKey(pending.ephemeralPublicKey),
                pending.signedPrekeyId,
                pending.oneTimePrekeyId,
                DmX3dhRejectionReason.ONE_TIME_PREKEY_CONSUMED,
                Instant.now().epochSecond,
            ),
        )
    } finally {
        bPrivate.destroy()
    }
}

private val BODIES = listOf("m0", "m1", "m2")

/**
 * The failure paths of the automatic re-send after a verified rejection: every replayed body reaches B exactly once
 * per replay (the originals plus one replay = twice), never a third time, and none is lost.
 */
class DmResendAfterRejectionFailureTest :
    FunSpec({
        test("prepare failure at item 1 (full lane): item 0 is dispatched once, only items 1 and 2 are retried") {
            val b = buildDmTestNode(oneTimePrekeyCount = 50)
            val c = buildDmTestNode()
            try {
                connectAndConverge(c, b)
                val bKey = b.identity.secp256k1KeyPair.publicKey
                val cKey = c.identity.secp256k1KeyPair.publicKey
                val received = CopyOnWriteArrayList<DmInboundMessage>()
                b.dmSessionManager.addInboundListener { received.add(it) }
                val cm = c.dmSessionManager
                val scheduled = CopyOnWriteArrayList<Pair<Long, () -> Unit>>()
                cm.scheduleForTest = { delay, task -> scheduled += delay to task }
                BODIES.forEach { cm.send(bKey, DmContent(body = it)) } // INITIAL + 2 TEXT, all online
                awaitCondition(Duration.ofSeconds(30)) { received.count { it.sender == cKey } == 3 } shouldBe true

                cm.handleX3dhRejectionForTest(rejectionOfCurrentInitiation(b, c))
                cm.diagnostics().rejectionsAccepted shouldBe 1L
                scheduled.size shouldBe 1
                // A lane of one: item 0 reserves the only slot, item 1 fails in reserve() before its ratchet step.
                cm.outboundLanesForTest().maxQueuedPerPeer = 1
                try {
                    scheduled[0].second()
                } finally {
                    cm.outboundLanesForTest().maxQueuedPerPeer = DmSessionManager.MAX_QUEUED_SENDS_PER_PEER
                }
                scheduled.size shouldBe 2
                scheduled[1].first shouldBe DmSessionManager.RESEND_RETRY_DELAY.toMillis()
                awaitCondition(Duration.ofSeconds(30)) {
                    received.count { it.sender == cKey && it.content.body == "m0" } == 2
                } shouldBe true

                scheduled[1].second()
                awaitCondition(Duration.ofSeconds(30)) {
                    BODIES.all { body -> received.count { it.sender == cKey && it.content.body == body } == 2 }
                } shouldBe true
                Thread.sleep(1_000)
                BODIES.forEach { body -> received.count { it.sender == cKey && it.content.body == body } shouldBe 2 }
                scheduled.size shouldBe 2
                cm.diagnostics().rebootstrapsAfterRejection shouldBe 1L
            } finally {
                b.stop()
                c.stop()
            }
        }

        test("dispatch failure at item 1: the loop stops there, item 2 is not sent early, items 1 and 2 retried once") {
            val b = buildDmTestNode(oneTimePrekeyCount = 50, anonymous = true)
            val c = buildDmTestNode(anonymous = true)
            try {
                connectAndConverge(c, b)
                val all = listOf(b, c)
                val transport = FlakyAnonymousTransport { all }
                all.forEach { it.dmSessionManager.installAnonymousTransport(transport) }
                val bKey = b.identity.secp256k1KeyPair.publicKey
                val cKey = c.identity.secp256k1KeyPair.publicKey
                val received = CopyOnWriteArrayList<DmInboundMessage>()
                b.dmSessionManager.addInboundListener { received.add(it) }
                val cm = c.dmSessionManager
                val scheduled = CopyOnWriteArrayList<Pair<Long, () -> Unit>>()
                cm.scheduleForTest = { delay, task -> scheduled += delay to task }
                BODIES.forEach { cm.send(bKey, DmContent(body = it)) }
                awaitCondition(Duration.ofSeconds(30)) { received.count { it.sender == cKey } == 3 } shouldBe true

                cm.handleX3dhRejectionForTest(rejectionOfCurrentInitiation(b, c))
                scheduled.size shouldBe 1
                val onlineBefore = transport.onlineCalls.get()
                val depositsBefore = transport.depositCalls.get()
                transport.succeedThenFailOnline.set(1) // item 0 goes through, item 1 fails online and offline
                scheduled[0].second()
                transport.onlineCalls.get() - onlineBefore shouldBe 2
                transport.depositCalls.get() - depositsBefore shouldBe 1
                scheduled.size shouldBe 2
                awaitCondition(Duration.ofSeconds(30)) {
                    received.count { it.sender == cKey && it.content.body == "m0" } == 2
                } shouldBe true
                received.count { it.sender == cKey && it.content.body == "m1" } shouldBe 1
                received.count { it.sender == cKey && it.content.body == "m2" } shouldBe 1
                // Only m0 went out under the new chain: m1 and m2 are taken out of the live buffer again.
                cm.replayBufferSizeForTest(bKey) shouldBe 1

                scheduled[1].second()
                awaitCondition(Duration.ofSeconds(30)) {
                    BODIES.all { body -> received.count { it.sender == cKey && it.content.body == body } == 2 }
                } shouldBe true
                Thread.sleep(1_000)
                BODIES.forEach { body -> received.count { it.sender == cKey && it.content.body == body } shouldBe 2 }
                scheduled.size shouldBe 2
                cm.diagnostics().rebootstrapsAfterRejection shouldBe 1L
                // Each body exactly once in the live buffer of the new chain, not m1 and m2 twice.
                cm.replayBufferSizeForTest(bKey) shouldBe 3

                // B refuses the new chain later (e.g. the deposited X3DH_INITIAL hit a consumed one-time prekey): the
                // next re-send replays every body exactly once more.
                cm.handleX3dhRejectionForTest(rejectionOfCurrentInitiation(b, c))
                scheduled.size shouldBe 3
                scheduled[2].second()
                awaitCondition(Duration.ofSeconds(30)) {
                    BODIES.all { body -> received.count { it.sender == cKey && it.content.body == body } == 3 }
                } shouldBe true
                Thread.sleep(1_000)
                BODIES.forEach { body -> received.count { it.sender == cKey && it.content.body == body } shouldBe 3 }
                scheduled.size shouldBe 3
            } finally {
                b.stop()
                c.stop()
            }
        }

        test("dispatch failure at item 0 while a newer rejection is accepted: the newer record and snapshot win") {
            val b = buildDmTestNode(oneTimePrekeyCount = 50, anonymous = true)
            val c = buildDmTestNode(anonymous = true)
            try {
                connectAndConverge(c, b)
                val all = listOf(b, c)
                val transport = FlakyAnonymousTransport { all }
                all.forEach { it.dmSessionManager.installAnonymousTransport(transport) }
                val bKey = b.identity.secp256k1KeyPair.publicKey
                val cKey = c.identity.secp256k1KeyPair.publicKey
                val received = CopyOnWriteArrayList<DmInboundMessage>()
                b.dmSessionManager.addInboundListener { received.add(it) }
                val cm = c.dmSessionManager
                val scheduled = CopyOnWriteArrayList<Pair<Long, () -> Unit>>()
                cm.scheduleForTest = { delay, task -> scheduled += delay to task }
                BODIES.forEach { cm.send(bKey, DmContent(body = it)) }
                awaitCondition(Duration.ofSeconds(30)) { received.count { it.sender == cKey } == 3 } shouldBe true

                cm.handleX3dhRejectionForTest(rejectionOfCurrentInitiation(b, c))
                scheduled.size shouldBe 1
                // During phase B (no stripe lock), right before item 0 (the new X3DH_INITIAL) goes out, B refuses that
                // new initiation as well; then item 0's dispatch fails.
                val newChainOtk = AtomicInteger(Int.MIN_VALUE)
                val fired = AtomicBoolean(false)
                cm.beforeDispatchForTest = { _, _ ->
                    if (fired.compareAndSet(false, true)) {
                        newChainOtk.set(cm.pendingInitiationForTest(bKey)!!.oneTimePrekeyId!!)
                        cm.handleX3dhRejectionForTest(rejectionOfCurrentInitiation(b, c))
                    }
                }
                val onlineBefore = transport.onlineCalls.get()
                val depositsBefore = transport.depositCalls.get()
                transport.succeedThenFailOnline.set(0)
                scheduled[0].second()
                cm.beforeDispatchForTest = null
                fired.get() shouldBe true
                cm.diagnostics().rejectionsAccepted shouldBe 2L
                // Item 0 failed: items 1 and 2 were not dispatched in that attempt.
                transport.onlineCalls.get() - onlineBefore shouldBe 1
                transport.depositCalls.get() - depositsBefore shouldBe 1
                // The newer rejection's record survives (no stale overwrite), and only ITS re-send is scheduled.
                val pending = cm.pendingInitiationForTest(bKey)!!
                pending.rejectionRebootstraps shouldBe 2
                pending.gaveUp shouldBe false
                pending.excludedIds shouldContain newChainOtk.get()
                scheduled.size shouldBe 2

                // The newer re-send replays every body exactly once more.
                scheduled[1].second()
                awaitCondition(Duration.ofSeconds(30)) {
                    BODIES.all { body -> received.count { it.sender == cKey && it.content.body == body } == 2 }
                } shouldBe true
                Thread.sleep(1_000)
                BODIES.forEach { body -> received.count { it.sender == cKey && it.content.body == body } shouldBe 2 }
                scheduled.size shouldBe 2
                cm.diagnostics().rebootstrapsAfterRejection shouldBe 1L
                cm.pendingInitiationForTest(bKey)!!.excludedIds shouldContain newChainOtk.get()
            } finally {
                b.stop()
                c.stop()
            }
        }

        test("dispatch failure at item 1 overtaken by a newer rejection whose re-send already ran: no third copy") {
            val b = buildDmTestNode(oneTimePrekeyCount = 50, anonymous = true)
            val c = buildDmTestNode(anonymous = true)
            try {
                connectAndConverge(c, b)
                val all = listOf(b, c)
                val transport = FlakyAnonymousTransport { all }
                all.forEach { it.dmSessionManager.installAnonymousTransport(transport) }
                val bKey = b.identity.secp256k1KeyPair.publicKey
                val cKey = c.identity.secp256k1KeyPair.publicKey
                val received = CopyOnWriteArrayList<DmInboundMessage>()
                b.dmSessionManager.addInboundListener { received.add(it) }
                val cm = c.dmSessionManager
                val scheduled = CopyOnWriteArrayList<Pair<Long, () -> Unit>>()
                cm.scheduleForTest = { delay, task -> scheduled += delay to task }
                BODIES.forEach { cm.send(bKey, DmContent(body = it)) }
                awaitCondition(Duration.ofSeconds(30)) { received.count { it.sender == cKey } == 3 } shouldBe true

                cm.handleX3dhRejectionForTest(rejectionOfCurrentInitiation(b, c))
                scheduled.size shouldBe 1
                // Phase B of the first re-send: item 0 (new X3DH_INITIAL) goes out. Right before item 1, B refuses that
                // new chain; its re-send runs on another thread and finishes phase A (it snapshots m0, m1, m2 from the
                // live buffer and re-initiates) before item 1 of the first re-send fails online and offline.
                val hookCalls = AtomicInteger()
                var newer: Thread? = null
                cm.beforeDispatchForTest = { _, _ ->
                    if (hookCalls.incrementAndGet() == 2) {
                        val chainBefore = cm.pendingInitiationForTest(bKey)!!.ephemeralPublicKey
                        cm.handleX3dhRejectionForTest(rejectionOfCurrentInitiation(b, c))
                        check(scheduled.size == 2) { "the newer rejection was not accepted" }
                        newer = Thread { scheduled[1].second() }.also { it.start() }
                        check(
                            awaitCondition(Duration.ofSeconds(30)) {
                                val now = cm.pendingInitiationForTest(bKey)?.ephemeralPublicKey
                                now != null && !now.contentEquals(chainBefore)
                            },
                        ) { "the newer re-send did not re-initiate" }
                        transport.succeedThenFailOnline.set(0) // item 1 of the FIRST re-send fails
                    }
                }
                scheduled[0].second()
                newer!!.join(60_000)
                cm.beforeDispatchForTest = null
                cm.diagnostics().rejectionsAccepted shouldBe 2L

                // m0 went out under both re-sends; m1 and m2 only under the newer one. No further re-send is scheduled.
                awaitCondition(Duration.ofSeconds(30)) {
                    received.count { it.sender == cKey && it.content.body == "m0" } == 3 &&
                        received.count { it.sender == cKey && it.content.body == "m1" } == 2 &&
                        received.count { it.sender == cKey && it.content.body == "m2" } == 2
                } shouldBe true
                Thread.sleep(1_000)
                scheduled.size shouldBe 2
                received.count { it.sender == cKey && it.content.body == "m0" } shouldBe 3
                received.count { it.sender == cKey && it.content.body == "m1" } shouldBe 2
                received.count { it.sender == cKey && it.content.body == "m2" } shouldBe 2
                cm.replayBufferSizeForTest(bKey) shouldBe 3
            } finally {
                b.stop()
                c.stop()
            }
        }

        test(
            "unexpected dispatch exception at item 1 (not a DmSessionException): items 1 and 2 are still retried once",
        ) {
            val b = buildDmTestNode(oneTimePrekeyCount = 50, anonymous = true)
            val c = buildDmTestNode(anonymous = true)
            try {
                connectAndConverge(c, b)
                val all = listOf(b, c)
                val transport = FlakyAnonymousTransport { all }
                transport.depositFailure = { IllegalStateException("simulated unexpected deposit failure") }
                all.forEach { it.dmSessionManager.installAnonymousTransport(transport) }
                val bKey = b.identity.secp256k1KeyPair.publicKey
                val cKey = c.identity.secp256k1KeyPair.publicKey
                val received = CopyOnWriteArrayList<DmInboundMessage>()
                b.dmSessionManager.addInboundListener { received.add(it) }
                val cm = c.dmSessionManager
                val scheduled = CopyOnWriteArrayList<Pair<Long, () -> Unit>>()
                cm.scheduleForTest = { delay, task -> scheduled += delay to task }
                BODIES.forEach { cm.send(bKey, DmContent(body = it)) }
                awaitCondition(Duration.ofSeconds(30)) { received.count { it.sender == cKey } == 3 } shouldBe true

                cm.handleX3dhRejectionForTest(rejectionOfCurrentInitiation(b, c))
                scheduled.size shouldBe 1
                transport.succeedThenFailOnline.set(1) // item 0 goes through, item 1 fails online, its deposit throws
                scheduled[0].second()
                // Before the fix the unexpected exception left the loop past the failure handling: m1 and m2 were lost.
                scheduled.size shouldBe 2
                scheduled[1].second()
                awaitCondition(Duration.ofSeconds(30)) {
                    BODIES.all { body -> received.count { it.sender == cKey && it.content.body == body } == 2 }
                } shouldBe true
                Thread.sleep(1_000)
                BODIES.forEach { body -> received.count { it.sender == cKey && it.content.body == body } shouldBe 2 }
                scheduled.size shouldBe 2
                cm.diagnostics().rebootstrapsAfterRejection shouldBe 1L
            } finally {
                b.stop()
                c.stop()
            }
        }

        test(
            "give-up whose pending record cannot be written: no exception escapes, nothing more is scheduled or sent",
        ) {
            val b = buildDmTestNode(oneTimePrekeyCount = 50, anonymous = true)
            val cDir = Files.createTempDirectory("dm-resend-unwritable")
            val c = buildDmTestNode(sessionStoreDirectory = cDir, anonymous = true)
            try {
                connectAndConverge(c, b)
                val all = listOf(b, c)
                val transport = FlakyAnonymousTransport { all }
                all.forEach { it.dmSessionManager.installAnonymousTransport(transport) }
                val bKey = b.identity.secp256k1KeyPair.publicKey
                val cKey = c.identity.secp256k1KeyPair.publicKey
                val received = CopyOnWriteArrayList<DmInboundMessage>()
                b.dmSessionManager.addInboundListener { received.add(it) }
                val cm = c.dmSessionManager
                val scheduled = CopyOnWriteArrayList<Pair<Long, () -> Unit>>()
                cm.scheduleForTest = { delay, task -> scheduled += delay to task }
                BODIES.forEach { cm.send(bKey, DmContent(body = it)) }
                awaitCondition(Duration.ofSeconds(30)) { received.count { it.sender == cKey } == 3 } shouldBe true

                cm.handleX3dhRejectionForTest(rejectionOfCurrentInitiation(b, c))
                for (attempt in 1..DmSessionManager.MAX_RESEND_ATTEMPTS) {
                    scheduled.size shouldBe attempt
                    transport.succeedThenFailOnline.set(0) // item 0 fails online and offline
                    if (attempt == DmSessionManager.MAX_RESEND_ATTEMPTS) {
                        // Phase B of the last attempt (no stripe lock): the session directory becomes read-only, so
                        // the give-up record cannot be stored.
                        cm.beforeDispatchForTest = { _, _ -> cDir.toFile().setWritable(false) }
                    }
                    scheduled[attempt - 1].second()
                }
                cm.beforeDispatchForTest = null
                cDir.toFile().setWritable(true)
                Thread.sleep(1_000)
                scheduled.size shouldBe DmSessionManager.MAX_RESEND_ATTEMPTS
                BODIES.forEach { body -> received.count { it.sender == cKey && it.content.body == body } shouldBe 1 }
                cm.pendingReplayCountForTest(bKey) shouldBe 0
            } finally {
                cDir.toFile().setWritable(true)
                b.stop()
                c.stop()
            }
        }

        test("no listener holds the sender's stripe lock while a replay is delivered and its failure is handled") {
            val b = buildDmTestNode(oneTimePrekeyCount = 50, anonymous = true)
            val c = buildDmTestNode(anonymous = true)
            try {
                connectAndConverge(c, b)
                val all = listOf(b, c)
                val transport = FlakyAnonymousTransport { all }
                all.forEach { it.dmSessionManager.installAnonymousTransport(transport) }
                val bKey = b.identity.secp256k1KeyPair.publicKey
                val cKey = c.identity.secp256k1KeyPair.publicKey
                val received = CopyOnWriteArrayList<DmInboundMessage>()
                val lockHeldInListener = Collections.synchronizedList(mutableListOf<Boolean>())
                b.dmSessionManager.addInboundListener {
                    lockHeldInListener += b.dmSessionManager.holdsPeerLockForTest(it.sender)
                    received.add(it)
                }
                val cm = c.dmSessionManager
                val scheduled = CopyOnWriteArrayList<Pair<Long, () -> Unit>>()
                cm.scheduleForTest = { delay, task -> scheduled += delay to task }
                BODIES.forEach { cm.send(bKey, DmContent(body = it)) }
                awaitCondition(Duration.ofSeconds(30)) { received.count { it.sender == cKey } == 3 } shouldBe true

                cm.handleX3dhRejectionForTest(rejectionOfCurrentInitiation(b, c))
                transport.succeedThenFailOnline.set(1) // m0 is replayed on this thread, m1 fails: failure handling
                scheduled[0].second()
                scheduled.size shouldBe 2
                scheduled[1].second()
                awaitCondition(Duration.ofSeconds(30)) {
                    BODIES.all { body -> received.count { it.sender == cKey && it.content.body == body } == 2 }
                } shouldBe true
                lockHeldInListener.size shouldBe 6
                lockHeldInListener.toList() shouldBe List(6) { false }
            } finally {
                b.stop()
                c.stop()
            }
        }
    })
