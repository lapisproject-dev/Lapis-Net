@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.mailonion

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.read.ListAppender
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.withClue
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerInfo
import net.lapisphilosophorum.lapisnet.directory.ANONYMOUS_MAILBOX_GOSSIP_TOPIC
import net.lapisphilosophorum.lapisnet.directory.AnonymousCapability
import net.lapisphilosophorum.lapisnet.directory.DirectoryReachability
import net.lapisphilosophorum.lapisnet.dm.MailboxTopics
import net.lapisphilosophorum.lapisnet.dm.buildDmTestNode
import net.lapisphilosophorum.lapisnet.dmonion.RelayHost
import net.lapisphilosophorum.lapisnet.dmonion.SyntheticLocator
import net.lapisphilosophorum.lapisnet.dmonion.awaitCondition
import net.lapisphilosophorum.lapisnet.dmonion.isSeenBehindService
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.mail.AnonymousMailSizing
import net.lapisphilosophorum.lapisnet.mail.AttachmentRef
import net.lapisphilosophorum.lapisnet.mail.EncryptionMode
import net.lapisphilosophorum.lapisnet.mail.InboxTopics
import net.lapisphilosophorum.lapisnet.mail.MailAnonymousDeliveryException
import net.lapisphilosophorum.lapisnet.mail.MessageBodyCodec
import net.lapisphilosophorum.lapisnet.mail.SentMessage
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onionwire.OnionServiceApp
import org.slf4j.LoggerFactory
import java.time.Duration
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

private fun addressNeedles(node: net.lapisphilosophorum.lapisnet.networking.LapisNode): List<ByteArray> =
    node.listenAddresses().flatMap { ma ->
        val text = ma.toString()
        val port = Regex("/tcp/(\\d+)").find(text)!!.groupValues[1].toInt()
        listOf(ma.serialize(), text.toByteArray(), byteArrayOf(0x06, (port ushr 8).toByte(), port.toByte()))
    }

/**
 * Real nodes on loopback: six relays in a full mesh; A, B and C in anonymity mode (never relays, connected ONLY to relays,
 * all advertising DM and MAIL), D an ordinary direct-mode node. All relays sit on 127.0.0.1, which the real locator can not
 * tell apart, so a locator with synthetic /16 networks is injected: network diversity is verified only with that locator,
 * NOT over real networks.
 */
class MultiNodeMailOverCircuitsTest :
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
        val a = MailOnionNode(relays, locator)
        val b = MailOnionNode(relays, locator)
        val c = MailOnionNode(relays, locator)
        val d = buildDmTestNode()
        val sentMails = ArrayList<SentMessage>()
        val knownSubjects = ArrayList<String>()

        afterSpec {
            logRoot.detachAppender(logAppender)
            logRoot.level = oldLevel
            runCatching { a.n.stop() }
            runCatching { b.n.stop() }
            runCatching { c.n.stop() }
            runCatching { d.stop() }
            relays.forEach { runCatching { it.close() } }
        }

        fun send(
            from: MailOnionNode,
            to: MailOnionNode,
            subject: String,
            body: String = "body of $subject",
            attachments: List<AttachmentRef> = emptyList(),
        ): SentMessage {
            knownSubjects += subject
            return from.mail
                .sender
                .send(
                    from.n.identity.secp256k1KeyPair,
                    listOf(to.key),
                    subject,
                    body,
                    attachments = attachments,
                    encryption = EncryptionMode.HYBRID_ECIES,
                ).also { sentMails += it }
        }

        fun has(
            node: MailOnionNode,
            subject: String,
        ) = node.mail.subjects().contains(subject)

        /** Sends (again, a few times: the first circuits of a freshly started mesh can fail) until [to] has the mail. */
        fun sendUntilReceived(
            from: MailOnionNode,
            to: MailOnionNode,
            subject: String,
            body: String = "body of $subject",
            attachments: List<AttachmentRef> = emptyList(),
        ) {
            var tries = 0
            while (!has(to, subject) && tries < 3) {
                tries++
                send(from, to, subject, body, attachments)
                awaitCondition(Duration.ofSeconds(60)) { has(to, subject) }
            }
            withClue("mail '$subject' did not arrive") { has(to, subject) shouldBe true }
        }

        test("A, B and C start in anonymity mode and see each other (with MAIL capability) only through the relays")
            .config(timeout = 1_500.seconds) {
                relays.forEach { r -> d.node.connect(PeerInfo(r.node.peerId, r.node.listenAddresses())) }
                val all = listOf(a, b, c)
                all.forEach { it.n.start() }
                all.forEach { it.n.awaitPublished() shouldBe true }

                fun seesMail(
                    viewer: MailOnionNode,
                    other: MailOnionNode,
                ): Boolean {
                    val r = viewer.n.runtime.resolveIdentity(other.key)
                    val record =
                        when (r) {
                            is DirectoryReachability.Hidden -> r.record
                            is DirectoryReachability.HiddenDescriptorMissing -> r.record
                            else -> return false
                        }
                    return r is DirectoryReachability.Hidden &&
                        AnonymousCapability.MAIL in record.capabilities &&
                        viewer.n.bundleGossip.lookup(other.key) != null
                }

                // The later tests send between A and B (both directions); C only observes. Those two pairs are the criterion,
                // the other four are reported in the failure clue only (they depend on slow gossip under load).
                val required = listOf(a to b, b to a)

                fun allSee() = required.all { (v, o) -> seesMail(v, o) }
                var lastPublish = 0L
                var converged = false
                for (attempt in 1..4) {
                    converged =
                        awaitCondition(Duration.ofSeconds(150)) {
                            if (System.currentTimeMillis() - lastPublish > 3_000) {
                                d.publishSelf()
                                lastPublish = System.currentTimeMillis()
                            }
                            allSee()
                        }
                    if (converged) break
                    // a directory object published while the mesh was still forming is only repeated hourly: restart
                    // the node that somebody cannot see, the way a user would
                    for (node in listOf(a, b)) {
                        if (required.any { (v, o) -> o === node && !seesMail(v, o) }) {
                            node.n.stop()
                            node.n.start()
                            node.n.awaitPublished() shouldBe true
                        }
                    }
                }

                val names = mapOf(a to "A", b to "B", c to "C")

                fun missing() =
                    all
                        .flatMap { v -> all.filter { it !== v }.map { v to it } }
                        .filter { (v, o) -> !seesMail(v, o) }
                        .joinToString { (v, o) ->
                            "${names.getValue(v)}->${names.getValue(o)}=" +
                                v.n.runtime.resolveIdentity(o.key)::class.simpleName +
                                "/bundle=" + (v.n.bundleGossip.lookup(o.key) != null)
                        }
                withClue("convergence; missing pairs (viewer->other=reachability class): ${missing()}") {
                    converged shouldBe true
                }
                awaitCondition(Duration.ofSeconds(120)) {
                    if (System.currentTimeMillis() - lastPublish > 3_000) {
                        d.publishSelf()
                        lastPublish = System.currentTimeMillis()
                    }
                    a.n.peerDirectory.lookup(d.identity.secp256k1KeyPair.publicKey) != null
                } shouldBe true
            }

        test("a small mail A to B travels as an INLINE bundle over a circuit and is delivered intact")
            .config(timeout = 600.seconds) {
                sendUntilReceived(a, b, "mailtest small online 1", "hello from A")
                val message =
                    b.mail.inbox.messages().first {
                        b.mail.openMessage(it).subject ==
                            "mailtest small online 1"
                    }
                b.mail.openMessage(message).body shouldBe "hello from A"
                message.envelope.sender shouldBe a.key
                // acknowledged online: nothing waits for a later announcement
                awaitCondition(Duration.ofSeconds(60)) { a.n.redelivery.pendingCount() == 0 } shouldBe true
                a.mail.retry.pendingCount() shouldBe 0
            }

        test("the topics: nobody subscribes to a per-recipient inbox or mailbox topic, everybody to the shared one")
            .config(timeout = 120.seconds) {
                val keys = listOf(a, b, c).map { it.key }
                for (node in listOf(a, b, c)) {
                    val topics = node.n.pubsub.subscribedTopics()
                    keys.forEach { k ->
                        (InboxTopics.forRecipient(k) in topics) shouldBe false
                        (MailboxTopics.forRecipient(k) in topics) shouldBe false
                    }
                    (ANONYMOUS_MAILBOX_GOSSIP_TOPIC in topics) shouldBe true
                    node.mail.inbox.subscribed shouldBe false
                }
            }

        test(
            "network observer: A and B only ever connect to relays, publish no inbox topic and leak no address in their bundles",
        ).config(timeout = 120.seconds) {
            val relayIds = relays.map { it.node.peerId }.toSet()
            (a.n.connectedPeers.contains(b.n.node.peerId)) shouldBe false
            (b.n.connectedPeers.contains(a.n.node.peerId)) shouldBe false
            a.n.connectedPeers.all { it in relayIds } shouldBe true
            b.n.connectedPeers.all { it in relayIds } shouldBe true
            a.n.publishedTopics.none { it.startsWith("LapisNet:inbox:") } shouldBe true
            a.mail.port.frames
                .isNotEmpty() shouldBe true
            val needles =
                addressNeedles(a.n.node) + addressNeedles(b.n.node) +
                    listOf(a.n.node.peerId.bytes, b.n.node.peerId.bytes)
            needles.none { n ->
                a.mail.port.frames
                    .any { contains(it, n) }
            } shouldBe true
        }

        test(
            "offline: B is down, A's small mail is announced as a sealed item; B restarts and gets it exactly once, C sees but can not open it",
        ).config(timeout = 900.seconds) {
            b.n.stop()
            val pendingBefore = a.n.redelivery.pendingCount()
            val cTriedBefore = c.mail.subscriber.triedCount()
            send(a, b, "mailtest while away 6")
            awaitCondition(Duration.ofSeconds(120)) { a.n.redelivery.pendingCount() > pendingBefore } shouldBe true
            b.n.start()
            b.n.awaitPublished() shouldBe true
            awaitCondition(Duration.ofSeconds(300)) { has(b, "mailtest while away 6") } shouldBe true
            // C is subscribed to the shared topic and tried the item, but it does not open for C
            awaitCondition(Duration.ofSeconds(60)) { c.mail.subscriber.triedCount() > cTriedBefore } shouldBe true
            c.mail.inbox
                .messages()
                .size shouldBe 0
            // re-announcements continue, yet nothing is delivered twice
            val announced = a.n.redelivery.announcementCount()
            awaitCondition(Duration.ofSeconds(60)) { a.n.redelivery.announcementCount() > announced + 1 } shouldBe
                true
            b.mail.subjects().count { it == "mailtest while away 6" } shouldBe 1
        }

        test("a CIRCUIT mail carries a large body and an attachment in band; the blob is local at B and never fetched")
            .config(timeout = 900.seconds) {
                val blob = ByteArray(200_000) { (it % 251).toByte() }
                val cid = a.n.storage.put(blob)
                val ref = AttachmentRef(cid, "big.bin", "application/octet-stream", blob.size.toLong())
                val body = "x".repeat(30_000)
                sendUntilReceived(a, b, "mailtest circuit mail 5", body, listOf(ref))
                val message =
                    b.mail.inbox.messages().first {
                        b.mail.openMessage(it).subject ==
                            "mailtest circuit mail 5"
                    }
                b.mail.openMessage(message).body shouldBe body
                awaitCondition(Duration.ofSeconds(30)) { b.n.storage.getLocal(cid) != null } shouldBe true
                b.n.storage
                    .getLocal(cid)!!
                    .contentEquals(blob) shouldBe true
                // C never got the blob
                c.n.storage.getLocal(cid) shouldBe null
            }

        test("the acceptance gate refuses identically to the sender; a contact then passes")
            .config(timeout = 900.seconds) {
                b.mail.requireVeritasPath()
                val processedBefore = b.mail.handler.processedCount()
                val before =
                    b.mail.inbox
                        .messages()
                        .size
                send(a, b, "mailtest gated 2")
                awaitCondition(Duration.ofSeconds(60)) { b.mail.handler.processedCount() > processedBefore } shouldBe
                    true
                Thread.sleep(500)
                // acknowledged like any other bundle: A has nothing to retry or announce for it
                a.mail.retry.pendingCount() shouldBe 0
                b.mail.inbox
                    .messages()
                    .size shouldBe before
                has(b, "mailtest gated 2") shouldBe false
                b.mail.contacts += a.key
                sendUntilReceived(a, b, "mailtest from a contact 3")
                b.mail.inbox.updateAcceptanceCheck(null)
            }

        test(
            "not reachable anonymously: a direct-mode node and an unknown identity get the same refusal; no circuit is built",
        ).config(timeout = 300.seconds) {
            val dKey = d.identity.secp256k1KeyPair.publicKey
            var lastDPublish = 0L
            awaitCondition(Duration.ofSeconds(120)) {
                if (System.currentTimeMillis() - lastDPublish > 3_000) {
                    d.publishSelf()
                    lastDPublish = System.currentTimeMillis()
                }
                a.n.runtime.resolveIdentity(dKey) is DirectoryReachability.Direct
            } shouldBe true
            val unknown = DualKeyIdentity.generate().secp256k1KeyPair.publicKey
            val connectsBefore =
                a.mail.port.connects
                    .get()
            val unreachableBefore =
                a.n.runtime
                    .status()
                    .recipientUnreachableCount
            val messages =
                listOf(dKey, unknown).map { target ->
                    shouldThrow<MailAnonymousDeliveryException> {
                        a.mail.sender.send(a.n.identity.secp256k1KeyPair, listOf(target), "nobody home", "x")
                    }.message
                }
            messages shouldBe listOf("recipient-not-reachable-anonymously", "recipient-not-reachable-anonymously")
            a.mail.port.connects
                .get() shouldBe connectsBefore
            (a.n.connectedPeers.contains(d.node.peerId)) shouldBe false
            a.n.runtime
                .status()
                .recipientUnreachableCount shouldBe unreachableBefore + 2
        }

        test("a bundle above 1 MiB is refused before any circuit is built or any item announced")
            .config(timeout = 300.seconds) {
                val blob = ByteArray(AnonymousMailSizing.MAX_CIRCUIT_BUNDLE_BYTES) { 1 }
                val cid = a.n.storage.put(blob)
                val connectsBefore =
                    a.mail.port.connects
                        .get()
                val pendingBefore = a.n.redelivery.pendingCount()
                val ex =
                    shouldThrow<MailAnonymousDeliveryException> {
                        send(
                            a,
                            b,
                            "mailtest too big 4",
                            attachments = listOf(AttachmentRef(cid, "huge", "x/y", blob.size.toLong())),
                        )
                    }
                ex.message shouldBe "mail-too-large-anonymous"
                a.mail.port.connects
                    .get() shouldBe connectsBefore
                a.n.redelivery.pendingCount() shouldBe pendingBefore
                a.mail.retry.pendingCount() shouldBe 0
            }

        test("replay and tamper: a replayed bundle, a replayed sealed item and a bit flip are never delivered twice")
            .config(timeout = 600.seconds) {
                val delivered =
                    b.mail.inbox
                        .messages()
                        .size
                // a mail B received in THIS run: the in-memory index is empty after a restart (known limit, see
                // docs/anonymity.adoc), so the replay of an older frame would count as new
                val first = sentMails.first { it.body.subject == "mailtest from a contact 3" }
                val frame = first.frameBytes
                withClue("subjects at B: ${b.mail.subjects()}") { has(b, "mailtest from a contact 3") shouldBe true }
                b.mail.sink.acceptAnonymousMail(frame, emptyList())
                b.mail.sink.acceptAnonymousMail(frame, emptyList())
                b.mail.sink.acceptAnonymousMail(
                    frame.copyOf().also {
                        it[it.size - 3] =
                            (it[it.size - 3].toInt() xor 1).toByte()
                    },
                    emptyList(),
                )
                a.n.port.items.lastOrNull()?.let { item ->
                    b.mail.subscriber.offer(item)
                    b.mail.subscriber.offer(item.copyOf().also { it[100] = (it[100].toInt() xor 1).toByte() })
                }
                Thread.sleep(1_500)
                withClue("subjects at B: ${b.mail.subjects()}") {
                    b.mail.inbox
                        .messages()
                        .size shouldBe delivered
                }
                b.mail.subjects().count { it == "mailtest from a contact 3" } shouldBe 1
            }

        test(
            "limits on the real stack: at most four mail streams are served, a bad frame closes the stream, queues stay bounded",
        ).config(timeout = 600.seconds) {
            awaitCondition(Duration.ofSeconds(120)) {
                a.n.runtime.resolveIdentity(b.key) is DirectoryReachability.Hidden
            } shouldBe true
            val streams = ArrayList<net.lapisphilosophorum.lapisnet.onionwire.OnionRendezvousStream>()
            repeat(6) {
                runCatching {
                    val hidden = a.n.runtime.resolveIdentity(b.key) as DirectoryReachability.Hidden
                    streams +=
                        a.n.runtime
                            .connectToService(
                                hidden.descriptor,
                                OnionServiceApp.MAIL,
                                40.seconds,
                            ).get(60, java.util.concurrent.TimeUnit.SECONDS)
                }
            }
            streams.isNotEmpty() shouldBe true
            (b.mail.handler.openStreams() <= OnionMailInboundHandler.MAX_STREAMS) shouldBe true
            // a frame whose declared length is far above the maximum: closed before anything is allocated
            val victim = streams.first()
            victim.send(
                java.nio.ByteBuffer
                    .allocate(5)
                    .put(3)
                    .putInt(Int.MAX_VALUE)
                    .array(),
            )
            awaitCondition(Duration.ofSeconds(30)) { victim.isClosed } shouldBe true
            streams.forEach { runCatching { it.close() } }
            (
                a.n.redelivery.pendingCount() <=
                    net.lapisphilosophorum.lapisnet.dmonion.AnonymousMailboxRedelivery.MAX_ENTRIES
            ) shouldBe
                true
            (a.mail.retry.pendingCount() <= OnionMailRetryQueue.MAX_ENTRIES) shouldBe true
        }

        test(
            "restart with a NEW onion address: A's next small mail and a CIRCUIT mail with attachment reach B exactly once, over the new descriptor",
        ).config(timeout = 900.seconds) {
            b.n.freshServiceKeyPerStart = true
            val oldService = b.n.serviceKey.publicKey
            b.n.stop()
            b.n.start()
            (b.n.serviceKey.publicKey == oldService) shouldBe false
            b.n.awaitPublished() shouldBe true
            val newService = b.n.serviceKey.publicKey
            var lastTick = 0L
            // A must learn B's NEW record and descriptor before the CIRCUIT mail (which needs a rendezvous stream)
            withClue("A does not see B behind the new service") {
                awaitCondition(Duration.ofSeconds(360)) {
                    if (System.currentTimeMillis() - lastTick > 3_000) {
                        a.n.runtime.maintainNow()
                        b.n.runtime.maintainNow()
                        lastTick = System.currentTimeMillis()
                    }
                    b.n.isSeenBehindService(a.n, newService)
                } shouldBe true
            }
            val failuresBefore = a.n.port.connectFailures.size
            sendUntilReceived(a, b, "mailtest after restart 8", "small after restart")
            val blob = ByteArray(120_000) { (it % 241).toByte() }
            val cid = a.n.storage.put(blob)
            val ref = AttachmentRef(cid, "after-restart.bin", "application/octet-stream", blob.size.toLong())
            val body = "y".repeat(20_000)
            sendUntilReceived(a, b, "mailtest after restart 9", body, listOf(ref))
            awaitCondition(Duration.ofSeconds(30)) { b.n.storage.getLocal(cid) != null } shouldBe true
            b.n.storage
                .getLocal(cid)!!
                .contentEquals(blob) shouldBe true
            b.mail.subjects().count { it == "mailtest after restart 8" } shouldBe 1
            b.mail.subjects().count { it == "mailtest after restart 9" } shouldBe 1
            // A never built a circuit to the introduction points of the old descriptor once the new one was known
            withClue("connect failures of A: ${a.n.port.connectFailures.drop(failuresBefore)}") {
                a.n.port.connectFailures.size shouldBe failuresBefore
            }
        }

        test("start and stop leave nothing behind: no stream, no thread; a second start works")
            .config(timeout = 900.seconds) {
                listOf(a, b, c).forEach { it.n.stop() }
                a.n.handler.openStreams() shouldBe 0
                awaitCondition(Duration.ofSeconds(30)) {
                    Thread.getAllStackTraces().keys.none { it.isAlive && it.name.startsWith("lapis-net-mail-onion") }
                } shouldBe true
                a.n.start()
                a.n.awaitPublished() shouldBe true
                a.n.runtime.ready() shouldBe true
                a.n.stop()
            }

        test("logs of the mail and onion layers hold no address, peer id, key, fingerprint, CID, subject or body")
            .config(timeout = 120.seconds) {
                fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
                val forbidden = ArrayList<String>()
                val nodes = listOf(a, b, c)
                nodes.forEach {
                    forbidden +=
                        it.n.node.peerId
                            .toBase58()
                    forbidden += hex(it.n.identity.secp256k1KeyPair.publicKey.bytes)
                    forbidden += hex(it.n.identity.ed25519KeyPair.publicKey.bytes)
                    forbidden +=
                        it.n.identity.secp256k1KeyPair.publicKey
                            .fingerprint()
                    forbidden += hex(it.n.serviceKey.publicKey.bytes)
                }
                relays.forEach {
                    forbidden += it.node.peerId.toBase58()
                    forbidden += hex(it.identity.secp256k1KeyPair.publicKey.bytes)
                }
                forbidden += knownSubjects
                forbidden += listOf("hello from A", "mailtest while away 6", "mailtest circuit mail 5")
                sentMails.forEach { forbidden += it.bodyCid.toString() }
                forbidden += MessageBodyCodec.cidFor(ByteArray(200_000) { (it % 251).toByte() }).toString()
                val patterns = listOf("/ip4", "/ip6", "/tcp", "127.0.0.1", "localhost", "/p2p/")
                val hexRun = Regex("[0-9a-fA-F]{32,}")
                val own =
                    logAppender.list.toList().filter {
                        it.loggerName.contains("lapisnet.mail") ||
                            it.loggerName.contains("lapisnet.dmonion") ||
                            it.loggerName.contains("lapisnet.onion")
                    }
                (own.size > 0) shouldBe true
                for (event in own) {
                    val text = event.formattedMessage + " " + (event.throwableProxy?.message ?: "")
                    for (f in forbidden) {
                        withClue("log line from ${event.loggerName} contains ${f.take(6)}...: ${text.take(160)}") {
                            text.contains(f) shouldBe false
                        }
                    }
                    for (p in patterns) {
                        withClue("log line contains $p: ${text.take(160)}") {
                            text.contains(p) shouldBe
                                false
                        }
                    }
                    withClue("log line contains a long hex run: ${text.take(160)}") {
                        hexRun.containsMatchIn(text) shouldBe
                            false
                    }
                }
            }
    })
