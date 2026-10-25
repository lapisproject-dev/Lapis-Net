@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.mailonion

import io.kotest.assertions.withClue
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.directory.DirectoryReachability
import net.lapisphilosophorum.lapisnet.dm.DmContent
import net.lapisphilosophorum.lapisnet.dm.DmInboundMessage
import net.lapisphilosophorum.lapisnet.dmonion.DmCircuitFraming
import net.lapisphilosophorum.lapisnet.dmonion.RelayHost
import net.lapisphilosophorum.lapisnet.dmonion.SyntheticLocator
import net.lapisphilosophorum.lapisnet.dmonion.awaitCondition
import net.lapisphilosophorum.lapisnet.mail.EncryptionMode
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onionwire.anonymity.TrafficPaddingConfig
import java.time.Duration
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.time.Duration.Companion.seconds

/**
 * Real nodes on loopback (wave V0.10.0-H): six relays, A with padding standard (cover off, so that the count of cells
 * is deterministic), B with padding off as the control. The relays sit on 127.0.0.1, so a locator with synthetic /16
 * networks is injected (diversity is verified only with it). The observer sees what a network observer of the guard link
 * sees: relay cells of 1024 bytes in a number that is a function of the size CLASS, not of the message length.
 */
class MultiNodePaddingOverCircuitsTest :
    FunSpec({
        val relays = List(6) { RelayHost() }
        for (i in relays.indices) for (j in i + 1 until relays.size) relays[i].connectTo(relays[j])
        val locator = SyntheticLocator()
        relays.forEachIndexed { i, r -> locator.put(r.key, 10 + i, i) }
        val a = MailOnionNode(relays, locator, TrafficPaddingConfig(cover = false))
        val b = MailOnionNode(relays, locator, TrafficPaddingConfig.OFF)
        val aGot = CopyOnWriteArrayList<DmInboundMessage>()
        val bGot = CopyOnWriteArrayList<DmInboundMessage>()

        afterSpec {
            runCatching { a.n.stop() }
            runCatching { b.n.stop() }
            relays.forEach { runCatching { it.close() } }
        }

        /** Chunks of the DM or mail frame that [port] handed to its stream since [from], and the declared length of it. */
        fun chunkCount(
            frames: List<ByteArray>,
            from: Int,
        ): Int = frames.size - from

        test("A and B start and find each other through the relays").config(timeout = 900.seconds) {
            a.n.start()
            b.n.start()
            a.n.awaitPublished() shouldBe true
            b.n.awaitPublished() shouldBe true

            fun sees(
                x: MailOnionNode,
                y: MailOnionNode,
            ) = x.n.runtime.resolveIdentity(y.key) is DirectoryReachability.Hidden &&
                x.n.bundleGossip.lookup(y.key) != null
            var ok = false
            for (attempt in 1..4) {
                ok = awaitCondition(Duration.ofSeconds(75)) { sees(a, b) && sees(b, a) }
                if (ok) break
                if (!sees(b, a)) {
                    a.n.stop()
                    a.n.start()
                    a.n.awaitPublished() shouldBe true
                }
                if (!sees(a, b)) {
                    b.n.stop()
                    b.n.start()
                    b.n.awaitPublished() shouldBe true
                }
            }
            ok shouldBe true
            a.n.dm.addInboundListener { aGot += it }
            b.n.dm.addInboundListener { bGot += it }
        }

        test(
            "direct messages: the cell count of a padded sender is a function of the size class, the control shows the length",
        ).config(timeout = 900.seconds) {
            fun sendA(body: String): Int {
                val before = a.n.port.frames.size
                val received = bGot.size
                repeat(3) {
                    if (bGot.size == received) {
                        a.n.dm.sendAuto(b.key, DmContent(body = body))
                        awaitCondition(Duration.ofSeconds(30)) { bGot.size > received }
                    }
                }
                withClue("message to B did not arrive") { (bGot.size > received) shouldBe true }
                return chunkCount(a.n.port.frames, before)
            }

            fun sendB(body: String): Int {
                val before = b.n.port.frames.size
                val received = aGot.size
                repeat(3) {
                    if (aGot.size == received) {
                        b.n.dm.sendAuto(a.key, DmContent(body = body))
                        awaitCondition(Duration.ofSeconds(30)) { aGot.size > received }
                    }
                }
                withClue("message to A did not arrive") { (aGot.size > received) shouldBe true }
                return chunkCount(b.n.port.frames, before)
            }
            sendA("warm up the session") // the handshake message and the circuit setup
            val small = sendA("s".repeat(100))
            val smallish = sendA("t".repeat(300))
            small shouldBe smallish
            val big = sendA("u".repeat(1000))
            val bigger = sendA("v".repeat(1400))
            big shouldBe bigger
            (big > small) shouldBe true
            // every recorded chunk is a full relay cell payload: no length is visible in a short last chunk
            a.n.port.frames
                .all { it.size == DmCircuitFraming.DEFAULT_MAX_PAYLOAD } shouldBe true

            // control: B has padding off, its chunk counts follow the length
            sendB("warm up B")
            val cSmall = sendB("s".repeat(100))
            val cBig = sendB("u".repeat(1000))
            withClue("control: $cSmall vs $cBig") { (cBig > cSmall) shouldBe true }
            b.n.port.frames
                .any { it.size < 910 } shouldBe true
        }

        test("mail: two bundles of one size class have the same cell count at the padded sender") {
            fun sendMail(
                from: MailOnionNode,
                to: MailOnionNode,
                subject: String,
                size: Int,
            ): Int {
                val before = from.mail.port.frames.size
                var tries = 0
                while (!to.mail.subjects().contains(subject) && tries < 3) {
                    tries++
                    from.mail.sender.send(
                        from.n.identity.secp256k1KeyPair,
                        listOf(to.key),
                        subject,
                        "m".repeat(size),
                        encryption = EncryptionMode.HYBRID_ECIES,
                    )
                    awaitCondition(Duration.ofSeconds(60)) { to.mail.subjects().contains(subject) }
                }
                withClue("mail '$subject' did not arrive") { to.mail.subjects().contains(subject) shouldBe true }
                return from.mail.port.frames.size - before
            }
            sendMail(a, b, "warm", 100)
            val c1 = sendMail(a, b, "mail 20k", 20_000)
            val c2 = sendMail(a, b, "mail 28k", 28_000)
            withClue("20 KB vs 28 KB: $c1 vs $c2") { c1 shouldBe c2 }
            a.mail.port.frames
                .all { it.size == 910 } shouldBe true
        }
    })
