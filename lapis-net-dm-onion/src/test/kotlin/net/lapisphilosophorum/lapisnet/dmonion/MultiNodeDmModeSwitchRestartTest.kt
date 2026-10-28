@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.dmonion

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.withClue
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import net.lapisphilosophorum.lapisnet.directory.DirectoryReachability
import net.lapisphilosophorum.lapisnet.dm.DmAnonymousDeliveryException
import net.lapisphilosophorum.lapisnet.dm.DmContent
import net.lapisphilosophorum.lapisnet.dm.DmInboundMessage
import net.lapisphilosophorum.lapisnet.dm.DmSendOutcome
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onionwire.path.EncryptedFileGuardStateStore
import net.lapisphilosophorum.lapisnet.onionwire.path.GuardLoad
import java.time.Duration
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.time.Duration.Companion.seconds

/**
 * Mode switch by restart (wave I): A runs ON, then restarts in NORMAL mode, then ON again with the same data directory
 * and identity but a new service key (a new onion address). B stays in anonymity mode throughout. Documented behaviour
 * (docs/anonymity.adoc, "Refusals the user sees"): while A is in normal mode, B gets `recipient-not-reachable-anonymously`
 * and builds no circuit; once A is back ON with the same guards, B delivers again. Loopback with a synthetic locator.
 */
class MultiNodeDmModeSwitchRestartTest :
    FunSpec({
        val relays = List(6) { RelayHost() }
        for (i in relays.indices) for (j in i + 1 until relays.size) relays[i].connectTo(relays[j])
        val locator = SyntheticLocator()
        relays.forEachIndexed { i, r -> locator.put(r.key, 10 + i, i) }
        val a = DmOnionNode(relays, locator).also { it.freshServiceKeyPerStart = true }
        val b = DmOnionNode(relays, locator)
        val aReceived = CopyOnWriteArrayList<DmInboundMessage>()
        val bReceived = CopyOnWriteArrayList<DmInboundMessage>()
        var guardBefore: Secp256k1PublicKey? = null

        afterSpec {
            runCatching { a.stop() }
            runCatching { a.stopNormalMode() }
            runCatching { b.stop() }
            relays.forEach { runCatching { it.close() } }
        }

        fun primaryGuardOfA(): Secp256k1PublicKey =
            EncryptedFileGuardStateStore(a.dir.resolve("onion").resolve("guards.bin"), a.identity).use {
                it
                    .load()
                    .shouldBeInstanceOf<GuardLoad.Loaded>()
                    .state.primary!!
                    .identity
            }

        fun seesHidden(
            viewer: DmOnionNode,
            other: DmOnionNode,
        ) = viewer.runtime.resolveIdentity(other.key) is DirectoryReachability.Hidden &&
            viewer.bundleGossip.lookup(other.key) != null

        fun sendUntilDelivered(
            from: DmOnionNode,
            to: DmOnionNode,
            inbox: CopyOnWriteArrayList<DmInboundMessage>,
            body: String,
        ): DmSendOutcome? {
            var outcome: DmSendOutcome? = null
            val before = inbox.size
            repeat(3) {
                if (inbox.size == before) {
                    outcome = from.dm.sendAuto(to.key, DmContent(body = body))
                    awaitCondition(Duration.ofSeconds(40)) { inbox.size > before }
                }
            }
            return outcome
        }

        test("A and B run in anonymity mode and exchange a DM over circuits").config(timeout = 600.seconds) {
            a.start()
            b.start()
            a.dm.addInboundListener { aReceived += it }
            b.dm.addInboundListener { bReceived += it }
            a.awaitPublished() shouldBe true
            b.awaitPublished() shouldBe true
            var lastPublish = 0L
            withClue("A and B see each other") {
                awaitCondition(Duration.ofSeconds(360)) {
                    if (System.currentTimeMillis() - lastPublish > 3_000) {
                        a.runtime.maintainNow()
                        b.runtime.maintainNow()
                        lastPublish = System.currentTimeMillis()
                    }
                    seesHidden(a, b) && seesHidden(b, a)
                } shouldBe true
            }
            sendUntilDelivered(a, b, bReceived, "hello B")
            bReceived.last().content.body shouldBe "hello B"
            guardBefore = primaryGuardOfA()
        }

        test(
            "A restarts in NORMAL mode: B resolves A as direct and is refused, without any circuit to A's old descriptor",
        ).config(timeout = 600.seconds) {
            val failuresBefore = b.port.connectFailures.size
            val framesBefore = b.port.frames.size
            a.stop()
            a.startNormalMode()
            withClue("B->A ${b.runtime.resolveIdentity(a.key)::class.simpleName}") {
                awaitCondition(Duration.ofSeconds(120)) {
                    b.runtime.resolveIdentity(a.key) is DirectoryReachability.Direct
                } shouldBe true
            }
            shouldThrow<DmAnonymousDeliveryException> {
                b.dm.sendAuto(a.key, DmContent(body = "are you there"))
            }.message shouldBe "recipient-not-reachable-anonymously"
            // nothing was built or sent towards A's old (or any) service
            b.port.connectFailures.size shouldBe failuresBefore
            b.port.frames.size shouldBe framesBefore
        }

        test("A restarts ON again: same guard, a NEW onion address, B delivers over the new descriptor")
            .config(timeout = 900.seconds) {
                val oldService = a.serviceKey.publicKey
                a.stopNormalMode()
                a.start()
                a.dm.addInboundListener { aReceived += it }
                (a.serviceKey.publicKey == oldService) shouldBe false
                a.awaitPublished() shouldBe true
                var lastTick = 0L
                withClue("B->A ${b.runtime.resolveIdentity(a.key)::class.simpleName}") {
                    awaitCondition(Duration.ofSeconds(360)) {
                        if (System.currentTimeMillis() - lastTick > 3_000) {
                            a.runtime.maintainNow()
                            b.runtime.maintainNow()
                            lastTick = System.currentTimeMillis()
                        }
                        b.runtime.resolveIdentity(a.key) is DirectoryReachability.Hidden
                    } shouldBe true
                }
                // the guards of the earlier ON run survived the NORMAL interlude
                primaryGuardOfA() shouldBe guardBefore
                val outcome = sendUntilDelivered(b, a, aReceived, "welcome back")
                withClue("connect failures of B: ${b.port.connectFailures}") {
                    aReceived.last().content.body shouldBe "welcome back"
                }
                println("TIMELINE mode-switch: B->A outcome=$outcome")
            }
    })
