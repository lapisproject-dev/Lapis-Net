@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onion

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.onion.fake.FixedClock
import net.lapisphilosophorum.lapisnet.onion.fake.InMemoryOnionNetwork
import net.lapisphilosophorum.lapisnet.onion.fake.Probe
import net.lapisphilosophorum.lapisnet.onion.fake.newTestRelay

private class MailboxRig(
    limits: OnionRelayLimits = OnionRelayLimits(),
) {
    val clock = FixedClock()
    val relay = newTestRelay(clock = clock, limits = limits)
    val net = InMemoryOnionNetwork(listOf(relay))

    fun probe() = Probe(net, clock)

    fun item(fill: Int = 5): ByteArray = ByteArray(MailboxPublishBody.ITEM_SIZE) { (it + fill).toByte() }

    fun sendItem(
        p: Probe,
        index: Int,
        item: ByteArray = item(index),
    ): List<RelayMessage> {
        var last: List<RelayMessage> = emptyList()
        for (body in MailboxPublishBody.encodeItem(index, item)) last = p.send(RelayCommand.MAILBOX_PUBLISH, body)
        return last
    }

    fun establishIntroBody() =
        EstablishIntroBody
            .create(Ed25519KeyPair.generate(), relay.binding.relayIdDigest(), clock.millis() / 1000 + 600, 1)
            .encode()
}

class OnionRelayMailboxPublishTest :
    FunSpec({
        test("eight fragments are reassembled and handed to the host exactly once; the host's reply is relayed back") {
            val r = MailboxRig()
            val p = r.probe()
            val item = r.item()
            r.sendItem(p, 0, item) shouldBe emptyList()
            r.net.mailboxItems.size shouldBe 1
            r.net.mailboxItems[0]
                .second
                .contentEquals(item) shouldBe true
            r.net.apply(
                0,
                r.relay.relay.reply(
                    r.net.mailboxItems[0].first,
                    RelayMessage(RelayCommand.MAILBOX_PUBLISHED, 0, byteArrayOf(0)),
                ),
            )
            p.drain().single().command shouldBe RelayCommand.MAILBOX_PUBLISHED
            p.close()
            r.relay.relay.circuitCount shouldBe 0
        }

        test("the per-link mailbox counter is removed when the link closes") {
            val r = MailboxRig()
            val p = r.probe()
            r.sendItem(p, 0)
            r.relay.relay.mailboxCounterLinkCount() shouldBe 1
            r.relay.relay.onLinkClosed(p.client.link)
            r.relay.relay.mailboxCounterLinkCount() shouldBe 0
        }

        test("at most four items per circuit; the fifth closes the circuit") {
            val r = MailboxRig()
            val p = r.probe()
            repeat(4) { r.sendItem(p, it) }
            r.net.mailboxItems.size shouldBe 4
            p.destroyed shouldBe false
            val body = MailboxPublishBody.encodeItem(4, r.item())[0]
            p.send(RelayCommand.MAILBOX_PUBLISH, body)
            p.destroyed shouldBe true
            r.net.mailboxItems.size shouldBe 4
            r.relay.relay.circuitCount shouldBe 0
        }

        test(
            "the per-link limit is applied when an item starts and answered with a status, then the circuit is closed on more traffic",
        ) {
            val r =
                MailboxRig(OnionRelayLimits(mailboxPublishPerLinkPerMinute = 1, mailboxPublishGlobalPerMinute = 100))
            val p = r.probe()
            r.sendItem(p, 0)
            val refused = p.send(RelayCommand.MAILBOX_PUBLISH, MailboxPublishBody.encodeItem(1, r.item())[0])
            refused.single().command shouldBe RelayCommand.MAILBOX_PUBLISHED
            refused.single().data[0] shouldBe MailboxPublishStatus.RATE_LIMITED
            r.net.mailboxItems.size shouldBe 1
            p.destroyed shouldBe false
            p.send(RelayCommand.MAILBOX_PUBLISH, MailboxPublishBody.encodeItem(1, r.item())[1])
            p.destroyed shouldBe true
        }

        test("the global limit holds across circuits and refills with time") {
            val r =
                MailboxRig(OnionRelayLimits(mailboxPublishPerLinkPerMinute = 100, mailboxPublishGlobalPerMinute = 1))
            r.sendItem(r.probe(), 0)
            val second = r.probe()
            val refused = second.send(RelayCommand.MAILBOX_PUBLISH, MailboxPublishBody.encodeItem(0, r.item())[0])
            refused.single().data[0] shouldBe MailboxPublishStatus.RATE_LIMITED
            r.clock.advanceMillis(61_000)
            r.sendItem(r.probe(), 0)
            r.net.mailboxItems.size shouldBe 2
        }

        test("a wrong body length, a bad header or a wrong fragment order destroys the circuit") {
            val r = MailboxRig()
            val good = MailboxPublishBody.encodeItem(0, r.item())
            r.probe().also {
                it.send(RelayCommand.MAILBOX_PUBLISH, ByteArray(719))
                it.destroyed shouldBe true
            }
            r.probe().also {
                it.send(RelayCommand.MAILBOX_PUBLISH, good[0].copyOf().also { b -> b[2] = 7 })
                it.destroyed shouldBe true
            }
            r.probe().also {
                it.send(RelayCommand.MAILBOX_PUBLISH, good[0].copyOf().also { b -> b[3] = 1 })
                it.destroyed shouldBe true
            }
            r.probe().also {
                it.send(RelayCommand.MAILBOX_PUBLISH, good[1])
                it.destroyed shouldBe true
            }
            r.probe().also {
                it.send(RelayCommand.MAILBOX_PUBLISH, good[0])
                it.send(RelayCommand.MAILBOX_PUBLISH, good[2])
                it.destroyed shouldBe true
            }
            r.probe().also {
                it.send(RelayCommand.MAILBOX_PUBLISH, good[0])
                it.send(RelayCommand.MAILBOX_PUBLISH, MailboxPublishBody.encodeItem(1, r.item())[1])
                it.destroyed shouldBe true
            }
            r.probe().also {
                it.send(RelayCommand.MAILBOX_PUBLISH, good[0])
                it.send(RelayCommand.MAILBOX_PUBLISH, good[0])
                it.destroyed shouldBe true
            }
            r.probe().also {
                it.send(RelayCommand.MAILBOX_PUBLISH, MailboxPublishBody.encodeItem(3, r.item())[0])
                it.destroyed shouldBe true
            }
            r.net.mailboxItems.size shouldBe 0
        }

        test("an item that is not completed in time is dropped and the sweep closes the circuit") {
            val r = MailboxRig()
            val p = r.probe()
            val good = MailboxPublishBody.encodeItem(0, r.item())
            for (i in 0 until 4) p.send(RelayCommand.MAILBOX_PUBLISH, good[i])
            r.clock.advanceMillis(16_000)
            r.net.apply(0, r.relay.relay.sweepExpired())
            p.drain()
            p.destroyed shouldBe true
            r.net.mailboxItems.size shouldBe 0
            r.relay.relay.circuitCount shouldBe 0
        }

        test("a late fragment after the timeout destroys the circuit") {
            val r = MailboxRig()
            val p = r.probe()
            val good = MailboxPublishBody.encodeItem(0, r.item())
            for (i in 0 until 4) p.send(RelayCommand.MAILBOX_PUBLISH, good[i])
            r.clock.advanceMillis(16_000)
            p.send(RelayCommand.MAILBOX_PUBLISH, good[4])
            p.destroyed shouldBe true
            r.net.mailboxItems.size shouldBe 0
        }

        test("the role is only accepted at the last hop of a circuit without another role") {
            val r = MailboxRig()
            val withRole = r.probe()
            withRole.send(RelayCommand.ESTABLISH_INTRO, r.establishIntroBody())
            withRole.send(RelayCommand.MAILBOX_PUBLISH, MailboxPublishBody.encodeItem(0, r.item())[0])
            withRole.destroyed shouldBe true

            val publishing = r.probe()
            publishing.send(RelayCommand.MAILBOX_PUBLISH, MailboxPublishBody.encodeItem(0, r.item())[0])
            publishing.send(RelayCommand.DIRECTORY_PUBLISH, ByteArray(720))
            publishing.destroyed shouldBe true
        }

        test("EXTEND, DATA and reply commands on a publishing circuit destroy it") {
            val r = MailboxRig()
            for (command in listOf(RelayCommand.EXTEND, RelayCommand.DATA, RelayCommand.MAILBOX_PUBLISHED)) {
                val p = r.probe()
                r.sendItem(p, 0)
                p.send(command, ByteArray(10))
                p.destroyed shouldBe true
            }
        }

        test("the codec round trips and rejects out-of-range input") {
            val item = MailboxPublishBody.randomItem()
            val bodies = MailboxPublishBody.encodeItem(2, item)
            bodies.size shouldBe MailboxPublishBody.FRAGMENT_COUNT
            bodies.all { it.size == MailboxPublishBody.BODY_SIZE } shouldBe true
            val joined = bodies.map { MailboxPublishBody.fragmentOf(it) }.reduce { a, b -> a + b }
            joined.contentEquals(item) shouldBe true
            MailboxPublishBody.decodeHeader(bodies[3]).fragIndex shouldBe 3
            MailboxPublishBody.decodeHeader(bodies[3]).itemIndex shouldBe 2
        }
    })
