@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onion

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.onion.fake.FixedClock
import net.lapisphilosophorum.lapisnet.onion.fake.InMemoryOnionNetwork
import net.lapisphilosophorum.lapisnet.onion.fake.Probe
import net.lapisphilosophorum.lapisnet.onion.fake.newTestRelay
import java.security.SecureRandom

private class PublishRig(
    limits: OnionRelayLimits = OnionRelayLimits(),
) {
    val clock = FixedClock()
    val relay = newTestRelay(clock = clock, limits = limits)
    val net = InMemoryOnionNetwork(listOf(relay))
    private val random = SecureRandom()

    fun probe() = Probe(net, clock)

    fun body(
        type: DirectoryObjectType = DirectoryObjectType.ANONYMOUS_PEER_RECORD,
        size: Int = 248,
    ) = DirectoryPublishBody.encode(type, ByteArray(size) { 7 }, random)

    fun establishIntroBody() =
        EstablishIntroBody
            .create(
                Ed25519KeyPair.generate(),
                relay.binding.relayIdDigest(),
                clock.millis() / 1000 + 600,
                1,
            ).encode()
}

class OnionRelayDirectoryPublishTest :
    FunSpec({
        test(
            "a publish at the last hop of a role-less circuit is delivered to the host, the host's reply is relayed back",
        ) {
            val r = PublishRig()
            val p = r.probe()
            p.send(RelayCommand.DIRECTORY_PUBLISH, r.body()) shouldBe emptyList()
            r.net.publishes.size shouldBe 1
            val handle =
                r.net.publishes
                    .single()
                    .circuitHandle
            r.net.apply(
                0,
                r.relay.relay.reply(handle, RelayMessage(RelayCommand.DIRECTORY_PUBLISHED, 0, byteArrayOf(0))),
            )
            val answers = p.drain()
            answers.single().command shouldBe RelayCommand.DIRECTORY_PUBLISHED
            answers.single().data[0] shouldBe 0
            p.close()
            r.relay.relay.circuitCount shouldBe 0
        }

        test("at most four publishes per circuit are served, the fifth closes it") {
            val r = PublishRig()
            val p = r.probe()
            repeat(4) { p.send(RelayCommand.DIRECTORY_PUBLISH, r.body()) }
            r.net.publishes.size shouldBe 4
            p.destroyed shouldBe false
            p.send(RelayCommand.DIRECTORY_PUBLISH, r.body())
            p.destroyed shouldBe true
            r.net.publishes.size shouldBe 4
            r.relay.relay.circuitCount shouldBe 0
        }

        test("the global and the per-link limits are checked before the body is looked at and answered with a status") {
            val limits = OnionRelayLimits(directoryPublishPerLinkPerMinute = 2, directoryPublishGlobalPerMinute = 100)
            val r = PublishRig(limits)
            val p = r.probe()
            p.send(RelayCommand.DIRECTORY_PUBLISH, r.body())
            p.send(RelayCommand.DIRECTORY_PUBLISH, r.body())
            // over the limit: even a body of the wrong length gets only the status, it is not parsed
            val refused = p.send(RelayCommand.DIRECTORY_PUBLISH, ByteArray(5))
            refused.single().command shouldBe RelayCommand.DIRECTORY_PUBLISHED
            refused.single().data[0] shouldBe DirectoryPublishStatus.RATE_LIMITED
            r.net.publishes.size shouldBe 2
            p.destroyed shouldBe false

            val g =
                PublishRig(
                    OnionRelayLimits(directoryPublishPerLinkPerMinute = 100, directoryPublishGlobalPerMinute = 1),
                )
            g.probe().send(RelayCommand.DIRECTORY_PUBLISH, g.body())
            val second = g.probe().send(RelayCommand.DIRECTORY_PUBLISH, g.body())
            second.single().data[0] shouldBe DirectoryPublishStatus.RATE_LIMITED
            g.net.publishes.size shouldBe 1
        }

        test("the limits refill with time") {
            val r = PublishRig(OnionRelayLimits(directoryPublishGlobalPerMinute = 1))
            r.probe().send(RelayCommand.DIRECTORY_PUBLISH, r.body())
            r
                .probe()
                .send(RelayCommand.DIRECTORY_PUBLISH, r.body())
                .single()
                .data[0] shouldBe
                DirectoryPublishStatus.RATE_LIMITED
            r.clock.advanceMillis(61_000)
            r.probe().send(RelayCommand.DIRECTORY_PUBLISH, r.body()) shouldBe emptyList()
            r.net.publishes.size shouldBe 2
        }

        test("a wrong body length or an overflowing length field destroys the circuit; an unknown type is answered") {
            val r = PublishRig()
            r.probe().also {
                it.send(RelayCommand.DIRECTORY_PUBLISH, ByteArray(719))
                it.destroyed shouldBe true
            }
            r.probe().also {
                it.send(RelayCommand.DIRECTORY_PUBLISH, r.body().also { b -> b[1] = 0x7F })
                it.destroyed shouldBe true
            }
            val unknown = r.probe()
            val answer = unknown.send(RelayCommand.DIRECTORY_PUBLISH, r.body().also { b -> b[0] = 9 })
            answer.single().data[0] shouldBe DirectoryPublishStatus.UNKNOWN_TYPE
            r.net.publishes.size shouldBe 0
        }

        test("the role is only accepted at the last hop of a circuit without another role") {
            val r = PublishRig()
            val withRole = r.probe()
            withRole.send(RelayCommand.ESTABLISH_INTRO, r.establishIntroBody())
            withRole.send(RelayCommand.DIRECTORY_PUBLISH, r.body())
            withRole.destroyed shouldBe true

            val publishing = r.probe()
            publishing.send(RelayCommand.DIRECTORY_PUBLISH, r.body())
            publishing.send(RelayCommand.ESTABLISH_INTRO, r.establishIntroBody())
            publishing.destroyed shouldBe true
            r.net.publishes.size shouldBe 1
        }

        test("EXTEND, DATA and reply commands on a publishing circuit destroy it") {
            val r = PublishRig()
            for (command in listOf(RelayCommand.EXTEND, RelayCommand.DATA, RelayCommand.DIRECTORY_PUBLISHED)) {
                val p = r.probe()
                p.send(RelayCommand.DIRECTORY_PUBLISH, r.body())
                p.send(command, ByteArray(10))
                p.destroyed shouldBe true
            }
        }

        test("a DIRECTORY_PUBLISHED reply sent TO a relay as if it were a request destroys the circuit") {
            val r = PublishRig()
            val p = r.probe()
            p.send(RelayCommand.DIRECTORY_PUBLISHED, byteArrayOf(0))
            p.destroyed shouldBe true
        }

        test("closing circuits leaves nothing behind") {
            val r = PublishRig()
            repeat(5) {
                r.probe().also { p ->
                    p.send(RelayCommand.DIRECTORY_PUBLISH, r.body())
                    p.close()
                }
            }
            r.relay.relay.circuitCount shouldBe 0
        }
    })
