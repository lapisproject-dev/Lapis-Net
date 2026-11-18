@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onion

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.onion.fake.FixedClock
import net.lapisphilosophorum.lapisnet.onion.fake.InMemoryOnionNetwork
import net.lapisphilosophorum.lapisnet.onion.fake.Probe
import net.lapisphilosophorum.lapisnet.onion.fake.newTestRelay
import java.security.SecureRandom

private class LookupRig(
    limits: OnionRelayLimits = OnionRelayLimits(),
    relays: Int = 1,
) {
    val clock = FixedClock()
    val relayList = List(relays) { newTestRelay(clock = clock, limits = limits) }
    val relay = relayList.last()
    val net = InMemoryOnionNetwork(relayList)
    val random = SecureRandom()

    fun probe() = Probe(net, clock, idx = relayList.size - 1)

    fun request(id: Int = 1) = LookupRequestBody.encode(id, LookupOperation.GET_BLOCK, ByteArray(36) { 3 }, random)

    /** Answers the last delivered request with the fragments of NOT_FOUND. */
    fun answerLast() {
        val req = net.lookupRequests.last()
        for (f in LookupResponseBody.encodeAnswer(req.requestId, LookupStatus.NOT_FOUND, ByteArray(0), random)) {
            net.apply(relayList.size - 1, relay.relay.replyLookupFragment(req.circuitHandle, f))
        }
    }
}

class OnionRelayLookupTest :
    FunSpec({
        test("a request at the last hop is delivered to the host; the host's fragments travel back") {
            val r = LookupRig()
            val p = r.probe()
            p.send(RelayCommand.LOOKUP_REQUEST, r.request(42)) shouldBe emptyList()
            r.net.lookupRequests.size shouldBe 1
            val req = r.net.lookupRequests.single()
            req.requestId shouldBe 42
            req.op shouldBe LookupOperation.GET_BLOCK
            req.toString().contains("0303") shouldBe false
            r.answerLast()
            val back = p.drain()
            back.size shouldBe 3
            back.all { it.command == RelayCommand.LOOKUP_RESPONSE } shouldBe true
            p.destroyed shouldBe false
        }

        test("a lookup addressed to a middle hop destroys the circuit") {
            val r = LookupRig(relays = 2)
            val client = r.net.newClient(0)
            val circuit = r.net.buildCircuitFor(client, listOf(0, 1), SecureRandom(), r.clock)
            r.net.clientSend(
                0,
                client.link,
                Cell(
                    client.circuitId,
                    CellCommand.RELAY,
                    circuit.wrapForward(RelayMessage(RelayCommand.LOOKUP_REQUEST, 0, r.request()), 1),
                ),
            )
            client.inbox.any { it.command == CellCommand.DESTROY } shouldBe true
            r.net.lookupRequests.size shouldBe 0
        }

        test(
            "roles are exclusive: a lookup after a directory publish and a publish after a lookup destroy the circuit",
        ) {
            val r = LookupRig()
            val a = r.probe()
            a.send(
                RelayCommand.DIRECTORY_PUBLISH,
                DirectoryPublishBody.encode(DirectoryObjectType.ANONYMOUS_PEER_RECORD, ByteArray(248) { 7 }, r.random),
            )
            a.send(RelayCommand.LOOKUP_REQUEST, r.request())
            a.destroyed shouldBe true
            a.destroyReason shouldBe DestroyReason.PROTOCOL

            val b = r.probe()
            b.send(RelayCommand.LOOKUP_REQUEST, r.request())
            r.answerLast()
            b.send(
                RelayCommand.DIRECTORY_PUBLISH,
                DirectoryPublishBody.encode(DirectoryObjectType.ANONYMOUS_PEER_RECORD, ByteArray(248) { 7 }, r.random),
            )
            b.destroyed shouldBe true
        }

        test("four sequential lookups per circuit; the fifth closes it with RESOURCE_LIMIT") {
            val r = LookupRig()
            val p = r.probe()
            repeat(4) {
                p.send(RelayCommand.LOOKUP_REQUEST, r.request(it))
                r.answerLast()
                p.drain()
                p.destroyed shouldBe false
            }
            p.send(RelayCommand.LOOKUP_REQUEST, r.request(5))
            p.destroyed shouldBe true
            p.destroyReason shouldBe DestroyReason.RESOURCE_LIMIT
            r.net.lookupRequests.size shouldBe 4
        }

        test("a second request while the first is outstanding destroys the circuit with PROTOCOL") {
            val r = LookupRig()
            val p = r.probe()
            p.send(RelayCommand.LOOKUP_REQUEST, r.request(1))
            p.send(RelayCommand.LOOKUP_REQUEST, r.request(2))
            p.destroyed shouldBe true
            p.destroyReason shouldBe DestroyReason.PROTOCOL
            r.net.lookupRequests.size shouldBe 1
        }

        test("the per-link limit answers RATE_LIMITED in three fragments without reaching the host") {
            val r = LookupRig(OnionRelayLimits(lookupRequestsPerLinkPerMinute = 1, lookupRequestsGlobalPerMinute = 100))
            val p = r.probe()
            p.send(RelayCommand.LOOKUP_REQUEST, r.request(1))
            r.answerLast()
            p.drain()
            val refused = p.send(RelayCommand.LOOKUP_REQUEST, r.request(2))
            refused.size shouldBe 3
            val h = LookupResponseBody.decodeFragmentHeader(refused[0].data)
            h.requestId shouldBe 2
            LookupResponseBody.decodeAnswerHeader(refused[0].data, h.fragCount).status shouldBe
                LookupStatus.RATE_LIMITED
            r.net.lookupRequests.size shouldBe 1
            p.destroyed shouldBe false
        }

        test("the global limit holds across circuits and refills after a minute") {
            val r = LookupRig(OnionRelayLimits(lookupRequestsPerLinkPerMinute = 100, lookupRequestsGlobalPerMinute = 1))
            r.probe().send(RelayCommand.LOOKUP_REQUEST, r.request())
            val second = r.probe().send(RelayCommand.LOOKUP_REQUEST, r.request())
            LookupResponseBody.decodeAnswerHeader(second[0].data, 3).status shouldBe LookupStatus.RATE_LIMITED
            r.clock.advanceMillis(61_000)
            r.probe().send(RelayCommand.LOOKUP_REQUEST, r.request())
            r.net.lookupRequests.size shouldBe 2
        }

        test("lookupEnabled=false answers DISABLED in three fragments and keeps the circuit") {
            val r = LookupRig(OnionRelayLimits(lookupEnabled = false))
            val p = r.probe()
            val answer = p.send(RelayCommand.LOOKUP_REQUEST, r.request(7))
            answer.size shouldBe 3
            LookupResponseBody.decodeAnswerHeader(answer[0].data, 3).status shouldBe LookupStatus.DISABLED
            r.net.lookupRequests.size shouldBe 0
            p.destroyed shouldBe false
        }

        test("an unknown version or operation is answered with its status") {
            val r = LookupRig()
            val p = r.probe()
            val answer = p.send(RelayCommand.LOOKUP_REQUEST, r.request(3).also { it[2] = 77 })
            LookupResponseBody.decodeAnswerHeader(answer[0].data, 3).status shouldBe LookupStatus.UNSUPPORTED_OPERATION
            val answer2 = p.send(RelayCommand.LOOKUP_REQUEST, r.request(4).also { it[0] = 9 })
            LookupResponseBody.decodeAnswerHeader(answer2[0].data, 3).status shouldBe LookupStatus.UNSUPPORTED_VERSION
            r.net.lookupRequests.size shouldBe 0
        }

        test("a wrong length or broken header destroys the circuit") {
            val r = LookupRig()
            r.probe().also {
                it.send(RelayCommand.LOOKUP_REQUEST, ByteArray(100))
                it.destroyed shouldBe true
            }
            r.probe().also {
                it.send(RelayCommand.LOOKUP_REQUEST, r.request().also { b -> b[3] = 1 })
                it.destroyed shouldBe true
            }
        }

        test("a relay of the old version (legacyNoLookup) destroys the circuit with AUTH_FAILED") {
            val r = LookupRig()
            r.relay.relay.legacyNoLookup = true
            val p = r.probe()
            p.send(RelayCommand.LOOKUP_REQUEST, r.request())
            p.destroyed shouldBe true
            p.destroyReason shouldBe DestroyReason.AUTH_FAILED
            r.net.lookupRequests.size shouldBe 0
        }

        test("a LOOKUP_RESPONSE arriving at a relay destroys the circuit") {
            val r = LookupRig()
            val p = r.probe()
            p.send(
                RelayCommand.LOOKUP_RESPONSE,
                LookupResponseBody.encodeAnswer(1, LookupStatus.NOT_FOUND, ByteArray(0), r.random)[0],
            )
            p.destroyed shouldBe true
            p.destroyReason shouldBe DestroyReason.PROTOCOL
        }

        test("fragments without an outstanding request are not sent") {
            val r = LookupRig()
            val p = r.probe()
            p.send(RelayCommand.LOOKUP_REQUEST, r.request(1))
            r.answerLast()
            p.drain().size shouldBe 3
            val handle =
                r.net.lookupRequests
                    .last()
                    .circuitHandle
            val extra = LookupResponseBody.encodeAnswer(1, LookupStatus.NOT_FOUND, ByteArray(0), r.random)[0]
            r.net.apply(0, r.relay.relay.replyLookupFragment(handle, extra))
            p.drain().size shouldBe 0
        }
    })
