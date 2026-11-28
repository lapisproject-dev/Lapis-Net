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

    fun batchRequest(
        id: Int = 1,
        n: Int = 2,
        seed: Int = 0,
    ) = LookupBatchRequestBody.encode(
        id,
        LookupOperation.GET_BLOCK,
        List(n) { i -> ByteArray(36) { (seed * 10 + i + 1).toByte() } },
        random,
    )

    /** The fragments of a NOT_FOUND answer to every item of the last delivered batch. */
    fun lastBatchAnswer(): List<ByteArray> {
        val b = net.lookupBatches.last()
        return LookupBatchResponseBody.encodeBatch(
            b.requestId,
            b.keys.map { LookupStatus.NOT_FOUND to ByteArray(0) },
            random,
        )
    }

    fun replyBatchFragment(
        index: Int,
        frags: List<ByteArray> = lastBatchAnswer(),
    ) = net.apply(
        relayList.size - 1,
        relay.relay.replyLookupFragment(net.lookupBatches.last().circuitHandle, frags[index]),
    )

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

        test(
            "a version-2 batch is delivered with its keys; the circuit stays busy until the last fragment of the last item",
        ) {
            val r = LookupRig()
            val p = r.probe()
            p.send(RelayCommand.LOOKUP_REQUEST, r.batchRequest(5, 3)) shouldBe emptyList()
            r.net.lookupRequests.size shouldBe 0
            val b = r.net.lookupBatches.single()
            b.requestId shouldBe 5
            b.keys.size shouldBe 3
            b.toString() shouldBe "DeliverLookupBatch(op=GET_BLOCK, items=3)"
            val frags = r.lastBatchAnswer()
            frags.size shouldBe 9
            for (i in 0 until 8) r.replyBatchFragment(i, frags)
            p.drain().size shouldBe 8
            // still outstanding: a second request now destroys the circuit
            p.send(RelayCommand.LOOKUP_REQUEST, r.batchRequest(6, 1))
            p.destroyed shouldBe true
            p.destroyReason shouldBe DestroyReason.PROTOCOL
        }

        test("after the last fragment of the last item the next request is accepted") {
            val r = LookupRig()
            val p = r.probe()
            p.send(RelayCommand.LOOKUP_REQUEST, r.batchRequest(5, 2))
            val frags = r.lastBatchAnswer()
            for (i in frags.indices) r.replyBatchFragment(i, frags)
            p.drain().size shouldBe 6
            p.send(RelayCommand.LOOKUP_REQUEST, r.batchRequest(6, 2, seed = 1)) shouldBe emptyList()
            p.destroyed shouldBe false
            r.net.lookupBatches.size shouldBe 2
        }

        test("the end of the first item does not end the batch: a batch needs the last fragment of the last item") {
            val r = LookupRig()
            val p = r.probe()
            p.send(RelayCommand.LOOKUP_REQUEST, r.batchRequest(5, 2))
            val frags = r.lastBatchAnswer()
            for (i in 0 until 3) r.replyBatchFragment(i, frags) // item 0 is complete
            p.drain().size shouldBe 3
            p.send(RelayCommand.LOOKUP_REQUEST, r.batchRequest(6, 1, seed = 2))
            p.destroyed shouldBe true
        }

        test("fragments of the wrong version for the open request are dropped and the request stays open") {
            val r = LookupRig()
            val p = r.probe()
            p.send(RelayCommand.LOOKUP_REQUEST, r.batchRequest(5, 2))
            val v1 = LookupResponseBody.encodeAnswer(5, LookupStatus.NOT_FOUND, ByteArray(0), r.random)
            for (f in v1) {
                r.net.apply(
                    0,
                    r.relay.relay.replyLookupFragment(
                        r.net.lookupBatches
                            .last()
                            .circuitHandle,
                        f,
                    ),
                )
            }
            p.drain().size shouldBe 0
            r.replyBatchFragment(0)
            p.drain().size shouldBe 1
            // and a version-2 fragment for a version-1 request is dropped as well
            val q = r.probe()
            q.send(RelayCommand.LOOKUP_REQUEST, r.request(8))
            val v2 = LookupBatchResponseBody.encodeBatch(8, listOf(LookupStatus.NOT_FOUND to ByteArray(0)), r.random)
            for (f in v2) {
                r.net.apply(
                    0,
                    r.relay.relay.replyLookupFragment(
                        r.net.lookupRequests
                            .last()
                            .circuitHandle,
                        f,
                    ),
                )
            }
            q.drain().size shouldBe 0
        }

        test("the per-link and global counters are charged per item and all or nothing") {
            val r = LookupRig(OnionRelayLimits(lookupRequestsPerLinkPerMinute = 8, lookupRequestsGlobalPerMinute = 100))
            val p = r.probe()
            p.send(RelayCommand.LOOKUP_REQUEST, r.batchRequest(1, 8))
            r.net.lookupBatches.size shouldBe 1
            val frags = r.lastBatchAnswer()
            for (i in frags.indices) r.replyBatchFragment(i, frags)
            p.drain().size shouldBe 24
            // the link allowance of this minute is used up: a batch of two is refused per item, in version-2 framing
            val refused = p.send(RelayCommand.LOOKUP_REQUEST, r.batchRequest(2, 2, seed = 1))
            refused.size shouldBe 6
            for ((i, m) in refused.withIndex()) {
                val h = LookupBatchResponseBody.decodeFragmentHeader(m.data, 2)
                h.itemIndex shouldBe i / 3
                h.requestId shouldBe 2
                LookupBatchResponseBody.decodeAnswerHeader(refused[(i / 3) * 3].data, 3).status shouldBe
                    LookupStatus.RATE_LIMITED
            }
            r.net.lookupBatches.size shouldBe 1
            p.destroyed shouldBe false
        }

        test("WindowCounter.tryAcquire(n) is all or nothing") {
            val clock = FixedClock()
            val c = WindowCounter(5, clock)
            c.tryAcquire(3) shouldBe true
            c.tryAcquire(3) shouldBe false
            c.tryAcquire(2) shouldBe true
            c.tryAcquire() shouldBe false
            clock.advanceMillis(61_000)
            c.tryAcquire(5) shouldBe true
        }

        test("more than lookupItemsPerCircuit items on one circuit close it with RESOURCE_LIMIT") {
            val r = LookupRig(OnionRelayLimits(lookupItemsPerCircuit = 5))
            val p = r.probe()
            p.send(RelayCommand.LOOKUP_REQUEST, r.batchRequest(1, 3))
            val frags = r.lastBatchAnswer()
            for (i in frags.indices) r.replyBatchFragment(i, frags)
            p.drain()
            p.send(RelayCommand.LOOKUP_REQUEST, r.batchRequest(2, 3, seed = 1))
            p.destroyed shouldBe true
            p.destroyReason shouldBe DestroyReason.RESOURCE_LIMIT
            r.net.lookupBatches.size shouldBe 1
        }

        test("the four-request limit per circuit holds for batches too") {
            val r = LookupRig()
            val p = r.probe()
            repeat(4) {
                p.send(RelayCommand.LOOKUP_REQUEST, r.batchRequest(it, 1, seed = it))
                val frags = r.lastBatchAnswer()
                for (i in frags.indices) r.replyBatchFragment(i, frags)
                p.drain()
            }
            p.send(RelayCommand.LOOKUP_REQUEST, r.batchRequest(9, 1, seed = 9))
            p.destroyed shouldBe true
            p.destroyReason shouldBe DestroyReason.RESOURCE_LIMIT
        }

        test("lookupEnabled=false answers DISABLED for every item in version-2 framing and keeps the circuit") {
            val r = LookupRig(OnionRelayLimits(lookupEnabled = false))
            val p = r.probe()
            val answer = p.send(RelayCommand.LOOKUP_REQUEST, r.batchRequest(7, 3))
            answer.size shouldBe 9
            for (item in 0 until 3) {
                LookupBatchResponseBody.decodeAnswerHeader(answer[item * 3].data, 3).status shouldBe
                    LookupStatus.DISABLED
            }
            r.net.lookupBatches.size shouldBe 0
            p.destroyed shouldBe false
        }

        test("an unknown operation in a batch is answered per item") {
            val r = LookupRig()
            val p = r.probe()
            val answer = p.send(RelayCommand.LOOKUP_REQUEST, r.batchRequest(3, 2).also { it[2] = 77 })
            answer.size shouldBe 6
            LookupBatchResponseBody.decodeAnswerHeader(answer[3].data, 3).status shouldBe
                LookupStatus.UNSUPPORTED_OPERATION
            r.net.lookupBatches.size shouldBe 0
        }

        test("version 3 is answered UNSUPPORTED_VERSION in the version-1 framing") {
            val r = LookupRig()
            val p = r.probe()
            val answer = p.send(RelayCommand.LOOKUP_REQUEST, r.batchRequest(3, 2).also { it[0] = 3 })
            answer.size shouldBe 3
            LookupResponseBody.decodeAnswerHeader(answer[0].data, 3).status shouldBe LookupStatus.UNSUPPORTED_VERSION
            p.destroyed shouldBe false
        }

        test("a malformed batch destroys the circuit (item count 0, duplicate keys, flags)") {
            val r = LookupRig()
            r.probe().also {
                it.send(RelayCommand.LOOKUP_REQUEST, r.batchRequest(1, 2).also { b -> b[5] = 0 })
                it.destroyed shouldBe true
            }
            r.probe().also {
                it.send(RelayCommand.LOOKUP_REQUEST, r.batchRequest(1, 2).also { b -> b[3] = 1 })
                it.destroyed shouldBe true
            }
            val same =
                LookupBatchRequestBody.encode(
                    1,
                    LookupOperation.GET_BLOCK,
                    listOf(
                        ByteArray(36) {
                            1
                        },
                        ByteArray(36) { 2 },
                    ),
                    r.random,
                )
            for (i in 0 until 36) same[6 + 37 + 1 + i] = 1
            r.probe().also {
                it.send(RelayCommand.LOOKUP_REQUEST, same)
                it.destroyed shouldBe true
            }
            r.net.lookupBatches.size shouldBe 0
        }

        test(
            "a relay that behaves like 0.13.0 answers a batch with UNSUPPORTED_VERSION in three fragments and lives on",
        ) {
            val r = LookupRig()
            r.relay.relay.lookupV1OnlyForTest = true
            val p = r.probe()
            val answer = p.send(RelayCommand.LOOKUP_REQUEST, r.batchRequest(4, 4))
            answer.size shouldBe 3
            val h = LookupResponseBody.decodeFragmentHeader(answer[0].data)
            h.requestId shouldBe 4
            LookupResponseBody.decodeAnswerHeader(answer[0].data, h.fragCount).status shouldBe
                LookupStatus.UNSUPPORTED_VERSION
            p.destroyed shouldBe false
            r.net.lookupBatches.size shouldBe 0
            // version 1 still works on the same circuit
            p.send(RelayCommand.LOOKUP_REQUEST, r.request(5))
            r.net.lookupRequests.size shouldBe 1
        }

        test("a relay without the lookup role (legacyNoLookup) destroys the circuit on a batch, like on any lookup") {
            val r = LookupRig()
            r.relay.relay.legacyNoLookup = true
            val p = r.probe()
            p.send(RelayCommand.LOOKUP_REQUEST, r.batchRequest())
            p.destroyed shouldBe true
            p.destroyReason shouldBe DestroyReason.AUTH_FAILED
        }

        test("a batch addressed to a middle hop destroys the circuit") {
            val r = LookupRig(relays = 2)
            val client = r.net.newClient(0)
            val circuit = r.net.buildCircuitFor(client, listOf(0, 1), SecureRandom(), r.clock)
            r.net.clientSend(
                0,
                client.link,
                Cell(
                    client.circuitId,
                    CellCommand.RELAY,
                    circuit.wrapForward(RelayMessage(RelayCommand.LOOKUP_REQUEST, 0, r.batchRequest()), 1),
                ),
            )
            client.inbox.any { it.command == CellCommand.DESTROY } shouldBe true
            r.net.lookupBatches.size shouldBe 0
        }
    })
