package net.lapisphilosophorum.lapisnet.browser

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.longs.shouldBeLessThan
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.call.CallEvent

private fun drainAll(sub: CallEventHub.Subscription): List<CallUiEvent> {
    val out = mutableListOf<CallUiEvent>()
    while (true) {
        val r = sub.events.tryReceive()
        if (!r.isSuccess) break
        out += r.getOrThrow()
    }
    return out
}

/** V0.9.15 - the reason of a block is local display data: in the UI event and in the history, never on the wire. */
class CallEventHubBlockReasonTest :
    FunSpec({
        test("a blocked call carries the reason in the UI event and in blockedAttempts") {
            val remote = FakeCallRemote()
            val hub =
                CallEventHub(
                    remote,
                    autoRejectQuarantined = true,
                    blockReasonOf = { CallBlockReason.KARMA_BELOW_THRESHOLD },
                )
            val sub = hub.trySubscribe().shouldNotBeNull()
            val id = randomCallId()
            val peer = randomPeer()
            remote.emit(CallEvent.IncomingCall(id, peer, quarantined = true))
            val event = drainAll(sub).single()
            event.type shouldBe "blocked"
            event.blockReason shouldBe "KARMA_BELOW_THRESHOLD"
            hub.blockedAttempts().single().reason shouldBe CallBlockReason.KARMA_BELOW_THRESHOLD
            hub.isBlocked(id) shouldBe true
        }

        test("a throwing explanation degrades to POLICY and the call is still blocked") {
            val remote = FakeCallRemote()
            val hub = CallEventHub(remote, autoRejectQuarantined = true, blockReasonOf = { error("boom") })
            val sub = hub.trySubscribe().shouldNotBeNull()
            remote.emit(CallEvent.IncomingCall(randomCallId(), randomPeer(), quarantined = true))
            val event = drainAll(sub).single()
            event.type shouldBe "blocked"
            event.blockReason shouldBe "POLICY"
        }

        test("the default explanation is POLICY") {
            val remote = FakeCallRemote()
            val hub = CallEventHub(remote, autoRejectQuarantined = true)
            val sub = hub.trySubscribe().shouldNotBeNull()
            remote.emit(CallEvent.IncomingCall(randomCallId(), randomPeer(), quarantined = true))
            drainAll(sub).single().blockReason shouldBe "POLICY"
        }

        test("an ordinary incoming call carries no block reason, and the explanation is not even asked") {
            val remote = FakeCallRemote()
            var asked = 0
            val hub =
                CallEventHub(remote, autoRejectQuarantined = true, blockReasonOf = {
                    asked++
                    CallBlockReason.POLICY
                })
            val sub = hub.trySubscribe().shouldNotBeNull()
            remote.emit(CallEvent.IncomingCall(randomCallId(), randomPeer(), quarantined = false))
            val event = drainAll(sub).single()
            event.type shouldBe "incoming"
            event.blockReason.shouldBeNull()
            asked shouldBe 0
        }

        test("a quarantined call that is not auto-rejected rings as unaccepted and has no block reason") {
            val remote = FakeCallRemote()
            val hub = CallEventHub(remote, autoRejectQuarantined = false)
            val sub = hub.trySubscribe().shouldNotBeNull()
            remote.emit(CallEvent.IncomingCall(randomCallId(), randomPeer(), quarantined = true))
            val event = drainAll(sub).single()
            event.type shouldBe "incoming"
            event.unaccepted shouldBe true
            event.blockReason.shouldBeNull()
            hub.blockedAttempts() shouldBe emptyList()
        }

        test("explaining a block never blocks the call state thread noticeably") {
            val remote = FakeCallRemote()
            val hub =
                CallEventHub(
                    remote,
                    autoRejectQuarantined = true,
                    blockReasonOf = { CallBlockReason.VERITAS_BELOW_THRESHOLD },
                )
            val sub = hub.trySubscribe().shouldNotBeNull()
            repeat(40) { remote.emit(CallEvent.IncomingCall(randomCallId(), randomPeer(), quarantined = true)) }
            drainAll(sub).size shouldBe 40
            (hub.listenerInvocationNanosMaxForTesting() / 1_000_000) shouldBeLessThan 50
        }

        test("V0.10.0-G: IncomingSuppressed becomes a blocked UI event with ANONYMITY_MODE and is not actionable") {
            val remote = FakeCallRemote()
            val hub = CallEventHub(remote, autoRejectQuarantined = true)
            val sub = hub.trySubscribe().shouldNotBeNull()
            val id = randomCallId()
            val peer = randomPeer()
            remote.emit(
                CallEvent.IncomingSuppressed(
                    id,
                    peer,
                    net.lapisphilosophorum.lapisnet.call.CallSuppressCause.ANONYMITY_MODE,
                ),
            )
            val event = drainAll(sub).single()
            event.type shouldBe "blocked"
            event.blockReason shouldBe "ANONYMITY_MODE"
            hub.blockedAttempts().single().reason shouldBe CallBlockReason.ANONYMITY_MODE
            hub.isBlocked(id) shouldBe true
        }
    })
