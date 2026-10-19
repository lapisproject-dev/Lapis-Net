package net.lapisphilosophorum.lapisnet.browser

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.longs.shouldBeLessThan
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import kotlinx.coroutines.channels.ChannelResult
import net.lapisphilosophorum.lapisnet.call.CallEndReason
import net.lapisphilosophorum.lapisnet.call.CallEvent

private fun drain(sub: CallEventHub.Subscription): List<CallUiEvent> {
    val out = mutableListOf<CallUiEvent>()
    while (true) {
        val r: ChannelResult<CallUiEvent> = sub.events.tryReceive()
        if (!r.isSuccess) break
        out += r.getOrThrow()
    }
    return out
}

class CallEventHubTest :
    FunSpec({
        test("the hub registers exactly one listener, however many subscriptions come and go") {
            val remote = FakeCallRemote()
            val hub = CallEventHub(remote, autoRejectQuarantined = true)
            repeat(20) { hub.trySubscribe().shouldNotBeNull().close() }
            remote.listenerCount shouldBe 1
            hub.subscriberCountForTesting() shouldBe 0
        }

        test("the fifth concurrent subscription is refused, and succeeds again after a close") {
            val hub = CallEventHub(FakeCallRemote(), autoRejectQuarantined = true)
            val subs = (1..4).map { hub.trySubscribe().shouldNotBeNull() }
            hub.trySubscribe().shouldBeNull()
            subs[0].close()
            hub.trySubscribe().shouldNotBeNull()
        }

        test("closing twice returns the slot only once") {
            val hub = CallEventHub(FakeCallRemote(), autoRejectQuarantined = true)
            val subs = (1..4).map { hub.trySubscribe().shouldNotBeNull() }
            subs[0].close()
            subs[0].close()
            subs[0].close()
            // Exactly one slot is free again - a double release would allow two.
            hub.trySubscribe().shouldNotBeNull()
            hub.trySubscribe().shouldBeNull()
        }

        test("a subscriber that never reads is closed after its buffer overflows; others keep every event") {
            val remote = FakeCallRemote()
            val hub = CallEventHub(remote, autoRejectQuarantined = true)
            val slow = hub.trySubscribe().shouldNotBeNull()
            val fast = hub.trySubscribe().shouldNotBeNull()
            val peer = randomPeer()
            val received = mutableListOf<CallUiEvent>()
            repeat(65) {
                remote.emit(CallEvent.OutgoingRinging(randomCallId(), peer))
                received += drain(fast)
            }
            received.size shouldBe 65
            hub.subscriberCountForTesting() shouldBe 1
            // The slow subscriber's channel is closed (buffered items drain, then it ends).
            val slowEvents = drain(slow)
            slowEvents.size shouldBe 64
            slow.events.tryReceive().isClosed shouldBe true
            (hub.listenerInvocationNanosMaxForTesting() / 1_000_000) shouldBeLessThan 50
        }

        test("all five call events map to their UI event types") {
            val remote = FakeCallRemote()
            val hub = CallEventHub(remote, autoRejectQuarantined = true)
            val sub = hub.trySubscribe().shouldNotBeNull()
            val id = randomCallId()
            val peer = randomPeer()
            remote.emit(CallEvent.IncomingCall(id, peer, quarantined = false))
            remote.emit(CallEvent.OutgoingRinging(id, peer))
            remote.emit(CallEvent.Connecting(id, peer))
            remote.emit(CallEvent.Active(id, peer))
            remote.emit(CallEvent.Ended(id, peer, CallEndReason.LOCAL_HANGUP))
            val events = drain(sub)
            events.map { it.type } shouldBe listOf("incoming", "ringing", "connecting", "active", "ended")
            events.last().reason shouldBe "LOCAL_HANGUP"
            events.first().callId shouldBe id.bytes.joinToString("") { "%02x".format(it) }
            events.first().peerFingerprint shouldBe peer.fingerprint()
            events.first().unaccepted shouldBe false
        }

        test("a quarantined INVITE with auto-reject becomes 'blocked' and never reaches the remote") {
            val remote = FakeCallRemote()
            val hub = CallEventHub(remote, autoRejectQuarantined = true, clockSeconds = { 4242 })
            val sub = hub.trySubscribe().shouldNotBeNull()
            val id = randomCallId()
            val peer = randomPeer()
            remote.emit(CallEvent.IncomingCall(id, peer, quarantined = true))
            drain(sub).single().type shouldBe "blocked"
            hub.isBlocked(id) shouldBe true
            hub.blockedAttempts().single().atEpochSecond shouldBe 4242
            remote.totalMutatingCalls shouldBe 0
            remote.activeCalls().size shouldBe 0
        }

        test("a quarantined INVITE without auto-reject is an 'incoming' flagged unaccepted") {
            val remote = FakeCallRemote()
            val hub = CallEventHub(remote, autoRejectQuarantined = false)
            val sub = hub.trySubscribe().shouldNotBeNull()
            val id = randomCallId()
            remote.emit(CallEvent.IncomingCall(id, randomPeer(), quarantined = true))
            val event = drain(sub).single()
            event.type shouldBe "incoming"
            event.unaccepted shouldBe true
            hub.isBlocked(id) shouldBe false
        }

        test("the blocked ring never grows beyond 64 entries and evicts the oldest ids") {
            val remote = FakeCallRemote()
            val hub = CallEventHub(remote, autoRejectQuarantined = true)
            val ids = (1..100).map { randomCallId() }
            ids.forEach { remote.emit(CallEvent.IncomingCall(it, randomPeer(), quarantined = true)) }
            hub.blockedAttempts().size shouldBe 64
            hub.isBlocked(ids.first()) shouldBe false
            hub.isBlocked(ids.last()) shouldBe true
        }
    })
