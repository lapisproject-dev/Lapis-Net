package net.lapisphilosophorum.lapisnet.directory

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerId
import io.libp2p.core.crypto.KeyType
import io.libp2p.core.crypto.generateKeyPair
import io.libp2p.core.pubsub.ValidationResult
import java.security.SecureRandom
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset

private class MailboxTestClock(
    var millis: Long = Instant.now().toEpochMilli(),
) : Clock() {
    override fun getZone() = ZoneOffset.UTC

    override fun withZone(zone: java.time.ZoneId?) = this

    override fun instant(): Instant = Instant.ofEpochMilli(millis)

    override fun millis(): Long = millis
}

class AnonymousMailboxGossipTest :
    FunSpec({
        fun item(): ByteArray = ByteArray(AnonymousMailboxGossip.ITEM_SIZE).also(SecureRandom()::nextBytes)

        class Rig(
            perAuthor: Int = 10,
            global: Int = 120,
        ) {
            val clock = MailboxTestClock()
            val index = OnionRelayDescriptorIndex()
            val relay = OnionRelayPublisher()
            val relayDescriptor = relay.descriptor(sequence = 1)
            val relayPeer: PeerId

            init {
                index.add(relayDescriptor, clock.millis() / 1000) shouldBe DescriptorIngestOutcome.ACCEPTED
                relayPeer = relayDescriptor.peerId
            }

            val validator = AnonymousMailboxGossip.Validator(index, clock, perAuthor, global)
        }

        test("a correctly sized item from a known relay is valid; a duplicate is ignored") {
            val r = Rig()
            val bytes = item()
            r.validator.validate(bytes, r.relayPeer) shouldBe ValidationResult.Valid
            r.validator.validate(bytes, r.relayPeer) shouldBe ValidationResult.Ignore
        }

        test("a wrong size is rejected, also from a non-relay") {
            val r = Rig()
            val stranger = PeerId.fromPubKey(generateKeyPair(KeyType.ED25519).second)
            r.validator.validate(ByteArray(10), r.relayPeer) shouldBe ValidationResult.Invalid
            r.validator.validate(ByteArray(AnonymousMailboxGossip.ITEM_SIZE + 1), stranger) shouldBe
                ValidationResult.Invalid
        }

        test("an item whose author is not a relay is ignored, not rejected") {
            val r = Rig()
            val stranger = PeerId.fromPubKey(generateKeyPair(KeyType.ED25519).second)
            r.validator.validate(item(), stranger) shouldBe ValidationResult.Ignore
        }

        test("an expired relay descriptor no longer authorises its author") {
            val r = Rig()
            r.clock.millis += 2 * 3600 * 1000L
            r.validator.validate(item(), r.relayPeer) shouldBe ValidationResult.Ignore
        }

        test("the per-author budget ignores the excess and refills") {
            val r = Rig(perAuthor = 3, global = 1000)
            val results = List(5) { r.validator.validate(item(), r.relayPeer) }
            results.count { it == ValidationResult.Valid } shouldBe 3
            results.count { it == ValidationResult.Ignore } shouldBe 2
            r.clock.millis += 60_000
            r.validator.validate(item(), r.relayPeer) shouldBe ValidationResult.Valid
        }

        test("the global budget holds across relays") {
            val r = Rig(perAuthor = 1000, global = 4)
            val others =
                List(5) {
                    val other = OnionRelayPublisher()
                    val d = other.descriptor(sequence = 1)
                    r.index.add(d, r.clock.millis() / 1000)
                    d.peerId
                }
            val results = others.map { r.validator.validate(item(), it) }
            results.count { it == ValidationResult.Valid } shouldBe 4
        }

        test("a duplicate does not consume the budget") {
            val r = Rig(perAuthor = 2, global = 1000)
            val bytes = item()
            r.validator.validate(bytes, r.relayPeer) shouldBe ValidationResult.Valid
            repeat(10) { r.validator.validate(bytes, r.relayPeer) shouldBe ValidationResult.Ignore }
            r.validator.validate(item(), r.relayPeer) shouldBe ValidationResult.Valid
        }

        test("byPeerId finds the current descriptor and is cleaned up on replacement") {
            val index = OnionRelayDescriptorIndex()
            val relay = OnionRelayPublisher()
            val now = Instant.now().epochSecond
            val d1 = relay.descriptor(sequence = 1)
            val d2 = relay.descriptor(sequence = 2)
            index.add(d1, now)
            index.byPeerId(d1.peerId, now) shouldBe d1
            index.add(d2, now)
            index.byPeerId(d2.peerId, now) shouldBe d2
            index.byPeerId(PeerId.fromPubKey(generateKeyPair(KeyType.ED25519).second), now) shouldBe null
        }
    })
