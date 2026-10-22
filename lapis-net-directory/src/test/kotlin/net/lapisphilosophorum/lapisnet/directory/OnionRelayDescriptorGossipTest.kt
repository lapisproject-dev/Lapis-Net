package net.lapisphilosophorum.lapisnet.directory

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerId
import io.libp2p.core.crypto.KeyType
import io.libp2p.core.crypto.generateKeyPair
import io.libp2p.core.pubsub.ValidationResult
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset

private class MutableClock(
    var millis: Long = Instant.now().toEpochMilli(),
) : Clock() {
    override fun getZone() = ZoneOffset.UTC

    override fun withZone(zone: java.time.ZoneId?) = this

    override fun instant(): Instant = Instant.ofEpochMilli(millis)

    override fun millis(): Long = millis
}

private fun randomPeer(): PeerId = PeerId.fromPubKey(generateKeyPair(KeyType.ED25519).second)

class OnionRelayDescriptorGossipTest :
    FunSpec({
        fun validator(
            index: OnionRelayDescriptorIndex = OnionRelayDescriptorIndex(),
            clock: Clock = Clock.systemUTC(),
            perPeer: Int = 6,
            global: Int = 60,
        ) = OnionRelayDescriptorGossip.Validator(index, clock, perPeer, global)

        test("a valid descriptor is accepted and indexed; a duplicate and a replay are ignored") {
            val index = OnionRelayDescriptorIndex()
            val v = validator(index)
            val r = OnionRelayPublisher()
            val from = randomPeer()
            val d1 = r.descriptor(sequence = 1)
            v.validate(OnionRelayDescriptorCodec.encode(d1), from) shouldBe ValidationResult.Valid
            index.current(r.publisher.key, Instant.now().epochSecond) shouldBe d1
            v.validate(OnionRelayDescriptorCodec.encode(d1), from) shouldBe ValidationResult.Ignore
            v.validate(OnionRelayDescriptorCodec.encode(r.descriptor(sequence = 0)), from) shouldBe
                ValidationResult.Ignore
        }

        test("malformed, tampered and oversize messages are rejected") {
            val v = validator()
            val from = randomPeer()
            val r = OnionRelayPublisher()
            val bytes = OnionRelayDescriptorCodec.encode(r.descriptor())
            v.validate(ByteArray(10), from) shouldBe ValidationResult.Invalid
            v.validate(ByteArray(1_000_000), from) shouldBe ValidationResult.Invalid
            v.validate(bytes + 0, from) shouldBe ValidationResult.Invalid
            bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 1).toByte()
            v.validate(bytes, from) shouldBe ValidationResult.Invalid
            val garbage = bytes.copyOf().also { it[0] = 9 }
            v.validate(garbage, from) shouldBe ValidationResult.Invalid
        }

        test("an expired descriptor is ignored, not punished") {
            val clock = MutableClock()
            val v = validator(clock = clock)
            val r = OnionRelayPublisher()
            val d = r.descriptor(expiresInSeconds = 60)
            clock.millis += 120_000
            v.validate(OnionRelayDescriptorCodec.encode(d), randomPeer()) shouldBe ValidationResult.Ignore
        }

        test("the per-author rate limit ignores the excess and refills over time") {
            val clock = MutableClock()
            val v = validator(clock = clock, perPeer = 3, global = 1000)
            val from = randomPeer()
            val results =
                List(5) { v.validate(OnionRelayDescriptorCodec.encode(OnionRelayPublisher().descriptor()), from) }
            results.count { it == ValidationResult.Valid } shouldBe 3
            results.count { it == ValidationResult.Ignore } shouldBe 2
            clock.millis += 60_000
            v.validate(OnionRelayDescriptorCodec.encode(OnionRelayPublisher().descriptor()), from) shouldBe
                ValidationResult.Valid
        }

        test("the global rate limit holds across many authors") {
            val v = validator(perPeer = 1000, global = 4)
            val results =
                List(
                    10,
                ) { v.validate(OnionRelayDescriptorCodec.encode(OnionRelayPublisher().descriptor()), randomPeer()) }
            results.count { it == ValidationResult.Valid } shouldBe 4
            results.count { it == ValidationResult.Ignore } shouldBe 6
        }

        test("oversize messages are rejected before any rate-limit bucket is touched") {
            val v = validator(perPeer = 1, global = 1)
            val from = randomPeer()
            repeat(50) { v.validate(ByteArray(5000), from) shouldBe ValidationResult.Invalid }
            v.validate(OnionRelayDescriptorCodec.encode(OnionRelayPublisher().descriptor()), from) shouldBe
                ValidationResult.Valid
        }

        test("replays and duplicates do not use up the global budget, so a new descriptor still gets through") {
            val index = OnionRelayDescriptorIndex()
            val v = validator(index, perPeer = 1000, global = 2)
            val honest = OnionRelayPublisher().descriptor(sequence = 1)
            val bytes = OnionRelayDescriptorCodec.encode(honest)
            v.validate(bytes, randomPeer()) shouldBe ValidationResult.Valid
            // replay flood under fresh origins
            repeat(200) { v.validate(bytes, randomPeer()) shouldBe ValidationResult.Ignore }
            val fresh = OnionRelayPublisher().descriptor(sequence = 1)
            v.validate(OnionRelayDescriptorCodec.encode(fresh), randomPeer()) shouldBe ValidationResult.Valid
        }
    })
