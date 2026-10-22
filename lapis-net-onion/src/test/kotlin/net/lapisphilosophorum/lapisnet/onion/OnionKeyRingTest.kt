package net.lapisphilosophorum.lapisnet.onion

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair

private const val NOW = 1_800_000_000L

private class RingFixture {
    val identity = Secp256k1KeyPair.generate()
    val ring = OnionKeyRing(identity.publicKey)

    fun newKey(validUntil: Long): Pair<OnionKeyBinding, X25519KeyPair> {
        val kp = X25519KeyPair.generate()
        return OnionKeyBinding.create(identity, kp.publicKey, validUntil) to kp
    }
}

class OnionKeyRingTest :
    FunSpec({
        test("install makes the key current; rotation keeps the former current as previous") {
            val f = RingFixture()
            val (b1, k1) = f.newKey(NOW + 1000)
            val (b2, k2) = f.newKey(NOW + 2000)
            f.ring.install(b1, k1.privateKey, NOW)
            f.ring.current() shouldBe b1
            f.ring.install(b2, k2.privateKey, NOW)
            f.ring.current() shouldBe b2
            f.ring.accepted(NOW) shouldBe listOf(b2, b1)
            // old fingerprint is still selected during the overlap
            f.ring.withKeyFor(b1.onionKeyFingerprint(), NOW) { b, _ -> b } shouldBe b1
            f.ring.withKeyFor(b2.onionKeyFingerprint(), NOW) { b, _ -> b } shouldBe b2
            f.ring.withKeyFor(ByteArray(32), NOW) { b, _ -> b } shouldBe null
        }

        test("a third install zeroises the oldest key") {
            val f = RingFixture()
            val (b1, k1) = f.newKey(NOW + 1000)
            val (b2, k2) = f.newKey(NOW + 2000)
            val (b3, k3) = f.newKey(NOW + 3000)
            f.ring.install(b1, k1.privateKey, NOW)
            f.ring.install(b2, k2.privateKey, NOW)
            f.ring.install(b3, k3.privateKey, NOW)
            k1.privateKey.bytes.all { it == 0.toByte() } shouldBe true
            f.ring.accepted(NOW) shouldBe listOf(b3, b2)
            f.ring.withKeyFor(b1.onionKeyFingerprint(), NOW) { b, _ -> b } shouldBe null
        }

        test("expired keys are not selected, retireExpired zeroises them") {
            val f = RingFixture()
            val (b1, k1) = f.newKey(NOW + 100)
            val (b2, k2) = f.newKey(NOW + 5000)
            f.ring.install(b1, k1.privateKey, NOW)
            f.ring.install(b2, k2.privateKey, NOW)
            f.ring.withKeyFor(b1.onionKeyFingerprint(), NOW + 101) { b, _ -> b } shouldBe null
            f.ring.retireExpired(NOW + 101) shouldBe 1
            k1.privateKey.bytes.all { it == 0.toByte() } shouldBe true
            f.ring.accepted(NOW + 101) shouldBe listOf(b2)
            f.ring.retireExpired(NOW + 6000) shouldBe 1
            f.ring.current() shouldBe null
        }

        test("close zeroises every key and the ring then selects nothing") {
            val f = RingFixture()
            val (b1, k1) = f.newKey(NOW + 1000)
            f.ring.install(b1, k1.privateKey, NOW)
            f.ring.close()
            k1.privateKey.bytes.all { it == 0.toByte() } shouldBe true
            f.ring.withKeyFor(b1.onionKeyFingerprint(), NOW) { b, _ -> b } shouldBe null
            f.ring.current() shouldBe null
        }

        test("a binding of another identity, a mismatching private key and an expired binding are rejected") {
            val f = RingFixture()
            val other = Secp256k1KeyPair.generate()
            val kp = X25519KeyPair.generate()
            val foreign = OnionKeyBinding.create(other, kp.publicKey, NOW + 1000)
            shouldThrow<IllegalArgumentException> { f.ring.install(foreign, kp.privateKey, NOW) }
            val (b, _) = f.newKey(NOW + 1000)
            shouldThrow<IllegalArgumentException> { f.ring.install(b, X25519KeyPair.generate().privateKey, NOW) }
            val (expired, ek) = f.newKey(NOW - 1)
            shouldThrow<IllegalArgumentException> { f.ring.install(expired, ek.privateKey, NOW) }
            f.ring.current() shouldBe null
        }
    })
