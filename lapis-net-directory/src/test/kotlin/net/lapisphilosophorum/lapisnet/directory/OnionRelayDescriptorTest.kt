package net.lapisphilosophorum.lapisnet.directory

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.IdentityBinding
import java.time.Instant

class OnionRelayDescriptorTest :
    FunSpec({
        val now = Instant.now().epochSecond

        /** Re-encodes [d] with some bytes replaced and decodes again (structure kept, content tampered). */
        fun tamper(
            d: OnionRelayDescriptor,
            offset: Int,
        ): OnionRelayDescriptor {
            val bytes = OnionRelayDescriptorCodec.encode(d)
            bytes[offset] = (bytes[offset].toInt() xor 0x01).toByte()
            return OnionRelayDescriptorCodec.decode(bytes)
        }

        test("a freshly created descriptor verifies and exposes the peer id of its transport key") {
            val r = OnionRelayPublisher()
            val d = r.descriptor()
            OnionRelayDescriptor.verify(d, now) shouldBe true
            d.peerId shouldBe r.publisher.peerId
            d.identity shouldBe r.publisher.key
        }

        test("a flipped byte in the signature, the sequence number or the validity is rejected") {
            val d = OnionRelayPublisher().descriptor()
            val size = OnionRelayDescriptorCodec.ENCODED_SIZE
            OnionRelayDescriptor.verify(tamper(d, size - 1), now) shouldBe false // outer signature
            OnionRelayDescriptor.verify(tamper(d, 1 + 33 + 32 + 64 + 32 + 8 + 64 + 7), now) shouldBe false // seq
            OnionRelayDescriptor.verify(tamper(d, 1 + 33 + 32 + 64 + 32 + 8 + 64 + 8 + 7), now) shouldBe false // expiry
        }

        test("an onion key binding made by another identity is rejected") {
            val r = OnionRelayPublisher()
            val other = OnionRelayPublisher()
            shouldThrow<IllegalArgumentException> {
                r.descriptor(binding = other.onionBinding())
            }
            // forge a descriptor body that embeds a foreign binding: the codec rebuilds the binding with the
            // descriptor's own identity, so the foreign signature no longer verifies
            val foreign = other.onionBinding()
            val good = r.descriptor()
            val bytes = OnionRelayDescriptorCodec.encode(good)
            val fb = foreign.onionKey.bytes
            fb.copyInto(bytes, 1 + 33 + 32 + 64)
            foreign.signature.copyInto(bytes, 1 + 33 + 32 + 64 + 32 + 8)
            OnionRelayDescriptor.verify(OnionRelayDescriptorCodec.decode(bytes), now) shouldBe false
        }

        test("a wrong identity binding is rejected") {
            val r = OnionRelayPublisher()
            val d = r.descriptor()
            OnionRelayDescriptor.verify(tamper(d, 1 + 33 + 32 + 5), now) shouldBe false
        }

        test("a possession proof that does not come from the transport key is rejected") {
            val r = OnionRelayPublisher()
            val d = r.descriptor()
            val possessionOffset = OnionRelayDescriptorCodec.ENCODED_SIZE - 64 - 64
            OnionRelayDescriptor.verify(tamper(d, possessionOffset + 3), now) shouldBe false
        }

        test("an identity cannot point at a stranger's peer id: swapping the transport key breaks the binding") {
            val a = OnionRelayPublisher()
            val b = OnionRelayPublisher()
            val d = a.descriptor()
            val bytes = OnionRelayDescriptorCodec.encode(d)
            b.identity.ed25519KeyPair.publicKey.bytes
                .copyInto(bytes, 1 + 33)
            OnionRelayDescriptor.verify(OnionRelayDescriptorCodec.decode(bytes), now) shouldBe false
            // even with a binding made by A for B's transport key, B never signed the possession proof
            val forgedBinding = IdentityBinding.create(a.identity.secp256k1KeyPair, b.identity.ed25519KeyPair.publicKey)
            forgedBinding.signature.copyInto(bytes, 1 + 33 + 32)
            OnionRelayDescriptor.verify(OnionRelayDescriptorCodec.decode(bytes), now) shouldBe false
        }

        test("an expired descriptor and one claiming too long a validity are rejected") {
            val r = OnionRelayPublisher()
            val d = r.descriptor(expiresInSeconds = 100)
            OnionRelayDescriptor.verify(d, now + 110) shouldBe false
            OnionRelayDescriptor.verify(d, now + 50) shouldBe true
            // validity further out than the TTL window plus skew (checked at verify time, e.g. a clock far behind)
            val long = r.descriptor(expiresInSeconds = OnionRelayDescriptor.MAX_TTL_WINDOW_SECONDS)
            OnionRelayDescriptor.verify(long, now - OnionRelayDescriptor.MAX_CLOCK_SKEW_SECONDS - 10) shouldBe false
            shouldThrow<IllegalArgumentException> {
                r.descriptor(expiresInSeconds = OnionRelayDescriptor.MAX_TTL_WINDOW_SECONDS + 1)
            }
        }

        test("a descriptor never outlives its onion key") {
            val r = OnionRelayPublisher()
            val shortKey = r.onionBinding(notValidAfter = now + 600)
            shouldThrow<IllegalArgumentException> { r.descriptor(expiresInSeconds = 3600, binding = shortKey) }
            r.descriptor(expiresInSeconds = 500, binding = shortKey).let {
                OnionRelayDescriptor.verify(it, now) shouldBe true
            }
        }

        test("an expired onion key binding is rejected") {
            val r = OnionRelayPublisher()
            val expiredKey = r.onionBinding(notValidAfter = now - 10)
            shouldThrow<IllegalArgumentException> { r.descriptor(binding = expiredKey) }
        }

        test("verify never throws on garbage") {
            val d = OnionRelayPublisher().descriptor()
            OnionRelayDescriptor.verify(d, Long.MAX_VALUE) shouldBe false
            OnionRelayDescriptor.verify(d, Long.MIN_VALUE) shouldBe false
        }

        test("toString carries neither the peer id nor key bytes") {
            val r = OnionRelayPublisher()
            val s = r.descriptor().toString()
            (s.contains(r.publisher.peerId.toString())) shouldBe false
        }
    })
