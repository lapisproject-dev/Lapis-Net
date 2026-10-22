package net.lapisphilosophorum.lapisnet.directory

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import java.time.Instant

class OnionRelayDescriptorIndexTest :
    FunSpec({
        val now = Instant.now().epochSecond

        test("a higher sequence number replaces the descriptor and the digest map follows") {
            val r = OnionRelayPublisher()
            val index = OnionRelayDescriptorIndex()
            val d0 = r.descriptor(sequence = 0)
            val d1 = r.descriptor(sequence = 1)
            index.add(d0, now) shouldBe DescriptorIngestOutcome.ACCEPTED
            index.add(d1, now) shouldBe DescriptorIngestOutcome.ACCEPTED
            index.current(r.publisher.key, now) shouldBe d1
            index.byRelayIdDigest(d1.relayIdDigest(), now) shouldBe d1
            index.digestMapSize() shouldBe 1
            index.size() shouldBe 1
            // the old onion key's digest is the same relay id, so still one entry
            index.byRelayIdDigest(d0.relayIdDigest(), now) shouldBe d1
        }

        test("an exact duplicate, an older sequence number and equivocation at the same sequence are not accepted") {
            val r = OnionRelayPublisher()
            val index = OnionRelayDescriptorIndex()
            val d5 = r.descriptor(sequence = 5)
            index.add(d5, now) shouldBe DescriptorIngestOutcome.ACCEPTED
            index.add(d5, now) shouldBe DescriptorIngestOutcome.DUPLICATE
            index.add(r.descriptor(sequence = 4), now) shouldBe DescriptorIngestOutcome.REPLAYED_OR_STALE
            val sameSeqOtherKey = r.descriptor(sequence = 5)
            index.add(sameSeqOtherKey, now) shouldBe DescriptorIngestOutcome.REPLAYED_OR_STALE
            index.current(r.publisher.key, now) shouldBe d5
        }

        test("the high-water mark survives eviction of the descriptor, so an old one cannot be replayed") {
            val r = OnionRelayPublisher()
            val index = OnionRelayDescriptorIndex()
            val old = r.descriptor(sequence = 3, expiresInSeconds = 100)
            index.add(old, now) shouldBe DescriptorIngestOutcome.ACCEPTED
            index.evictExpired(now + 200) shouldBe 1
            index.size() shouldBe 0
            index.digestMapSize() shouldBe 0
            index.add(r.descriptor(sequence = 2, now = now + 200), now + 200) shouldBe
                DescriptorIngestOutcome.REPLAYED_OR_STALE
            index.add(r.descriptor(sequence = 4, now = now + 200), now + 200) shouldBe DescriptorIngestOutcome.ACCEPTED
        }

        test("invalid and expired descriptors are classified and never stored") {
            val r = OnionRelayPublisher()
            val index = OnionRelayDescriptorIndex()
            val d = r.descriptor(expiresInSeconds = 100)
            index.add(d, now + 500) shouldBe DescriptorIngestOutcome.EXPIRED
            val bytes = OnionRelayDescriptorCodec.encode(d)
            bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 1).toByte()
            index.add(OnionRelayDescriptorCodec.decode(bytes), now) shouldBe DescriptorIngestOutcome.INVALID
            index.size() shouldBe 0
        }

        test("a flood of 5000 identities stays within the capacity bound and refuses new ones") {
            val index = OnionRelayDescriptorIndex(maxTracked = 64, maxHighWaterMarks = 128)
            var accepted = 0
            var capacity = 0
            val template = OnionRelayPublisher()
            repeat(300) {
                val r = if (it == 0) template else OnionRelayPublisher()
                when (index.add(r.descriptor(), now)) {
                    DescriptorIngestOutcome.ACCEPTED -> accepted++
                    DescriptorIngestOutcome.CAPACITY -> capacity++
                    else -> error("unexpected outcome")
                }
            }
            accepted shouldBe 64
            capacity shouldBe 236
            index.size() shouldBe 64
            index.digestMapSize() shouldBe 64
            // existing identities can still update when the index is full
            index.add(template.descriptor(sequence = 1), now) shouldBe DescriptorIngestOutcome.ACCEPTED
        }

        test("a full index makes room by dropping expired descriptors first") {
            val index = OnionRelayDescriptorIndex(maxTracked = 2, maxHighWaterMarks = 8)
            index.add(OnionRelayPublisher().descriptor(expiresInSeconds = 50), now) shouldBe
                DescriptorIngestOutcome.ACCEPTED
            index.add(OnionRelayPublisher().descriptor(expiresInSeconds = 5000), now) shouldBe
                DescriptorIngestOutcome.ACCEPTED
            val late = now + 100
            index.add(OnionRelayPublisher().descriptor(now = late), late) shouldBe DescriptorIngestOutcome.ACCEPTED
            index.size() shouldBe 2
        }

        test("snapshot honours the limit and hides expired entries") {
            val index = OnionRelayDescriptorIndex()
            repeat(5) { index.add(OnionRelayPublisher().descriptor(), now) }
            index.add(OnionRelayPublisher().descriptor(expiresInSeconds = 10), now)
            index.snapshot(now + 100).size shouldBe 5
            index.snapshot(now, limit = 3).size shouldBe 3
        }
    })
