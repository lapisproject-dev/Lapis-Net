package net.lapisphilosophorum.lapisnet.directory

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerId
import io.libp2p.core.crypto.KeyType
import io.libp2p.core.crypto.generateKeyPair
import io.libp2p.core.pubsub.ValidationResult
import io.libp2p.crypto.keys.unmarshalEd25519PublicKey
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.onion.IntroPointEntry
import net.lapisphilosophorum.lapisnet.onion.OnionKeyBinding
import net.lapisphilosophorum.lapisnet.onion.OnionServiceAddress
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptor
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptorCodec
import net.lapisphilosophorum.lapisnet.storage.IpnsValue
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset

private class TestClock(
    var millis: Long = Instant.now().toEpochMilli(),
) : Clock() {
    override fun getZone() = ZoneOffset.UTC

    override fun withZone(zone: java.time.ZoneId?) = this

    override fun instant(): Instant = Instant.ofEpochMilli(millis)

    override fun millis(): Long = millis
}

private fun peer(): PeerId = PeerId.fromPubKey(generateKeyPair(KeyType.ED25519).second)

private fun nowSec() = Instant.now().epochSecond

private class Service(
    val key: Ed25519KeyPair = Ed25519KeyPair.generate(),
) {
    fun descriptor(
        seq: Long = 1,
        ttl: Long = 3600,
        count: Int = 2,
    ): OnionServiceDescriptor {
        val entries =
            List(count) {
                IntroPointEntry(
                    OnionKeyBinding.create(
                        Secp256k1KeyPair.generate(),
                        X25519KeyPair.generate().publicKey,
                        nowSec() + 86_400,
                    ),
                    Ed25519KeyPair.generate().publicKey,
                )
            }
        return OnionServiceDescriptor.create(
            key,
            X25519KeyPair.generate().publicKey,
            entries,
            seq,
            nowSec() + ttl,
            nowSec(),
        )
    }
}

class OnionServiceDirectoryTest :
    FunSpec({
        // ---- index -------------------------------------------------------------------------------
        test("the index accepts strictly increasing sequences, ignores duplicates, replays and equivocation") {
            val index = OnionServiceDescriptorIndex()
            val s = Service()
            val d1 = s.descriptor(seq = 1)
            val now = nowSec()
            index.add(d1, now) shouldBe DescriptorIngestOutcome.ACCEPTED
            index.add(d1, now) shouldBe DescriptorIngestOutcome.DUPLICATE
            index.add(s.descriptor(seq = 1), now) shouldBe DescriptorIngestOutcome.REPLAYED_OR_STALE // equivocation
            index.add(s.descriptor(seq = 0), now) shouldBe DescriptorIngestOutcome.REPLAYED_OR_STALE
            index.current(s.key.publicKey, now) shouldBe d1
            val d2 = s.descriptor(seq = 2)
            index.add(d2, now) shouldBe DescriptorIngestOutcome.ACCEPTED
            index.current(s.key.publicKey, now) shouldBe d2
            index.precheck(d1, now) shouldBe DescriptorIngestOutcome.REPLAYED_OR_STALE
            index.precheck(s.descriptor(seq = 3), now) shouldBe null
        }

        test("expired descriptors are refused, evicted, and the high-water mark survives eviction") {
            val index = OnionServiceDescriptorIndex()
            val s = Service()
            val d = s.descriptor(seq = 5, ttl = 100)
            index.add(d, nowSec()) shouldBe DescriptorIngestOutcome.ACCEPTED
            index.add(s.descriptor(seq = 6, ttl = 100), nowSec() + 200) shouldBe DescriptorIngestOutcome.EXPIRED
            index.evictExpired(nowSec() + 200) shouldBe 1
            index.size() shouldBe 0
            index.add(s.descriptor(seq = 4), nowSec()) shouldBe DescriptorIngestOutcome.REPLAYED_OR_STALE
            index.add(s.descriptor(seq = 7), nowSec()) shouldBe DescriptorIngestOutcome.ACCEPTED
        }

        test("a full index refuses new service keys without evicting valid ones, but accepts updates") {
            val index = OnionServiceDescriptorIndex(maxTracked = 2, maxHighWaterMarks = 4)
            val a = Service()
            val b = Service()
            val c = Service()
            val now = nowSec()
            index.add(a.descriptor(), now) shouldBe DescriptorIngestOutcome.ACCEPTED
            index.add(b.descriptor(), now) shouldBe DescriptorIngestOutcome.ACCEPTED
            index.add(c.descriptor(), now) shouldBe DescriptorIngestOutcome.CAPACITY
            index.add(a.descriptor(seq = 2), now) shouldBe DescriptorIngestOutcome.ACCEPTED
            index.size() shouldBe 2
        }

        test("an invalid descriptor is classified as INVALID") {
            val index = OnionServiceDescriptorIndex()
            val s = Service()
            val bytes = OnionServiceDescriptorCodec.encode(s.descriptor())
            bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 1).toByte()
            index.add(OnionServiceDescriptorCodec.decode(bytes), nowSec()) shouldBe DescriptorIngestOutcome.INVALID
        }

        // ---- gossip ------------------------------------------------------------------------------
        fun validator(
            index: OnionServiceDescriptorIndex = OnionServiceDescriptorIndex(),
            clock: Clock = Clock.systemUTC(),
            author: Int = 6,
            peerRate: Int = 12,
            global: Int = 60,
        ) = OnionServiceDescriptorGossip.Validator(index, clock, author, peerRate, global)

        test("gossip: a valid descriptor is accepted, duplicates and replays ignored without using any budget") {
            val index = OnionServiceDescriptorIndex()
            val v = validator(index, author = 1)
            val s = Service()
            val from = peer()
            val d1 = s.descriptor(seq = 1)
            v.validate(OnionServiceDescriptorCodec.encode(d1), from) shouldBe ValidationResult.Valid
            repeat(5) { v.validate(OnionServiceDescriptorCodec.encode(d1), from) shouldBe ValidationResult.Ignore }
            v.validate(OnionServiceDescriptorCodec.encode(s.descriptor(seq = 0)), from) shouldBe ValidationResult.Ignore
            // the single per-author token was spent by the first message only: a fresh sequence is rate limited (IGNORE),
            // proving the ignored ones consumed nothing else
            v.validate(OnionServiceDescriptorCodec.encode(s.descriptor(seq = 2)), from) shouldBe ValidationResult.Ignore
        }

        test("gossip: malformed, oversize, tampered and foreign-signed messages are rejected") {
            val v = validator()
            val from = peer()
            val s = Service()
            val bytes = OnionServiceDescriptorCodec.encode(s.descriptor())
            v.validate(ByteArray(10), from) shouldBe ValidationResult.Invalid
            v.validate(ByteArray(1_000_000), from) shouldBe ValidationResult.Invalid
            v.validate(bytes + 0, from) shouldBe ValidationResult.Invalid
            val flipped = bytes.copyOf().also { it[bytes.size - 3] = (it[bytes.size - 3].toInt() xor 1).toByte() }
            v.validate(flipped, from) shouldBe ValidationResult.Invalid
            // a descriptor re-signed by another key but claiming the original service key: signature mismatch
            val foreign = bytes.copyOf().also { it[1] = (it[1].toInt() xor 1).toByte() }
            v.validate(foreign, from) shouldBe ValidationResult.Invalid
        }

        test("gossip: per-author, per-peer and global rates only IGNORE the excess") {
            val clock = TestClock()
            val v = validator(clock = clock, author = 2, peerRate = 1000, global = 1000)
            val s = Service()
            val from = peer()
            val results = (1L..5L).map { v.validate(OnionServiceDescriptorCodec.encode(s.descriptor(seq = it)), from) }
            results.count { it == ValidationResult.Valid } shouldBe 2
            results.count { it == ValidationResult.Ignore } shouldBe 3

            val v2 = validator(clock = clock, author = 1000, peerRate = 1000, global = 3)
            val r2 = (1..6).map { v2.validate(OnionServiceDescriptorCodec.encode(Service().descriptor()), peer()) }
            r2.count { it == ValidationResult.Valid } shouldBe 3
            r2.none { it == ValidationResult.Invalid } shouldBe true

            val v3 = validator(clock = clock, author = 1000, peerRate = 2, global = 1000)
            val from3 = peer()
            val r3 = (1..5).map { v3.validate(OnionServiceDescriptorCodec.encode(Service().descriptor()), from3) }
            r3.count { it == ValidationResult.Valid } shouldBe 2
        }

        // ---- DHT ---------------------------------------------------------------------------------
        test("DHT: publish and resolve round-trip under the service key's own name") {
            val store = FakeIpnsValueStore()
            val dht = OnionServiceDht(store)
            val s = Service()
            val d = s.descriptor()
            dht.publish(s.key, d) shouldBe 1
            val published = store.published.single()
            published.publisher shouldBe PeerId.fromPubKey(unmarshalEd25519PublicKey(s.key.publicKey.bytes))
            dht.resolve(OnionServiceAddress(s.key.publicKey)) shouldBe d
            dht.resolve(OnionServiceAddress(Ed25519KeyPair.generate().publicKey)) shouldBe null
        }

        test("DHT: publishing a descriptor of another service key is refused") {
            val dht = OnionServiceDht(FakeIpnsValueStore())
            val s = Service()
            var threw = 0
            try {
                dht.publish(Ed25519KeyPair.generate(), s.descriptor())
            } catch (e: IllegalArgumentException) {
                threw++
            }
            threw shouldBe 1
        }

        test("DHT: wrong publisher, wrong magic, oversize, tampered and expired values resolve to null") {
            val s = Service()
            val address = OnionServiceAddress(s.key.publicKey)
            val d = s.descriptor()
            val good =
                byteArrayOf('L'.code.toByte(), 'N'.code.toByte(), 'H'.code.toByte(), 'S'.code.toByte(), 1) +
                    OnionServiceDescriptorCodec.encode(d)
            val publisher = PeerId.fromPubKey(unmarshalEd25519PublicKey(s.key.publicKey.bytes))

            fun resolveWith(
                value: ByteArray,
                from: PeerId = publisher,
            ): OnionServiceDescriptor? {
                val store = FakeIpnsValueStore()
                store.resolveOverride =
                    IpnsValue(from, value, 1, Instant.now().plusSeconds(3600), Duration.ofMinutes(5))
                return OnionServiceDht(store).resolve(address)
            }
            resolveWith(good) shouldBe d
            resolveWith(good, from = peer()) shouldBe null
            resolveWith(good.copyOf().also { it[0] = 'X'.code.toByte() }) shouldBe null
            resolveWith(good.copyOf().also { it[4] = 2 }) shouldBe null
            resolveWith(good + ByteArray(2000)) shouldBe null
            resolveWith(good.copyOf().also { it[good.size - 2] = (it[good.size - 2].toInt() xor 1).toByte() }) shouldBe
                null
            resolveWith(good.copyOf(10)) shouldBe null
            // a validly signed descriptor of ANOTHER service published under this address' name
            val other = Service()
            val foreign =
                byteArrayOf('L'.code.toByte(), 'N'.code.toByte(), 'H'.code.toByte(), 'S'.code.toByte(), 1) +
                    OnionServiceDescriptorCodec.encode(other.descriptor())
            resolveWith(foreign) shouldBe null
            // expired
            val store = FakeIpnsValueStore()
            store.resolveOverride =
                IpnsValue(publisher, good, 1, Instant.now().plusSeconds(3600), Duration.ofMinutes(5))
            OnionServiceDht(store) { Instant.now().plusSeconds(7200) }.resolve(address) shouldBe null
        }

        test("DHT: a failing lookup yields null") {
            val store = FakeIpnsValueStore()
            store.resolveFailure = IllegalStateException("boom")
            OnionServiceDht(store).resolve(OnionServiceAddress(Ed25519KeyPair.generate().publicKey)) shouldBe null
        }
    })
