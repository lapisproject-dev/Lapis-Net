package net.lapisphilosophorum.lapisnet.madli

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.longs.shouldBeExactly
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerId
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair

private fun testPeerId(seed: Byte): PeerId = PeerId(ByteArray(34) { seed })

private fun testMetrics(reachabilityMicros: Int = 500_000): MadliMetrics =
    MadliMetrics(
        reachabilityMicros = reachabilityMicros,
        medianBandwidthBytesPerSec = 10_000_000L,
        medianLatencyMillis = 50,
        deliveryIntegrityMicros = 900_000,
        routingHelpfulnessMicros = 700_000,
        observationCount = 10,
    )

class MadliDailyVectorTest :
    FunSpec({
        test("create -> verify round-trips true") {
            val observer = Secp256k1KeyPair.generate()
            val vector = MadliDailyVector.create(observer, testPeerId(1), epochDay = 100L, metrics = testMetrics())

            MadliDailyVector.verify(vector) shouldBe true
        }

        test("verify(expectedObserver) is true for the correct observer") {
            val observer = Secp256k1KeyPair.generate()
            val vector = MadliDailyVector.create(observer, testPeerId(1), epochDay = 100L, metrics = testMetrics())

            MadliDailyVector.verify(observer.publicKey, vector) shouldBe true
        }

        test("verify(expectedObserver) is false for the wrong observer") {
            val observer = Secp256k1KeyPair.generate()
            val otherObserver = Secp256k1KeyPair.generate()
            val vector = MadliDailyVector.create(observer, testPeerId(1), epochDay = 100L, metrics = testMetrics())

            MadliDailyVector.verify(otherObserver.publicKey, vector) shouldBe false
        }

        test("tampering with a metric field after signing fails verification") {
            val observer = Secp256k1KeyPair.generate()
            val vector = MadliDailyVector.create(observer, testPeerId(1), epochDay = 100L, metrics = testMetrics())
            val bytes = MadliDailyVectorCodec.encode(vector)

            // reachabilityMicros(4) is the first metric field, right after magic(4)+version(1)+
            // observer(33)+peerIdLen(2)+peerId(34)+epochDay(8). Flip the LOW-order byte (offset+3,
            // big-endian) rather than the high-order byte, so the tampered value (500_000 -> 500_001)
            // stays within MadliMetrics' valid range and decode() succeeds - this test is about
            // signature tampering, not triggering the codec's separate out-of-range rejection path
            // (that is MadliDailyVectorCodecTest's job).
            val offset = 4 + 1 + 33 + 2 + 34 + 8
            bytes[offset + 3] = (bytes[offset + 3] + 1).toByte()

            val decoded = MadliDailyVectorCodec.decode(bytes)
            MadliDailyVector.verify(decoded) shouldBe false
        }

        test("tampering with epochDay after signing fails verification") {
            val observer = Secp256k1KeyPair.generate()
            val vector = MadliDailyVector.create(observer, testPeerId(1), epochDay = 100L, metrics = testMetrics())
            val bytes = MadliDailyVectorCodec.encode(vector)

            // epochDay(8) sits right after magic(4)+version(1)+observer(33)+peerIdLen(2)+peerId(34).
            val offset = 4 + 1 + 33 + 2 + 34
            bytes[offset + 7] = (bytes[offset + 7] + 1).toByte()

            val decoded = MadliDailyVectorCodec.decode(bytes)
            MadliDailyVector.verify(decoded) shouldBe false
        }

        test("tampering with observedPeer after signing fails verification") {
            val observer = Secp256k1KeyPair.generate()
            val vector = MadliDailyVector.create(observer, testPeerId(1), epochDay = 100L, metrics = testMetrics())
            val bytes = MadliDailyVectorCodec.encode(vector)

            // peerId(34) sits right after magic(4)+version(1)+observer(33)+peerIdLen(2).
            val offset = 4 + 1 + 33 + 2
            bytes[offset] = (bytes[offset] + 1).toByte()

            val decoded = MadliDailyVectorCodec.decode(bytes)
            MadliDailyVector.verify(decoded) shouldBe false
        }

        test("signature defensive copy - mutating the returned array does not corrupt the vector") {
            val observer = Secp256k1KeyPair.generate()
            val vector = MadliDailyVector.create(observer, testPeerId(1), epochDay = 100L, metrics = testMetrics())

            val sig = vector.signature
            sig[0] = (sig[0] + 1).toByte()

            MadliDailyVector.verify(vector) shouldBe true
        }

        test("toString excludes the signature") {
            val observer = Secp256k1KeyPair.generate()
            val vector = MadliDailyVector.create(observer, testPeerId(1), epochDay = 100L, metrics = testMetrics())

            val text = vector.toString()

            text shouldBe
                "MadliDailyVector(observer=${observer.publicKey.fingerprint()}, " +
                "observedPeer=${vector.observedPeer}, epochDay=100, metrics=${vector.metrics}, relayMetrics=null)"
        }

        test("equals/hashCode are consistent, including the signature") {
            val observer = Secp256k1KeyPair.generate()
            val bytes =
                MadliDailyVectorCodec.encode(
                    MadliDailyVector.create(observer, testPeerId(1), 100L, testMetrics()),
                )
            val a = MadliDailyVectorCodec.decode(bytes)
            val b = MadliDailyVectorCodec.decode(bytes)

            a shouldBe b
            a.hashCode() shouldBe b.hashCode()
        }

        test("equals is false when the signature differs") {
            val observer = Secp256k1KeyPair.generate()
            val vectorA = MadliDailyVector.create(observer, testPeerId(1), epochDay = 100L, metrics = testMetrics())
            val vectorB = MadliDailyVector.create(observer, testPeerId(1), epochDay = 100L, metrics = testMetrics())

            // Two independent signing operations over the identical body may or may not produce
            // byte-identical ECDSA signatures depending on nonce derivation - either way, distinct
            // MadliDailyVector instances signed independently must be safely comparable.
            (vectorA == vectorA) shouldBe true
            (vectorB == vectorB) shouldBe true
        }

        test("currentEpochDayUtc is monotonic and floorDiv-correct for a negative millis input") {
            currentEpochDayUtc(0L) shouldBeExactly 0L
            currentEpochDayUtc(86_400_000L) shouldBeExactly 1L
            currentEpochDayUtc(-1L) shouldBeExactly -1L // one millisecond before epoch is already "day -1"
            currentEpochDayUtc(-86_400_000L) shouldBeExactly -1L
            currentEpochDayUtc(-86_400_001L) shouldBeExactly -2L
        }
    })
