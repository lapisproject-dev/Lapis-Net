package net.lapisphilosophorum.lapisnet.madli

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.libp2p.core.PeerId
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair

private fun peer(seed: Byte): PeerId = PeerId(ByteArray(34) { seed })

private val core = MadliMetrics(500_000, 10_000_000L, 50, 900_000, 700_000, 10)
private val relay = MadliRelayMetrics(850_000, 12)

/** Offset of the v2 flags byte: magic(4)+version(1)+observer(33)+peerIdLen(2)+peerId(34)+epochDay(8). */
private const val FLAGS_OFFSET = 4 + 1 + 33 + 2 + 34 + 8
private const val VERSION_OFFSET = 4

private fun v2(
    metrics: MadliMetrics? = null,
    relayMetrics: MadliRelayMetrics? = relay,
    observer: Secp256k1KeyPair = Secp256k1KeyPair.generate(),
): MadliDailyVector = MadliDailyVector.create(observer, peer(1), 100L, metrics, relayMetrics)

class MadliDailyVectorV2CodecTest :
    FunSpec({
        test("relay-only vector round-trips and uses version 2 with flags=relay") {
            val vector = v2()
            val bytes = MadliDailyVectorCodec.encode(vector)

            bytes[VERSION_OFFSET] shouldBe MadliDailyVectorCodec.VERSION_V2
            bytes[FLAGS_OFFSET].toInt() shouldBe 0x02
            MadliDailyVectorCodec.decode(bytes) shouldBe vector
            MadliDailyVector.verify(MadliDailyVectorCodec.decode(bytes)) shouldBe true
        }

        test("core plus relay vector round-trips with flags=core|relay") {
            val vector = v2(metrics = core)
            val bytes = MadliDailyVectorCodec.encode(vector)

            bytes[VERSION_OFFSET] shouldBe MadliDailyVectorCodec.VERSION_V2
            bytes[FLAGS_OFFSET].toInt() shouldBe 0x03
            val decoded = MadliDailyVectorCodec.decode(bytes)
            decoded shouldBe vector
            decoded.metrics shouldBe core
            decoded.relayMetrics shouldBe relay
        }

        test("a core-only vector is encoded canonically as v1") {
            val vector = v2(metrics = core, relayMetrics = null)
            val bytes = MadliDailyVectorCodec.encode(vector)

            bytes[VERSION_OFFSET] shouldBe MadliDailyVectorCodec.VERSION_V1
            MadliDailyVectorCodec.decode(bytes) shouldBe vector
        }

        test("a vector with neither block cannot be created") {
            shouldThrow<IllegalArgumentException> {
                MadliDailyVector.create(Secp256k1KeyPair.generate(), peer(1), 1L, null, null)
            }
        }

        test("content id differs between a v1 vector and its v2 sibling") {
            val observer = Secp256k1KeyPair.generate()
            val a = v2(metrics = core, relayMetrics = null, observer = observer)
            val b = v2(metrics = core, relayMetrics = relay, observer = observer)

            a.contentId() shouldNotBe b.contentId()
        }

        fun malformed(bytes: ByteArray) =
            shouldThrow<MalformedMadliDailyVectorException> {
                MadliDailyVectorCodec.decode(bytes)
            }

        test("unknown flag bits are rejected") {
            val bytes = MadliDailyVectorCodec.encode(v2())
            bytes[FLAGS_OFFSET] = 0x06
            malformed(bytes)
            bytes[FLAGS_OFFSET] = 0x82.toByte()
            malformed(bytes)
        }

        test("flags == 0 is rejected") {
            val bytes = MadliDailyVectorCodec.encode(v2())
            bytes[FLAGS_OFFSET] = 0
            malformed(bytes)
        }

        test("a non-canonical v2 vector with only the core flag is rejected") {
            // Build a v2-labelled core-only encoding by hand: version=2, flags=1, core block.
            val v1Bytes = MadliDailyVectorCodec.encode(v2(metrics = core, relayMetrics = null))
            val head = v1Bytes.copyOfRange(0, FLAGS_OFFSET)
            head[VERSION_OFFSET] = MadliDailyVectorCodec.VERSION_V2
            val rest = v1Bytes.copyOfRange(FLAGS_OFFSET, v1Bytes.size)
            malformed(head + byteArrayOf(0x01) + rest)
        }

        test("version 3 is rejected") {
            val bytes = MadliDailyVectorCodec.encode(v2())
            bytes[VERSION_OFFSET] = 3
            malformed(bytes)
        }

        test("truncation inside the relay block is rejected") {
            val bytes = MadliDailyVectorCodec.encode(v2())
            // Drop the signature plus 3 bytes of the relay block.
            malformed(bytes.copyOfRange(0, bytes.size - 64 - 3))
            malformed(bytes.copyOfRange(0, bytes.size - 5))
        }

        test("trailing bytes are rejected") {
            malformed(MadliDailyVectorCodec.encode(v2()) + byteArrayOf(0))
        }

        test("out-of-range relayReliabilityMicros are rejected") {
            for (bad in intArrayOf(-1, 1_000_001, Int.MAX_VALUE)) {
                val bytes = MadliDailyVectorCodec.encode(v2())
                val off = FLAGS_OFFSET + 1
                bytes[off] = (bad ushr 24).toByte()
                bytes[off + 1] = (bad ushr 16).toByte()
                bytes[off + 2] = (bad ushr 8).toByte()
                bytes[off + 3] = bad.toByte()
                malformed(bytes)
            }
        }

        test("a negative relayAttemptCount is rejected") {
            val bytes = MadliDailyVectorCodec.encode(v2())
            val off = FLAGS_OFFSET + 1 + 4
            bytes[off] = 0xFF.toByte()
            bytes[off + 1] = 0xFF.toByte()
            bytes[off + 2] = 0xFF.toByte()
            bytes[off + 3] = 0xFF.toByte()
            malformed(bytes)
        }

        test("flipping the core flag bit of a signed v2 body breaks decoding or verification") {
            val bytes = MadliDailyVectorCodec.encode(v2(metrics = core))
            bytes[FLAGS_OFFSET] = 0x02 // drop the core flag -> block layout shifts
            val outcome = runCatching { MadliDailyVectorCodec.decode(bytes) }
            (outcome.isFailure || !MadliDailyVector.verify(outcome.getOrThrow())) shouldBe true
        }

        test("tampering with a relay field invalidates the signature") {
            val bytes = MadliDailyVectorCodec.encode(v2())
            bytes[FLAGS_OFFSET + 4] = (bytes[FLAGS_OFFSET + 4] + 1).toByte()
            val decoded = MadliDailyVectorCodec.decode(bytes)
            MadliDailyVector.verify(decoded) shouldBe false
        }

        test("verify with a wrong expected observer is false for a v2 vector") {
            val vector = v2()
            MadliDailyVector.verify(Secp256k1KeyPair.generate().publicKey, vector) shouldBe false
            MadliDailyVector.verify(vector.observer, vector) shouldBe true
        }
    })
