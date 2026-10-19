package net.lapisphilosophorum.lapisnet.directory

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.crypto.KeyType
import io.libp2p.core.crypto.generateKeyPair
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.IdentityBinding
import org.peergos.protocol.ipns.IPNS
import java.time.LocalDateTime
import java.time.ZoneOffset

class DirectoryDhtValueCodecTest :
    FunSpec({
        val publisher = DirectoryPublisher()

        test("a value with both parts round-trips, parts byte-identical") {
            val value = publisher.value()
            val decoded = DirectoryDhtValueCodec.decode(DirectoryDhtValueCodec.encode(value))
            decoded shouldBe value
            decoded.peerRecordBytes!!.contentEquals(value.peerRecordBytes) shouldBe true
            decoded.prekeyBundleBytes!!.contentEquals(value.prekeyBundleBytes) shouldBe true
        }

        test("a peer-record-only and a bundle-only value round-trip") {
            val onlyRecord = publisher.value(bundle = null)
            val onlyBundle = publisher.value(peerRecord = null)
            DirectoryDhtValueCodec.decode(DirectoryDhtValueCodec.encode(onlyRecord)) shouldBe onlyRecord
            DirectoryDhtValueCodec.decode(DirectoryDhtValueCodec.encode(onlyBundle)) shouldBe onlyBundle
            DirectoryDhtValueCodec.decode(DirectoryDhtValueCodec.encode(onlyRecord)).prekeyBundleBytes shouldBe null
        }

        test("a value with neither part cannot be built") {
            shouldThrow<IllegalArgumentException> {
                DirectoryDhtValue(
                    publisher.key,
                    publisher.identity.binding,
                    null,
                    null,
                )
            }
            shouldThrow<IllegalArgumentException> {
                DirectoryDhtValue(publisher.key, publisher.identity.binding, ByteArray(0), null)
            }
        }

        test("a value above the size limit is refused when encoding and when decoding") {
            val big = DirectoryDhtValue(publisher.key, publisher.identity.binding, ByteArray(5000) { 1 }, null)
            shouldThrow<IllegalArgumentException> { DirectoryDhtValueCodec.encode(big) }
            shouldThrow<MalformedDirectoryDhtValueException> {
                DirectoryDhtValueCodec.decode(ByteArray(DirectoryDhtValueCodec.MAX_VALUE_BYTES + 1))
            }
        }

        test("every truncation of a valid value is malformed") {
            val bytes = DirectoryDhtValueCodec.encode(publisher.value())
            for (cut in listOf(0, 1, 5, 6, 38, 70, 100, 137, 138, 139, 300, bytes.size - 1)) {
                shouldThrow<MalformedDirectoryDhtValueException> { DirectoryDhtValueCodec.decode(bytes.copyOf(cut)) }
            }
        }

        test("trailing bytes, a bad magic, a wrong version and reserved flags are malformed") {
            val bytes = DirectoryDhtValueCodec.encode(publisher.value())
            shouldThrow<MalformedDirectoryDhtValueException> { DirectoryDhtValueCodec.decode(bytes + byteArrayOf(0)) }
            shouldThrow<MalformedDirectoryDhtValueException> {
                DirectoryDhtValueCodec.decode(bytes.copyOf().also { it[0] = 'X'.code.toByte() })
            }
            shouldThrow<MalformedDirectoryDhtValueException> {
                DirectoryDhtValueCodec.decode(bytes.copyOf().also { it[4] = 2 })
            }
            shouldThrow<MalformedDirectoryDhtValueException> {
                DirectoryDhtValueCodec.decode(bytes.copyOf().also { it[5] = (it[5].toInt() or 0x80).toByte() })
            }
            shouldThrow<MalformedDirectoryDhtValueException> {
                DirectoryDhtValueCodec.decode(bytes.copyOf().also { it[5] = 0 })
            }
        }

        test("a declared part length beyond the bytes that are there is malformed, not an allocation") {
            val bytes = DirectoryDhtValueCodec.encode(publisher.value(bundle = null))
            val lengthOffset = 4 + 1 + 1 + 33 + 32 + 64
            val lying = bytes.copyOf()
            lying[lengthOffset] = 0xFF.toByte()
            lying[lengthOffset + 1] = 0xFF.toByte()
            shouldThrow<MalformedDirectoryDhtValueException> { DirectoryDhtValueCodec.decode(lying) }
            val zero = bytes.copyOf()
            zero[lengthOffset] = 0
            zero[lengthOffset + 1] = 0
            shouldThrow<MalformedDirectoryDhtValueException> { DirectoryDhtValueCodec.decode(zero) }
        }

        test("an identity key that is not on the curve is malformed") {
            val bytes = DirectoryDhtValueCodec.encode(publisher.value())
            val offCurve = bytes.copyOf()
            for (i in 6 until 6 + 33) offCurve[i] = 0x05
            shouldThrow<MalformedDirectoryDhtValueException> { DirectoryDhtValueCodec.decode(offCurve) }
        }

        test("the largest value still fits into an IPNS record below Nabu's 10 KiB limit") {
            // an IPNS v2 record carries the value twice (protobuf value + signed CBOR data)
            val largest = ByteArray(DirectoryDhtValueCodec.MAX_VALUE_BYTES) { (it * 31).toByte() }
            val key = generateKeyPair(KeyType.ED25519).first
            val record =
                IPNS.createSignedRecord(
                    largest,
                    LocalDateTime.now(ZoneOffset.UTC).plusDays(7),
                    System.currentTimeMillis(),
                    Long.MAX_VALUE / 2,
                    key,
                )
            (record.size <= IPNS.MAX_RECORD_SIZE) shouldBe true
            println("largest directory value ${largest.size} bytes -> IPNS record ${record.size} bytes")
        }

        test("the larger of the two real artefacts, a peer record with 16 addresses, fits alone") {
            val identity = DualKeyIdentity.generate()
            val record =
                PeerRecord.create(
                    identity,
                    List(
                        PeerRecordCodec.MAX_ADDRESSES,
                    ) {
                        io.libp2p.core.multiformats
                            .Multiaddr("/ip4/10.0.0.$it/tcp/${4000 + it}")
                    },
                    setOf(PeerCapability.DM, PeerCapability.RELAY),
                    0,
                    java.time.Instant
                        .now()
                        .epochSecond + 100,
                )
            val value =
                DirectoryDhtValue(
                    identity.secp256k1KeyPair.publicKey,
                    identity.binding,
                    PeerRecordCodec.encode(record),
                    null,
                )
            (DirectoryDhtValueCodec.encode(value).size <= DirectoryDhtValueCodec.MAX_VALUE_BYTES) shouldBe true
            // and the binding an envelope repeats is the very one the record carries
            IdentityBinding.verify(identity.secp256k1KeyPair.publicKey, value.binding) shouldBe true
        }
    })
