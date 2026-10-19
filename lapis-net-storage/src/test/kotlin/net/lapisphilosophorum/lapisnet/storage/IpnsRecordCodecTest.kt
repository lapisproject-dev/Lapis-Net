package net.lapisphilosophorum.lapisnet.storage

import com.google.protobuf.ByteString
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.libp2p.core.PeerId
import io.libp2p.core.crypto.KeyType
import io.libp2p.core.crypto.generateKeyPair
import java.time.Duration
import java.time.Instant
import java.util.TimeZone

class IpnsRecordCodecTest :
    FunSpec({
        val limits = DhtLimits()
        val alice = IpnsIdentity.generate()

        fun validate(
            record: ByteArray,
            now: Instant = Instant.now(),
            key: ByteArray = alice.key,
            l: DhtLimits = limits,
        ) = IpnsRecordCodec.validate(key, record, now, l)

        test("a created record validates and every field comes back, expiry truncated to whole seconds") {
            val expiry = Instant.now().plus(Duration.ofHours(2))
            val record =
                alice.record(
                    "payload".toByteArray(),
                    sequence = 42,
                    notValidAfter = expiry,
                    ttl = Duration.ofMinutes(7),
                )
            val ok = validate(record)!!
            ok.publisher shouldBe alice.peerId
            String(ok.value) shouldBe "payload"
            ok.sequence shouldBe 42
            ok.ttl shouldBe Duration.ofMinutes(7)
            ok.notValidAfter shouldBe expiry.truncatedTo(java.time.temporal.ChronoUnit.SECONDS)
            ok.raw.contentEquals(record) shouldBe true
        }

        test("an expiry with sub-second digits round-trips (the validity format is canonical, not padded)") {
            val expiry = Instant.now().plus(Duration.ofHours(1)).plusMillis(5)
            validate(alice.record(notValidAfter = expiry)) shouldNotBe null
        }

        test("tampering with any signed field makes the record invalid") {
            val record = alice.record(sequence = 5)
            validate(tamper(record) { it.setValue(ByteString.copyFromUtf8("evil")) }) shouldBe null
            validate(tamper(record) { it.setSequence(6) }) shouldBe null
            validate(tamper(record) { it.setTtl(it.ttl + 1) }) shouldBe null
            validate(tamper(record) { it.setValidity(ByteString.copyFromUtf8("2099-01-01T00:00:00.0Z")) }) shouldBe null
            validate(
                tamper(record) {
                    val sig = it.signatureV2.toByteArray()
                    sig[0] = (sig[0].toInt() xor 1).toByte()
                    it.setSignatureV2(ByteString.copyFrom(sig))
                },
            ) shouldBe null
            validate(tamper(record) { it.setSignatureV2(ByteString.copyFrom(ByteArray(10))) }) shouldBe null
            validate(tamper(record) { it.clearSignatureV2() }) shouldBe null
            validate(tamper(record) { it.clearData() }) shouldBe null
            // data and the visible protobuf fields must agree, even when the data is validly signed
            val other = alice.record(value = "other".toByteArray(), sequence = 5)
            val otherData =
                org.peergos.protocol.ipns.pb.Ipns.IpnsEntry
                    .parseFrom(other)
            validate(
                tamper(record) {
                    it.setData(otherData.data)
                    it.setSignatureV2(otherData.signatureV2)
                },
            ) shouldBe null
        }

        test("the record of another publisher is not valid under this name, and a wrong pubKey field is refused") {
            val bob = IpnsIdentity.generate()
            validate(bob.record(), key = alice.key) shouldBe null
            validate(tamper(alice.record()) { it.setPubKey(ByteString.copyFrom(ByteArray(36))) }) shouldBe null
            // the correct pubKey field is harmless
            val correct = alice.key.copyOfRange(8, alice.key.size)
            validate(tamper(alice.record()) { it.setPubKey(ByteString.copyFrom(correct)) }) shouldNotBe null
        }

        test("keys that are not an Ed25519 identity multihash are refused") {
            val prefix = "/ipns/".toByteArray()
            val record = alice.record()
            val sha256 = prefix + byteArrayOf(0x12, 0x20) + ByteArray(32) { 3 }
            val secp = prefix + byteArrayOf(0x00, 0x25, 0x08, 0x02, 0x12, 0x21) + ByteArray(33) { 2 }
            val shortKey = alice.key.copyOf(alice.key.size - 1)
            val longKey = alice.key + byteArrayOf(0)
            val noPrefix = alice.key.copyOf().also { it[1] = 'x'.code.toByte() }
            val zeros = prefix + byteArrayOf(0x00, 0x24, 0x08, 0x01, 0x12, 0x20) + ByteArray(32)
            val ones = prefix + byteArrayOf(0x00, 0x24, 0x08, 0x01, 0x12, 0x20) + ByteArray(32) { 0xFF.toByte() }
            for (bad in listOf(sha256, secp, shortKey, longKey, noPrefix, zeros, ones, ByteArray(0))) {
                parseIpnsKey(bad) shouldBe null
                validate(record, key = bad) shouldBe null
            }
            parseIpnsKey(alice.key) shouldBe alice.peerId
            // an RSA-style peer ID (sha256 multihash) has no IPNS name here
            shouldThrow<IllegalArgumentException> { ipnsKeyFor(PeerId(byteArrayOf(0x12, 0x20) + ByteArray(32) { 1 })) }
        }

        test("a record above the size limit is refused before it is parsed") {
            val big = alice.record(value = ByteArray(2000) { 1 })
            validate(big, l = DhtLimits(maxIpnsRecordBytes = 1024)) shouldBe null
            validate(big) shouldNotBe null
            // garbage of any size never throws
            validate(ByteArray(20_000) { 0x7F }) shouldBe null
            validate(ByteArray(300) { 0x7F }) shouldBe null
            validate(ByteArray(0)) shouldBe null
        }

        test("create refuses records it cannot build") {
            val secp = generateKeyPair(KeyType.SECP256K1).first
            val future = Instant.now().plusSeconds(60)
            shouldThrow<IllegalArgumentException> {
                IpnsRecordCodec.create(secp, byteArrayOf(1), 1, future, Duration.ofMinutes(1))
            }
            shouldThrow<IllegalArgumentException> {
                IpnsRecordCodec.create(alice.privKey, ByteArray(0), 1, future, Duration.ofMinutes(1))
            }
            shouldThrow<IllegalArgumentException> {
                IpnsRecordCodec.create(alice.privKey, byteArrayOf(1), -1, future, Duration.ofMinutes(1))
            }
            shouldThrow<IllegalArgumentException> {
                IpnsRecordCodec.create(alice.privKey, byteArrayOf(1), 1, future, Duration.ZERO)
            }
            shouldThrow<IllegalArgumentException> {
                IpnsRecordCodec.create(alice.privKey, ByteArray(3000), 1, future, Duration.ofMinutes(1), 1024)
            }
        }

        test("expired, too-far-future and clock-skew boundaries") {
            val now = Instant.parse("2030-06-01T12:00:00Z")
            val skew = limits.maxClockSkew

            fun at(expiry: Instant) = alice.record(notValidAfter = expiry)
            validate(at(now.minusSeconds(3600)), now) shouldBe null
            validate(at(now.minus(skew).minusSeconds(2)), now) shouldBe null
            validate(at(now.minus(skew).plusSeconds(2)), now) shouldNotBe null
            validate(at(now.plusSeconds(60)), now) shouldNotBe null
            val maxEdge = now.plus(limits.maxRecordValidity).plus(skew)
            validate(at(maxEdge.minusSeconds(2)), now) shouldNotBe null
            validate(at(maxEdge.plusSeconds(2)), now) shouldBe null
        }

        test("validity is judged in UTC whatever the default time zone is") {
            val saved = TimeZone.getDefault()
            try {
                for (zone in listOf("Europe/Berlin", "Pacific/Kiritimati", "America/Los_Angeles", "UTC")) {
                    TimeZone.setDefault(TimeZone.getTimeZone(zone))
                    val now = Instant.now()
                    validate(alice.record(notValidAfter = now.plusSeconds(600)), now) shouldNotBe null
                    // 10 minutes ago is expired in every zone; with a local-time comparison some zones would accept it
                    validate(alice.record(notValidAfter = now.minusSeconds(600)), now) shouldBe null
                    // and 6 hours of offset in either direction must not move the 7-day window
                    validate(
                        alice.record(notValidAfter = now.plus(Duration.ofDays(7)).minusSeconds(60)),
                        now,
                    ) shouldNotBe
                        null
                }
            } finally {
                TimeZone.setDefault(saved)
            }
        }

        test("a validly signed record with absurdly nested CBOR in data is rejected without a stack overflow") {
            val nested = ByteArray(200_000) { 0x81.toByte() } + byteArrayOf(0x00)
            // under the size limit as a protobuf, so it reaches the data check
            val data = ByteArray(9000) { 0x81.toByte() } + byteArrayOf(0x00)
            validate(signedWithData(alice, data), l = DhtLimits()) shouldBe null
            validate(signedWithData(alice, nested)) shouldBe null // over the size limit: refused unparsed
        }

        test("validity strings that are not in the exact canonical form are refused") {
            val good = alice.record()
            val entry =
                org.peergos.protocol.ipns.pb.Ipns.IpnsEntry
                    .parseFrom(good)
            val validity = String(entry.validity.toByteArray())
            for (bad in listOf(validity.dropLast(1), validity + "Z", validity.replace("T", " "), "", "x".repeat(200))) {
                validate(tamper(good) { it.setValidity(ByteString.copyFromUtf8(bad)) }) shouldBe null
            }
        }

        test("sequence ordering: a higher sequence wins, at equal sequence the later expiry") {
            val now = Instant.now()
            val low = alice.validated(sequence = 1, notValidAfter = now.plusSeconds(3600))
            val high = alice.validated(sequence = 2, notValidAfter = now.plusSeconds(1800))
            val later = alice.validated(sequence = 1, notValidAfter = now.plusSeconds(7200))
            high.isNewerThan(low) shouldBe true
            low.isNewerThan(high) shouldBe false
            later.isNewerThan(low) shouldBe true
            low.isNewerThan(low) shouldBe false
        }
    })
