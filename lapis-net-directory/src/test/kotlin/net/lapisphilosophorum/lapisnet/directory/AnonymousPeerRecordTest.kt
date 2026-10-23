package net.lapisphilosophorum.lapisnet.directory

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldNotContain
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import java.time.Instant

private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

class AnonymousPeerRecordTest :
    FunSpec({
        val now = Instant.now().epochSecond

        test("a record round-trips through the fixed 248-byte encoding and verifies") {
            val p = AnonymousPublisher()
            val r = p.record(5, digest = ByteArray(32) { 7 })
            val bytes = AnonymousPeerRecordCodec.encode(r)
            bytes.size shouldBe 248
            val decoded = AnonymousPeerRecordCodec.decode(bytes)
            decoded shouldBe r
            AnonymousPeerRecord.verify(decoded, now) shouldBe true
            decoded.onionAddress shouldBe r.onionAddress
            decoded.capabilities shouldBe setOf(AnonymousCapability.DM)
            decoded.revoked shouldBe false
        }

        test("a revocation round-trips and carries no service key, proof, capability or digest") {
            val p = AnonymousPublisher()
            val r = p.revocation(9)
            val decoded = AnonymousPeerRecordCodec.decode(AnonymousPeerRecordCodec.encode(r))
            decoded.revoked shouldBe true
            decoded.serviceKey shouldBe null
            decoded.prekeyBundleDigest shouldBe null
            decoded.capabilities shouldBe emptySet()
            AnonymousPeerRecord.verify(decoded, now) shouldBe true
        }

        test("flipping any single bit of the encoding is rejected (structurally or by a signature)") {
            val p = AnonymousPublisher()
            for (original in listOf(p.record(5, digest = ByteArray(32) { 7 }), p.revocation(6))) {
                val bytes = AnonymousPeerRecordCodec.encode(original)
                for (i in bytes.indices) {
                    for (bit in 0 until 8) {
                        val tampered = bytes.copyOf().also { it[i] = (it[i].toInt() xor (1 shl bit)).toByte() }
                        val rejected =
                            try {
                                !AnonymousPeerRecord.verify(AnonymousPeerRecordCodec.decode(tampered), now)
                            } catch (e: MalformedAnonymousPeerRecordException) {
                                true
                            }
                        rejected shouldBe true
                    }
                }
            }
        }

        test("a foreign onion service can not be claimed: a proof by another service key is rejected") {
            val victim = AnonymousPublisher()
            val attacker = AnonymousPublisher()
            val genuine = attacker.record(3)
            // the attacker names the VICTIM's service key but can only sign the possession proof with its own key
            val forged = resign(attacker.identity, genuine, serviceKey = victim.serviceKey.publicKey)
            AnonymousPeerRecord.verify(forged, now) shouldBe false
        }

        test("a possession proof of an older sequence number does not transplant into a newer entry") {
            val p = AnonymousPublisher()
            val old = p.record(1)
            val newer = resign(p.identity, old, sequence = 2) // proof is still bound to sequence 1
            AnonymousPeerRecord.verify(newer, now) shouldBe false
            AnonymousPeerRecord.verify(p.record(2), now) shouldBe true
        }

        test("unknown flag and capability bits and an inconsistent revocation are malformed") {
            val p = AnonymousPublisher()
            val bytes = AnonymousPeerRecordCodec.encode(p.record(1))
            // flags byte is at offset 5, capabilities byte at 4+1+1+33+32+64 = 135
            for ((offset, value) in listOf(5 to 0x02, 5 to 0x80, 135 to 0x08, 135 to 0x80)) {
                val t = bytes.copyOf().also { it[offset] = (it[offset].toInt() or value).toByte() }
                shouldThrow<MalformedAnonymousPeerRecordException> { AnonymousPeerRecordCodec.decode(t) }
            }
            val revokedWithCapability = bytes.copyOf().also { it[5] = 1 } // REVOKED set but service key still present
            shouldThrow<MalformedAnonymousPeerRecordException> {
                AnonymousPeerRecordCodec.decode(
                    revokedWithCapability,
                )
            }
        }

        test("validity windows: expired, too far in the future and over-long creation are all refused") {
            val p = AnonymousPublisher()
            val r = p.record(1, expiresInSeconds = 600, now = now)
            AnonymousPeerRecord.verify(r, now + 601) shouldBe false
            shouldThrow<IllegalArgumentException> {
                p.record(
                    1,
                    expiresInSeconds =
                        AnonymousPeerRecord.MAX_TTL_WINDOW_SECONDS + 1,
                )
            }
            val tooLong = resign(p.identity, r, notValidAfter = now + AnonymousPeerRecord.MAX_TTL_WINDOW_SECONDS + 3600)
            AnonymousPeerRecord.verify(tooLong, now) shouldBe false
            AnonymousPeerRecord.verify(
                p.record(1, expiresInSeconds = AnonymousPeerRecord.MAX_TTL_WINDOW_SECONDS),
                now,
            ) shouldBe
                true
        }

        test("an all-zero possession proof is refused even with a valid outer signature") {
            val p = AnonymousPublisher()
            val zeroProof = resign(p.identity, p.record(1), serviceProof = ByteArray(64))
            AnonymousPeerRecord.verify(zeroProof, now) shouldBe false
            val onesProof = resign(p.identity, p.record(1), serviceProof = ByteArray(64) { 0xFF.toByte() })
            AnonymousPeerRecord.verify(onesProof, now) shouldBe false
        }

        test("an outer signature by another identity is rejected") {
            val p = AnonymousPublisher()
            val other = DualKeyIdentity.generate()
            val record = p.record(1)
            val bytes = AnonymousPeerRecordCodec.encode(record)
            val foreignSignature = AnonymousPeerRecordCodec.encode(resign(other, record)).copyOfRange(184, 248)
            val swapped = bytes.copyOf().also { foreignSignature.copyInto(it, 184) }
            AnonymousPeerRecord.verify(AnonymousPeerRecordCodec.decode(swapped), now) shouldBe false
        }

        test("toString and error messages expose neither the service key, the address, nor signatures") {
            val p = AnonymousPublisher()
            val r = p.record(4, digest = ByteArray(32) { 9 })
            val text = r.toString()
            text shouldNotContain hex(p.serviceKey.publicKey.bytes)
            text shouldNotContain hex(r.signature)
            text shouldNotContain hex(r.servicePossessionProof)
            text shouldNotContain r.onionAddress!!.encode()
            text shouldNotContain hex(ByteArray(32) { 9 })
            val e = shouldThrow<IllegalArgumentException> { p.record(1, expiresInSeconds = 10 * 3600) }
            (e.message ?: "") shouldNotContain hex(p.serviceKey.publicKey.bytes)
            // a different record never equals this one
            (r == AnonymousPublisher().record(4)) shouldBe false
            Ed25519KeyPair
                .generate()
                .publicKey.bytes.size shouldBe 32
        }
    })
