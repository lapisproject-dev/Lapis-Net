package net.lapisphilosophorum.lapisnet.onion

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.onion.fake.hex
import net.lapisphilosophorum.lapisnet.onion.fake.unhex
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter

class HopCipherTest :
    FunSpec({
        fun key() = ByteArray(32) { (it + 1).toByte() }

        test("RFC 8439 section 2.8.2 AEAD vector through the BouncyCastle path (pins BC behaviour)") {
            val plaintext =
                "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
                    .toByteArray(Charsets.US_ASCII)
            val k = ByteArray(32) { (0x80 + it).toByte() }
            val nonce = unhex("070000004041424344454647")
            val aad = unhex("50515253c0c1c2c3c4c5c6c7")
            val c = ChaCha20Poly1305()
            c.init(true, AEADParameters(KeyParameter(k), 128, nonce, aad))
            val out = ByteArray(c.getOutputSize(plaintext.size))
            var n = c.processBytes(plaintext, 0, plaintext.size, out, 0)
            n += c.doFinal(out, n)
            n shouldBe plaintext.size + 16
            hex(out) shouldBe
                "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6" +
                "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36" +
                "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc" +
                "3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691"
        }

        test("seal and open with implicit counters, in order") {
            val a = HopCipher(key(), Direction.FORWARD, 2)
            val b = HopCipher(key(), Direction.FORWARD, 2)
            for (i in 0 until 5) {
                val msg = ByteArray(40) { (it + i).toByte() }
                b.open(a.seal(msg)).contentEquals(msg) shouldBe true
            }
            a.cellsProcessed shouldBe 5
            b.cellsProcessed shouldBe 5
        }

        test("the same plaintext seals differently at every counter value") {
            val a = HopCipher(key(), Direction.FORWARD, 1)
            val first = hex(a.seal(ByteArray(32)))
            val second = hex(a.seal(ByteArray(32)))
            (first == second) shouldBe false
        }

        test("a replayed cell fails and poisons the cipher") {
            val a = HopCipher(key(), Direction.FORWARD, 1)
            val b = HopCipher(key(), Direction.FORWARD, 1)
            val c1 = a.seal(ByteArray(10))
            b.open(c1)
            shouldThrow<OnionIntegrityException> { b.open(c1) }
            shouldThrow<IllegalStateException> { b.open(a.seal(ByteArray(10))) }
        }

        test("reordered cells fail") {
            val a = HopCipher(key(), Direction.BACKWARD, 3)
            val b = HopCipher(key(), Direction.BACKWARD, 3)
            val c1 = a.seal(ByteArray(10))
            val c2 = a.seal(ByteArray(10))
            shouldThrow<OnionIntegrityException> { b.open(c2) }
            c1.size shouldBe 26
        }

        test("a dropped cell desynchronises the stream") {
            val a = HopCipher(key(), Direction.FORWARD, 1)
            val b = HopCipher(key(), Direction.FORWARD, 1)
            a.seal(ByteArray(10))
            shouldThrow<OnionIntegrityException> { b.open(a.seal(ByteArray(10))) }
        }

        test("direction and hop index are bound into the associated data") {
            val a = HopCipher(key(), Direction.FORWARD, 1)
            val ct = a.seal(ByteArray(10))
            shouldThrow<OnionIntegrityException> { HopCipher(key(), Direction.BACKWARD, 1).open(ct) }
            shouldThrow<OnionIntegrityException> { HopCipher(key(), Direction.FORWARD, 2).open(ct) }
        }

        test("short input and bit flips fail") {
            shouldThrow<OnionIntegrityException> { HopCipher(key(), Direction.FORWARD, 1).open(ByteArray(15)) }
            val ct = HopCipher(key(), Direction.FORWARD, 1).seal(ByteArray(10))
            for (i in ct.indices) {
                val bad = ct.copyOf().also { it[i] = (it[i].toInt() xor 0x01).toByte() }
                shouldThrow<OnionIntegrityException> { HopCipher(key(), Direction.FORWARD, 1).open(bad) }
            }
        }

        test("the per-direction cell limit forces rotation (test hook for the start counter)") {
            val a = HopCipher(key(), Direction.FORWARD, 1, maxCells = 3, startCounter = 2)
            a.seal(ByteArray(1))
            shouldThrow<OnionResourceLimitException> { a.seal(ByteArray(1)) }
            val real = HopCipher(key(), Direction.FORWARD, 1, startCounter = OnionConstants.MAX_CELLS_PER_DIRECTION - 1)
            real.seal(ByteArray(1))
            shouldThrow<OnionResourceLimitException> { real.seal(ByteArray(1)) }
        }

        test("closed cipher refuses use and its key is zeroised") {
            val c = HopCipher(key(), Direction.FORWARD, 1)
            c.close()
            c.keyRaw.all { it == 0.toByte() } shouldBe true
            shouldThrow<IllegalStateException> { c.seal(ByteArray(1)) }
        }
    })
