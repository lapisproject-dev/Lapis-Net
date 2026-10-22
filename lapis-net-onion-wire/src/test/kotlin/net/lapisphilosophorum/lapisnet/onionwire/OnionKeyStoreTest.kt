package net.lapisphilosophorum.lapisnet.onionwire

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onion.OnionKeyRing
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission
import kotlin.time.Duration.Companion.days

private val PASS = "correct horse".toCharArray()
private const val KDF_KIB = 64

@OptIn(ExperimentalOnionApi::class)
class OnionKeyStoreTest :
    FunSpec({
        fun dir(): Path = Files.createTempDirectory("onion-keystore-test")

        fun store(
            file: Path,
            identity: DualKeyIdentity,
            pass: CharArray? = PASS,
            clock: WireTestClock = WireTestClock(),
        ) = OnionKeyStore(file, identity, pass, clock, kdfMemoryKiB = KDF_KIB)

        fun ring(identity: DualKeyIdentity) = OnionKeyRing(identity.secp256k1KeyPair.publicKey)

        fun scalarsOf(ring: OnionKeyRing): List<ByteArray> {
            val out = ArrayList<ByteArray>()
            ring.snapshotForPersistence { entries -> entries.forEach { out += it.second.copyOf() } }
            return out
        }

        test("persist and reload round-trips the current key and the descriptor sequence") {
            val identity = DualKeyIdentity.generate()
            val file = dir().resolve("a.onionkeys")
            val r1 = ring(identity)
            val s1 = store(file, identity)
            s1.loadOrCreate(r1, 7.days) shouldBe OnionKeyStore.LoadResult.CREATED
            s1.lastDescriptorSequence = 42
            s1.persist(r1)
            val r2 = ring(identity)
            val s2 = store(file, identity)
            s2.loadOrCreate(r2, 7.days) shouldBe OnionKeyStore.LoadResult.LOADED
            r2.current() shouldBe r1.current()
            s2.lastDescriptorSequence shouldBe 42
            scalarsOf(r2).single().contentEquals(scalarsOf(r1).single()) shouldBe true
        }

        test("persisting a closed (empty) ring is a no-op and does not throw") {
            val identity = DualKeyIdentity.generate()
            val file = dir().resolve("a.onionkeys")
            val r = ring(identity)
            val st = store(file, identity)
            st.loadOrCreate(r, 7.days)
            val before = Files.readAllBytes(file)
            r.close()
            st.persist(r)
            Files.readAllBytes(file).contentEquals(before) shouldBe true
        }

        test("rotation keeps the old key as previous across a reload; an expired old key is dropped") {
            val identity = DualKeyIdentity.generate()
            val file = dir().resolve("a.onionkeys")
            val clock = WireTestClock()
            val r1 = ring(identity)
            val s1 = store(file, identity, clock = clock)
            s1.loadOrCreate(r1, 7.days)
            val first = r1.current()!!
            clock.advanceSeconds(4 * 86_400)
            s1.rotate(r1, 7.days)
            val second = r1.current()!!
            (second != first) shouldBe true

            val r2 = ring(identity)
            store(file, identity, clock = clock).loadOrCreate(r2, 7.days) shouldBe OnionKeyStore.LoadResult.LOADED
            r2.accepted(clock.millis() / 1000) shouldBe listOf(second, first)

            clock.advanceSeconds(4 * 86_400) // the first key (7 days) is now expired, the second still valid
            val r3 = ring(identity)
            store(file, identity, clock = clock).loadOrCreate(r3, 7.days) shouldBe OnionKeyStore.LoadResult.LOADED
            r3.accepted(clock.millis() / 1000) shouldBe listOf(second)
        }

        test("when every stored key is expired a fresh key is created") {
            val identity = DualKeyIdentity.generate()
            val file = dir().resolve("a.onionkeys")
            val clock = WireTestClock()
            val r1 = ring(identity)
            store(file, identity, clock = clock).loadOrCreate(r1, 1.days)
            clock.advanceSeconds(3 * 86_400)
            val r2 = ring(identity)
            store(file, identity, clock = clock).loadOrCreate(r2, 1.days) shouldBe OnionKeyStore.LoadResult.CREATED
            (r2.current() != r1.current()) shouldBe true
        }

        test("a wrong passphrase fails loudly") {
            val identity = DualKeyIdentity.generate()
            val file = dir().resolve("a.onionkeys")
            store(file, identity).loadOrCreate(ring(identity), 7.days)
            shouldThrow<OnionKeyStoreException> {
                store(file, identity, "wrong".toCharArray()).loadOrCreate(ring(identity), 7.days)
            }
        }

        test("any flipped byte of the file (header, salt, nonce, ciphertext, tag) is detected") {
            val identity = DualKeyIdentity.generate()
            val file = dir().resolve("a.onionkeys")
            store(file, identity).loadOrCreate(ring(identity), 7.days)
            val original = Files.readAllBytes(file)
            val offsets = listOf(0, 4, 5, 6, 10, 14, 20, 40, 60, 75, 76, 100, original.size - 1)
            for (offset in offsets) {
                val tampered = original.copyOf().also { it[offset] = (it[offset].toInt() xor 0x01).toByte() }
                Files.write(file, tampered)
                shouldThrow<OnionKeyStoreException> {
                    store(file, identity).loadOrCreate(ring(identity), 7.days)
                }
            }
            Files.write(file, original)
            store(file, identity).loadOrCreate(ring(identity), 7.days) shouldBe OnionKeyStore.LoadResult.LOADED
        }

        test("truncated, empty and oversized files are refused") {
            val identity = DualKeyIdentity.generate()
            val file = dir().resolve("a.onionkeys")
            store(file, identity).loadOrCreate(ring(identity), 7.days)
            val original = Files.readAllBytes(file)
            for (bad in listOf(ByteArray(0), original.copyOf(original.size / 2), original + ByteArray(5000))) {
                Files.write(file, bad)
                shouldThrow<OnionKeyStoreException> { store(file, identity).loadOrCreate(ring(identity), 7.days) }
            }
        }

        test("a file of another identity is refused even with the right passphrase") {
            val a = DualKeyIdentity.generate()
            val b = DualKeyIdentity.generate()
            val file = dir().resolve("a.onionkeys")
            store(file, a).loadOrCreate(ring(a), 7.days)
            shouldThrow<OnionKeyStoreException> { store(file, b).loadOrCreate(ring(b), 7.days) }
        }

        test("hostile key derivation parameters in the header are refused before any derivation") {
            val identity = DualKeyIdentity.generate()
            val file = dir().resolve("a.onionkeys")
            store(file, identity).loadOrCreate(ring(identity), 7.days)
            val bytes = Files.readAllBytes(file)
            // memory field at offset 6..9 set to 0x7FFFFFFF KiB
            bytes[6] = 0x7F
            bytes[7] = 0xFF.toByte()
            bytes[8] = 0xFF.toByte()
            bytes[9] = 0xFF.toByte()
            Files.write(file, bytes)
            shouldThrow<OnionKeyStoreException> { store(file, identity).loadOrCreate(ring(identity), 7.days) }
        }

        test("the file is 0600, contains no plaintext private key and leaves no temp file") {
            val identity = DualKeyIdentity.generate()
            val d = dir()
            val file = d.resolve("a.onionkeys")
            val r = ring(identity)
            store(file, identity).loadOrCreate(r, 7.days)
            val perms = Files.getPosixFilePermissions(file)
            perms shouldBe setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)
            val bytes = Files.readAllBytes(file)
            val scalar = scalarsOf(r).single()
            val found = (0..bytes.size - scalar.size).any { i -> (scalar.indices).all { bytes[i + it] == scalar[it] } }
            found shouldBe false
            Files.exists(d.resolve("a.onionkeys.tmp")) shouldBe false
        }

        test("a stale temp file from a crashed write is overwritten, not trusted") {
            val identity = DualKeyIdentity.generate()
            val d = dir()
            val file = d.resolve("a.onionkeys")
            Files.write(d.resolve("a.onionkeys.tmp"), ByteArray(10) { 7 })
            val r = ring(identity)
            store(file, identity).loadOrCreate(r, 7.days) shouldBe OnionKeyStore.LoadResult.CREATED
            Files.exists(d.resolve("a.onionkeys.tmp")) shouldBe false
            store(file, identity).loadOrCreate(ring(identity), 7.days) shouldBe OnionKeyStore.LoadResult.LOADED
        }

        test("every write uses a fresh salt and nonce") {
            val identity = DualKeyIdentity.generate()
            val file = dir().resolve("a.onionkeys")
            val r = ring(identity)
            val s = store(file, identity)
            s.loadOrCreate(r, 7.days)
            val first = Files.readAllBytes(file)
            s.persist(r)
            val second = Files.readAllBytes(file)
            first.copyOfRange(16, 44).contentEquals(second.copyOfRange(16, 44)) shouldBe false // salt + nonce
        }

        test("without a passphrase the keys are ephemeral and nothing is written") {
            val identity = DualKeyIdentity.generate()
            val d = dir()
            val file = d.resolve("a.onionkeys")
            val r = ring(identity)
            val s = store(file, identity, pass = null)
            s.loadOrCreate(r, 7.days) shouldBe OnionKeyStore.LoadResult.EPHEMERAL
            (r.current() != null) shouldBe true
            s.persist(r)
            Files.exists(file) shouldBe false
            Files.list(d).use { it.count() } shouldBe 0
        }

        test("close zeroises the passphrase copy but leaves the caller's array alone") {
            val identity = DualKeyIdentity.generate()
            val mine = "secret".toCharArray()
            val s = OnionKeyStore(dir().resolve("a.onionkeys"), identity, mine, kdfMemoryKiB = KDF_KIB)
            s.close()
            String(mine) shouldNotBe ""
            String(mine) shouldBe "secret"
        }
    })
