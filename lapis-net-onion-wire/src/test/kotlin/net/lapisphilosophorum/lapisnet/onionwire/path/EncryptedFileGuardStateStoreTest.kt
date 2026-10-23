@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onionwire.path

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.read.ListAppender
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import org.slf4j.LoggerFactory
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission

class EncryptedFileGuardStateStoreTest :
    FunSpec({
        val identity = DualKeyIdentity.generate()

        fun state(): GuardState {
            val now = System.currentTimeMillis() / 1000
            val a = syntheticDescriptor()
            val b = syntheticDescriptor()
            return GuardState(
                GuardEntry(a.identity, now, now + 40 * 86_400L, 2, now - 100, null),
                GuardEntry(b.identity, now, now + 50 * 86_400L, 0, null, now - 50),
                now - 10,
            )
        }

        test("a state survives a roundtrip") {
            val file = Files.createTempDirectory("guards").resolve("onion").resolve("guards.bin")
            EncryptedFileGuardStateStore(file, identity).use { store ->
                store.load() shouldBe GuardLoad.Missing
                val s = state()
                store.save(s)
                val loaded = store.load().shouldBeInstanceOf<GuardLoad.Loaded>()
                loaded.state shouldBe s
            }
        }

        test("a save after close leaves the file untouched and readable with the real key") {
            val file = Files.createTempDirectory("guards").resolve("guards.bin")
            val s = state()
            val store = EncryptedFileGuardStateStore(file, identity)
            store.save(s)
            store.close()
            store.save(state().copy(lastFailureRotationEpochSecond = null)) // would be encrypted with the zeroised key
            EncryptedFileGuardStateStore(file, identity).use { again ->
                again.load().shouldBeInstanceOf<GuardLoad.Loaded>().state shouldBe s
            }
        }

        test("a flipped bit in any byte is detected") {
            val file = Files.createTempDirectory("guards").resolve("guards.bin")
            EncryptedFileGuardStateStore(file, identity).use { store ->
                store.save(state())
                val original = Files.readAllBytes(file)
                for (i in original.indices) {
                    val copy = original.copyOf()
                    copy[i] = (copy[i].toInt() xor 0x01).toByte()
                    Files.write(file, copy)
                    store.load() shouldBe GuardLoad.Invalid
                }
            }
        }

        test("another identity can not read the file (key and AAD)") {
            val file = Files.createTempDirectory("guards").resolve("guards.bin")
            EncryptedFileGuardStateStore(file, identity).use { it.save(state()) }
            EncryptedFileGuardStateStore(file, DualKeyIdentity.generate()).use { it.load() shouldBe GuardLoad.Invalid }
        }

        test("truncation, trailing garbage and an empty file are invalid") {
            val file = Files.createTempDirectory("guards").resolve("guards.bin")
            EncryptedFileGuardStateStore(file, identity).use { store ->
                store.save(state())
                val original = Files.readAllBytes(file)
                Files.write(file, original.copyOf(original.size - 1))
                store.load() shouldBe GuardLoad.Invalid
                Files.write(file, original + byteArrayOf(0))
                store.load() shouldBe GuardLoad.Invalid
                Files.write(file, ByteArray(0))
                store.load() shouldBe GuardLoad.Invalid
            }
        }

        test(
            "a state that fails the plausibility checks is invalid (lifetime outside 30 to 60 days, time in the future)",
        ) {
            val file = Files.createTempDirectory("guards").resolve("guards.bin")
            EncryptedFileGuardStateStore(file, identity).use { store ->
                val now = System.currentTimeMillis() / 1000
                val g = syntheticDescriptor().identity
                store.save(GuardState(GuardEntry(g, now, now + 3600)))
                store.load() shouldBe GuardLoad.Invalid
                store.save(GuardState(GuardEntry(g, now + 86_400, now + 86_400 + 40 * 86_400L)))
                store.load() shouldBe GuardLoad.Invalid
                store.save(GuardState(GuardEntry(g, now, now + 40 * 86_400L, consecutiveFailures = -1)))
                store.load() shouldBe GuardLoad.Invalid
            }
        }

        test("every write uses a fresh nonce and the file is private") {
            val file = Files.createTempDirectory("guards").resolve("guards.bin")
            EncryptedFileGuardStateStore(file, identity).use { store ->
                val s = state()
                store.save(s)
                val first = Files.readAllBytes(file)
                store.save(s)
                val second = Files.readAllBytes(file)
                first.copyOfRange(5, 17).contentEquals(second.copyOfRange(5, 17)) shouldBe false
                runCatching { Files.getPosixFilePermissions(file) }.getOrNull()?.let {
                    it shouldBe setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)
                }
            }
        }

        test(
            "a deleted file after anonymity mode resets with a warning, a first start stays silent, the log has no content",
        ) {
            val logs = ListAppender<ILoggingEvent>().also { it.start() }
            val root = LoggerFactory.getLogger("net.lapisphilosophorum") as Logger
            val old = root.level
            root.level = Level.DEBUG
            root.addAppender(logs)
            try {
                val file = Files.createTempDirectory("guards").resolve("guards.bin")
                var resets = 0
                val clock =
                    net.lapisphilosophorum.lapisnet.onionwire
                        .WireTestClock()
                // first start: no file, no state expected, silent
                EncryptedFileGuardStateStore(file, identity).use { store ->
                    GuardManager(store, seededRandom(1), clock, missingIsReset = false) { resets++ }
                    resets shouldBe 0
                    logs.list.none { it.formattedMessage.contains("guard state") } shouldBe true
                }
                // the previous run was in anonymity mode but the file is gone
                EncryptedFileGuardStateStore(file, identity).use { store ->
                    GuardManager(store, seededRandom(1), clock, missingIsReset = true) { resets++ }
                }
                resets shouldBe 1
                val warn = logs.list.single { it.formattedMessage.contains("guard state") }
                warn.level shouldBe Level.WARN
                warn.formattedMessage shouldBe "guard state invalid, reselected guards"
            } finally {
                root.detachAppender(logs)
                root.level = old
            }
        }
    })
