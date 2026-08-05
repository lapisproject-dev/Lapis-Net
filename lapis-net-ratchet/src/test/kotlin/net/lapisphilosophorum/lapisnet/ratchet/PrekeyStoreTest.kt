package net.lapisphilosophorum.lapisnet.ratchet

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.KeystoreDecryptionException
import net.lapisphilosophorum.lapisnet.identity.PassphraseProvider
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission

class PrekeyStoreTest :
    FunSpec({
        test("create generates the expected one-time prekeys and nextOneTimePrekeyId") {
            val dir = Files.createTempDirectory("prekeystore-test")
            val identity = DualKeyIdentity.generate()
            val store = PrekeyStore.create(dir, identity, oneTimePrekeyCount = 5)
            store.availableOneTimePrekeyIds() shouldBe listOf(0, 1, 2, 3, 4)
            store.availableOneTimePrekeyCount() shouldBe 5
        }

        test("create refuses to overwrite an existing store file") {
            val dir = Files.createTempDirectory("prekeystore-test")
            val identity = DualKeyIdentity.generate()
            PrekeyStore.create(dir, identity, label = "alice", oneTimePrekeyCount = 1)
            shouldThrow<IllegalStateException> {
                PrekeyStore.create(dir, identity, label = "alice", oneTimePrekeyCount = 1)
            }
        }

        test("open returns null for an absent store") {
            val dir = Files.createTempDirectory("prekeystore-test")
            PrekeyStore.open(dir, label = "nobody") shouldBe null
        }

        test("open round-trips every public field") {
            val dir = Files.createTempDirectory("prekeystore-test")
            val identity = DualKeyIdentity.generate()
            val created = PrekeyStore.create(dir, identity, oneTimePrekeyCount = 3)
            val reopened = PrekeyStore.open(dir)!!
            reopened.ownerIdentity shouldBe created.ownerIdentity
            reopened.x25519IdentityPublicKey shouldBe created.x25519IdentityPublicKey
            reopened.signedPrekeyId shouldBe created.signedPrekeyId
            reopened.signedPrekeyPublicKey shouldBe created.signedPrekeyPublicKey
            reopened.availableOneTimePrekeyIds() shouldBe created.availableOneTimePrekeyIds()
        }

        test("consumption is durable across a simulated restart - plaintext store") {
            val dir = Files.createTempDirectory("prekeystore-test")
            val identity = DualKeyIdentity.generate()
            val store = PrekeyStore.create(dir, identity, oneTimePrekeyCount = 3)
            store.consumeOneTimePrekey(1)

            val reopened = PrekeyStore.open(dir)!!
            shouldThrow<PrekeyConsumptionException> { reopened.consumeOneTimePrekey(1) }
            reopened.availableOneTimePrekeyIds() shouldBe listOf(0, 2)
        }

        test("consumption is durable across a simulated restart - encrypted store") {
            val dir = Files.createTempDirectory("prekeystore-test")
            val identity = DualKeyIdentity.generate()
            val passphraseProvider = PassphraseProvider { "correct horse battery staple".toCharArray() }
            val store =
                PrekeyStore.create(
                    dir,
                    identity,
                    oneTimePrekeyCount = 3,
                    passphraseProvider = passphraseProvider,
                )
            store.consumeOneTimePrekey(1)

            val reopened = PrekeyStore.open(dir, passphraseProvider = passphraseProvider)!!
            shouldThrow<PrekeyConsumptionException> { reopened.consumeOneTimePrekey(1) }
            reopened.availableOneTimePrekeyIds() shouldBe listOf(0, 2)
        }

        test("double consumption within one instance throws") {
            val dir = Files.createTempDirectory("prekeystore-test")
            val identity = DualKeyIdentity.generate()
            val store = PrekeyStore.create(dir, identity, oneTimePrekeyCount = 1)
            store.consumeOneTimePrekey(0)
            shouldThrow<PrekeyConsumptionException> { store.consumeOneTimePrekey(0) }
        }

        test(
            "TWO concurrently-open PrekeyStore handles on the SAME file cannot both consume the same id - " +
                "the exact reuse this class exists to prevent, reproduced with two LIVE handles rather than " +
                "an open-after-close 'simulated restart'",
        ) {
            val dir = Files.createTempDirectory("prekeystore-test")
            val identity = DualKeyIdentity.generate()
            val a = PrekeyStore.create(dir, identity, oneTimePrekeyCount = 3)
            val b = PrekeyStore.open(dir)!!
            // Both handles are live at the same time - `a` is not closed/discarded before `b` opens.
            val consumedByA = a.consumeOneTimePrekey(0)
            // If `b` mutated from its own stale cached state instead of re-reading disk truth, this
            // would wrongly succeed AND return a byte-identical private key to consumedByA's.
            shouldThrow<PrekeyConsumptionException> { b.consumeOneTimePrekey(0) }

            // `b`'s own second attempt, on a DIFFERENT id, must succeed and must not resurrect `a`'s
            // tombstone for id 0 - the specific failure mode where a stale-state write silently
            // erases another handle's already-persisted consumption.
            val consumedByB = b.consumeOneTimePrekey(1)
            consumedByB.id shouldBe 1
            consumedByA.privateKey.bytes.contentEquals(consumedByB.privateKey.bytes) shouldBe false

            val reopened = PrekeyStore.open(dir)!!
            reopened.availableOneTimePrekeyIds() shouldBe listOf(2)
            shouldThrow<PrekeyConsumptionException> { reopened.consumeOneTimePrekey(0) }
            shouldThrow<PrekeyConsumptionException> { reopened.consumeOneTimePrekey(1) }
        }

        test("consuming an unknown id throws") {
            val dir = Files.createTempDirectory("prekeystore-test")
            val identity = DualKeyIdentity.generate()
            val store = PrekeyStore.create(dir, identity, oneTimePrekeyCount = 1)
            shouldThrow<PrekeyConsumptionException> { store.consumeOneTimePrekey(999) }
        }

        test("the returned private key is the one whose public half was published") {
            val dir = Files.createTempDirectory("prekeystore-test")
            val identity = DualKeyIdentity.generate()
            val store = PrekeyStore.create(dir, identity, oneTimePrekeyCount = 1)
            val bundle =
                store.publishBundle(
                    identity,
                    sequenceNumber = 1,
                    notValidAfterEpochSecond = 100_000L,
                    nowEpochSecond = 0,
                )
            val publishedPublicKey = bundle.oneTimePrekeys.single().publicKey
            val consumed = store.consumeOneTimePrekey(0)
            consumed.id shouldBe 0
            X25519KeyPair.fromPrivateKeyBytes(consumed.privateKey.bytes).publicKey shouldBe publishedPublicKey
        }

        test("after consumption, the on-disk tombstone's private key bytes are all-zero") {
            val dir = Files.createTempDirectory("prekeystore-test")
            val identity = DualKeyIdentity.generate()
            val store = PrekeyStore.create(dir, identity, oneTimePrekeyCount = 1)
            store.consumeOneTimePrekey(0)

            val file = dir.resolve("default.lnpk")
            val state = PrekeyStoreFileFormat.decode(Files.readAllBytes(file))
            val entry = state.entries.single { it.id == 0 }
            entry.state shouldBe OneTimePrekeyState.CONSUMED
            entry.privateKeyBytes.all { it == 0.toByte() } shouldBe true
        }

        test("exhaustion: consuming all one-time prekeys still leaves a valid, empty-one-time-prekey bundle") {
            val dir = Files.createTempDirectory("prekeystore-test")
            val identity = DualKeyIdentity.generate()
            val store = PrekeyStore.create(dir, identity, oneTimePrekeyCount = 2)
            store.consumeOneTimePrekey(0)
            store.consumeOneTimePrekey(1)
            store.availableOneTimePrekeyCount() shouldBe 0

            val bundle =
                store.publishBundle(
                    identity,
                    sequenceNumber = 1,
                    notValidAfterEpochSecond = 100_000L,
                    nowEpochSecond = 0,
                )
            bundle.oneTimePrekeys shouldBe emptyList()
            PrekeyBundle.verify(bundle) shouldBe true
            bundle.verifyEncryptionBinding() shouldBe true
            bundle.verifySignedPrekey() shouldBe true
        }

        test("generateOneTimePrekeys never reissues a consumed id, and nextOneTimePrekeyId stays monotonic") {
            val dir = Files.createTempDirectory("prekeystore-test")
            val identity = DualKeyIdentity.generate()
            val store = PrekeyStore.create(dir, identity, oneTimePrekeyCount = 2)
            store.consumeOneTimePrekey(0)
            val newOnes = store.generateOneTimePrekeys(2)
            newOnes.map { it.id } shouldBe listOf(2, 3)
            store.availableOneTimePrekeyIds() shouldBe listOf(1, 2, 3)
        }

        test("pruning at MAX_ONE_TIME_PREKEY_ENTRIES removes tombstones only, never available entries") {
            val dir = Files.createTempDirectory("prekeystore-test")
            val identity = DualKeyIdentity.generate()
            val store = PrekeyStore.create(dir, identity, oneTimePrekeyCount = 0)
            store.generateOneTimePrekeys(PrekeyStoreFileFormat.MAX_ONE_TIME_PREKEY_ENTRIES)
            // Consume the first 10 (oldest ids) to create tombstones.
            (0 until 10).forEach { store.consumeOneTimePrekey(it) }
            store.availableOneTimePrekeyCount() shouldBe (PrekeyStoreFileFormat.MAX_ONE_TIME_PREKEY_ENTRIES - 10)

            val newOnes = store.generateOneTimePrekeys(10)
            newOnes.size shouldBe 10
            // Total entries must stay at the cap - the 10 oldest tombstones (ids 0..9) were pruned.
            val file = dir.resolve("default.lnpk")
            val state = PrekeyStoreFileFormat.decode(Files.readAllBytes(file))
            state.entries.size shouldBe PrekeyStoreFileFormat.MAX_ONE_TIME_PREKEY_ENTRIES
            state.entries.none { it.id in 0 until 10 } shouldBe true
            // All 10 tombstones were pruned (never a live/AVAILABLE entry) - every remaining entry,
            // including the 10 freshly generated ones, is AVAILABLE, so the count is back to the cap.
            state.entries.count { it.state == OneTimePrekeyState.AVAILABLE } shouldBe
                PrekeyStoreFileFormat.MAX_ONE_TIME_PREKEY_ENTRIES
            state.entries.count { it.state == OneTimePrekeyState.CONSUMED } shouldBe 0
        }

        test("POSIX file permissions on the created store are rw-------") {
            val dir = Files.createTempDirectory("prekeystore-test")
            val identity = DualKeyIdentity.generate()
            PrekeyStore.create(dir, identity, oneTimePrekeyCount = 1)
            val file = dir.resolve("default.lnpk")
            if ("posix" !in file.fileSystem.supportedFileAttributeViews()) return@test
            val permissions = Files.getPosixFilePermissions(file)
            permissions shouldBe
                setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)
        }

        test("encrypted store: wrong passphrase throws KeystoreDecryptionException") {
            val dir = Files.createTempDirectory("prekeystore-test")
            val identity = DualKeyIdentity.generate()
            PrekeyStore.create(
                dir,
                identity,
                oneTimePrekeyCount = 1,
                passphraseProvider =
                    PassphraseProvider {
                        "right".toCharArray()
                    },
            )
            shouldThrow<KeystoreDecryptionException> {
                PrekeyStore.open(dir, passphraseProvider = PassphraseProvider { "wrong".toCharArray() })
            }
        }

        test(
            "encrypted store: a single flipped byte in the salt/nonce/ciphertext region throws " +
                "KeystoreDecryptionException - the Argon2-cost-parameter header bytes are covered separately " +
                "by the implausible-params test below, since those are validated BEFORE decryption is attempted",
        ) {
            val dir = Files.createTempDirectory("prekeystore-test")
            val identity = DualKeyIdentity.generate()
            val passphraseProvider = PassphraseProvider { "correct horse battery staple".toCharArray() }
            PrekeyStore.create(dir, identity, oneTimePrekeyCount = 1, passphraseProvider = passphraseProvider)
            val file = dir.resolve("default.lnpk")
            val bytes = Files.readAllBytes(file)
            // Salt starts at header offset 15; everything from there to end of file (salt, nonce,
            // ciphertext, GCM tag) is authenticated/derivation-relevant but NOT sanity-range-checked
            // before decryption, so tampering any byte there is guaranteed to surface as a
            // KeystoreDecryptionException, never a CorruptedPrekeyStoreException.
            for (i in 15 until bytes.size step 41) {
                val tampered = bytes.copyOf()
                tampered[i] = (tampered[i] + 1).toByte()
                shouldThrow<KeystoreDecryptionException> {
                    PrekeyStoreFileFormat.decodeEncrypted(tampered, passphraseProvider.get()!!)
                }
            }
        }

        test("encrypted store: an oversized file is rejected before decryption") {
            val identity = DualKeyIdentity.generate()
            val dir = Files.createTempDirectory("prekeystore-test")
            val passphraseProvider = PassphraseProvider { "correct horse battery staple".toCharArray() }
            PrekeyStore.create(dir, identity, oneTimePrekeyCount = 1, passphraseProvider = passphraseProvider)
            val oversized = ByteArray(PrekeyStoreFileFormat.MAX_STORE_FILE_BYTES + 1)
            shouldThrow<CorruptedPrekeyStoreException> {
                PrekeyStoreFileFormat.decodeAuto(oversized, passphraseProvider.get())
            }
        }

        test("encrypted store: implausible Argon2 params are rejected before Argon2 ever runs") {
            val identity = DualKeyIdentity.generate()
            val dir = Files.createTempDirectory("prekeystore-test")
            val passphraseProvider = PassphraseProvider { "correct horse battery staple".toCharArray() }
            val store =
                PrekeyStore.create(
                    dir,
                    identity,
                    oneTimePrekeyCount = 1,
                    passphraseProvider = passphraseProvider,
                )
            val file = dir.resolve("default.lnpk")
            val bytes = Files.readAllBytes(file).copyOf()
            // memoryKiB lives at header offset 6..9 (big-endian Int) - set it absurdly high.
            bytes[6] = 0x7F
            bytes[7] = 0x7F.toByte()
            bytes[8] = 0xFF.toByte()
            bytes[9] = 0xFF.toByte()
            shouldThrow<CorruptedPrekeyStoreException> {
                PrekeyStoreFileFormat.decodeEncrypted(bytes, passphraseProvider.get()!!)
            }
            store shouldNotBe null
        }

        test("v1-to-v2 migration: a plaintext store opened with a passphrase provider is re-saved encrypted") {
            val dir = Files.createTempDirectory("prekeystore-test")
            val identity = DualKeyIdentity.generate()
            PrekeyStore.create(dir, identity, oneTimePrekeyCount = 1) // plaintext, no passphrase
            val file = dir.resolve("default.lnpk")
            PrekeyStoreFileFormat.formatVersionOf(Files.readAllBytes(file)) shouldBe
                PrekeyStoreFileFormat.FORMAT_VERSION_1

            val passphraseProvider = PassphraseProvider { "a new passphrase".toCharArray() }
            PrekeyStore.open(dir, passphraseProvider = passphraseProvider)

            PrekeyStoreFileFormat.formatVersionOf(Files.readAllBytes(file)) shouldBe
                PrekeyStoreFileFormat.FORMAT_VERSION_2
            val reopened = PrekeyStore.open(dir, passphraseProvider = passphraseProvider)!!
            reopened.availableOneTimePrekeyIds() shouldBe listOf(0)
        }
    })
