package net.lapisphilosophorum.lapisnet.directory

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant

class DirectoryModeTransitionTest :
    FunSpec({
        val identity = DualKeyIdentity.generate()
        val nowMillis = System.currentTimeMillis()

        test("a first start without any state is OFF and a start in OFF needs no retiring record") {
            val t = DirectoryModeTransition(identity, InMemoryDirectoryModeStore()) { nowMillis }
            t.previousMode() shouldBe DirectoryAnonymityMode.OFF
            t.prepare(DirectoryAnonymityMode.OFF) shouldBe DirectoryTransitionPlan.None
        }

        test("a first start without state directly in ON builds no tombstone, and the first record still persists ON") {
            val store = InMemoryDirectoryModeStore()
            val t = DirectoryModeTransition(identity, store) { nowMillis }
            t.hasPersistedState() shouldBe false
            t.prepare(DirectoryAnonymityMode.ON) shouldBe DirectoryTransitionPlan.None
            val first = t.nextSequence(DirectoryAnonymityMode.ON)
            store.load() shouldBe DirectoryModeState(DirectoryAnonymityMode.ON, first)
            t.hasPersistedState() shouldBe true
        }

        test("a persisted OFF state followed by ON still builds the tombstone") {
            val store = InMemoryDirectoryModeStore(DirectoryModeState(DirectoryAnonymityMode.OFF, nowMillis - 5000))
            DirectoryModeTransition(identity, store) { nowMillis }
                .prepare(DirectoryAnonymityMode.ON)
                .shouldBeInstanceOf<DirectoryTransitionPlan.Tombstone>()
        }

        test("OFF to ON builds an address-free tombstone, then the anonymous record gets a higher sequence number") {
            val store = InMemoryDirectoryModeStore(DirectoryModeState(DirectoryAnonymityMode.OFF, nowMillis - 5000))
            val t = DirectoryModeTransition(identity, store) { nowMillis }
            val plan = t.prepare(DirectoryAnonymityMode.ON).shouldBeInstanceOf<DirectoryTransitionPlan.Tombstone>()
            val tombstone = plan.record
            tombstone.addresses.size shouldBe 0
            PeerRecord.verify(tombstone) shouldBe true
            val first = t.nextSequence(DirectoryAnonymityMode.ON)
            (first > tombstone.sequenceNumber) shouldBe true
            store.load() shouldBe DirectoryModeState(DirectoryAnonymityMode.ON, first)
            // restarted in ON: nothing more to retire
            DirectoryModeTransition(identity, store) { nowMillis }.prepare(DirectoryAnonymityMode.ON) shouldBe
                DirectoryTransitionPlan.None
        }

        test(
            "a crash between the tombstone and the first anonymous record repeats the tombstone with a higher sequence",
        ) {
            val store = InMemoryDirectoryModeStore(DirectoryModeState(DirectoryAnonymityMode.OFF, nowMillis - 5000))
            val first = DirectoryModeTransition(identity, store) { nowMillis }
            val a = (first.prepare(DirectoryAnonymityMode.ON) as DirectoryTransitionPlan.Tombstone).record
            val again = DirectoryModeTransition(identity, store) { nowMillis }
            val b = (again.prepare(DirectoryAnonymityMode.ON) as DirectoryTransitionPlan.Tombstone).record
            (b.sequenceNumber > a.sequenceNumber) shouldBe true
        }

        test("ON to OFF builds a revocation that covers every still-valid anonymous record, then a higher sequence") {
            val store = InMemoryDirectoryModeStore(DirectoryModeState(DirectoryAnonymityMode.ON, nowMillis - 5000))
            val t = DirectoryModeTransition(identity, store) { nowMillis }
            val plan = t.prepare(DirectoryAnonymityMode.OFF).shouldBeInstanceOf<DirectoryTransitionPlan.Revocation>()
            val revocation = plan.record
            revocation.revoked shouldBe true
            val now = nowMillis / 1000
            AnonymousPeerRecord.verify(revocation, now) shouldBe true
            // outlives an anonymous record created at the same moment with the longest allowed TTL
            (revocation.notValidAfterEpochSecond >= now + AnonymousPeerRecord.MAX_TTL_WINDOW_SECONDS) shouldBe true
            (revocation.sequenceNumber > nowMillis - 5000) shouldBe true
            (t.nextSequence(DirectoryAnonymityMode.OFF) > revocation.sequenceNumber) shouldBe true
        }

        test("sequence numbers never repeat or regress, even when the clock stands still or goes back") {
            val t = DirectoryModeTransition(identity, InMemoryDirectoryModeStore()) { nowMillis }
            val seq = List(5) { t.nextSequence(DirectoryAnonymityMode.ON) }
            seq shouldBe seq.sorted()
            seq.toSet().size shouldBe 5
            val back =
                DirectoryModeTransition(
                    identity,
                    InMemoryDirectoryModeStore(
                        DirectoryModeState(
                            DirectoryAnonymityMode.ON,
                            nowMillis + 10_000,
                        ),
                    ),
                ) { nowMillis - 1_000_000 }
            (back.nextSequence(DirectoryAnonymityMode.ON) > nowMillis + 10_000) shouldBe true
        }

        test("a full cycle OFF to ON to OFF keeps one current record type in the index of a third node") {
            val peers = PeerRecordIndex()
            val anon = AnonymousPeerRecordIndex(peers)
            val serviceKey =
                net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
                    .generate()
            val store = InMemoryDirectoryModeStore()
            val now = Instant.now().epochSecond
            val key = identity.secp256k1KeyPair.publicKey

            // normal mode before the first switch
            val t0 = DirectoryModeTransition(identity, store) { nowMillis }
            val normal =
                PeerRecord.create(
                    identity,
                    listOf(
                        io.libp2p.core.multiformats
                            .Multiaddr("/ip4/127.0.0.1/tcp/4001"),
                    ),
                    emptySet(),
                    t0.nextSequence(DirectoryAnonymityMode.OFF),
                    now + 600,
                )
            peers.add(normal) shouldBe true

            // OFF -> ON
            val t1 = DirectoryModeTransition(identity, store) { nowMillis }
            val tombstone = (t1.prepare(DirectoryAnonymityMode.ON) as DirectoryTransitionPlan.Tombstone).record
            peers.add(tombstone) shouldBe true
            peers.current(key)!!.addresses.size shouldBe 0
            val a =
                AnonymousPeerRecord.create(
                    identity,
                    serviceKey,
                    setOf(AnonymousCapability.DM),
                    null,
                    t1.nextSequence(DirectoryAnonymityMode.ON),
                    now + 600,
                    now,
                )
            anon.add(a, now) shouldBe AnonymousIngestOutcome.ACCEPTED
            peers.current(key).shouldBeNull()
            peers.add(normal) shouldBe false // the old address record can not return

            // ON -> OFF
            val t2 = DirectoryModeTransition(identity, store) { nowMillis }
            val revocation = (t2.prepare(DirectoryAnonymityMode.OFF) as DirectoryTransitionPlan.Revocation).record
            anon.add(revocation, now) shouldBe AnonymousIngestOutcome.ACCEPTED
            anon.isRevoked(key, now) shouldBe true
            val back =
                PeerRecord.create(
                    identity,
                    listOf(
                        io.libp2p.core.multiformats
                            .Multiaddr("/ip4/127.0.0.1/tcp/4001"),
                    ),
                    emptySet(),
                    t2.nextSequence(DirectoryAnonymityMode.OFF),
                    now + 600,
                )
            peers.add(back) shouldBe true
            anon.current(key, now).shouldBeNull()
            anon.isRevoked(key, now) shouldBe false
        }
    })

class FileDirectoryModeStoreTest :
    FunSpec({
        fun tempFile(): Path = Files.createTempDirectory("mode-store").resolve("directory-mode.state")

        test("a missing file means no state, which is treated as OFF") {
            val store = FileDirectoryModeStore(tempFile())
            store.load().shouldBeNull()
            DirectoryModeTransition(DualKeyIdentity.generate(), store).previousMode() shouldBe
                DirectoryAnonymityMode.OFF
        }

        test("state survives a restart") {
            val file = tempFile()
            FileDirectoryModeStore(file).save(DirectoryModeState(DirectoryAnonymityMode.ON, 123_456_789L))
            FileDirectoryModeStore(file).load() shouldBe DirectoryModeState(DirectoryAnonymityMode.ON, 123_456_789L)
        }

        test("a corrupt, truncated or foreign file is treated as no state, never as an error") {
            for (content in listOf(ByteArray(0), ByteArray(3) { 1 }, ByteArray(14) { 0x41 }, ByteArray(500) { 7 })) {
                val file = tempFile()
                Files.write(file, content)
                FileDirectoryModeStore(file).load().shouldBeNull()
            }
            val bad = tempFile()
            FileDirectoryModeStore(bad).save(DirectoryModeState(DirectoryAnonymityMode.ON, 5))
            val bytes = Files.readAllBytes(bad)
            bytes[5] = 9 // unknown mode ordinal
            Files.write(bad, bytes)
            FileDirectoryModeStore(bad).load().shouldBeNull()
        }

        test("writing is atomic: no temporary file stays behind and overwriting works") {
            val file = tempFile()
            val store = FileDirectoryModeStore(file)
            repeat(10) { store.save(DirectoryModeState(DirectoryAnonymityMode.entries[it % 2], it.toLong())) }
            store.load() shouldBe DirectoryModeState(DirectoryAnonymityMode.entries[1], 9)
            Files.list(file.parent).use { it.count() } shouldBe 1
        }

        test("a corrupt file does not leak its content into the log") {
            val file = tempFile()
            Files.write(file, "SECRET-CONTENT-123456".toByteArray())
            val root = org.slf4j.LoggerFactory.getLogger("net.lapisphilosophorum") as ch.qos.logback.classic.Logger
            val appender =
                ch.qos.logback.core.read
                    .ListAppender<ch.qos.logback.classic.spi.ILoggingEvent>()
                    .also { it.start() }
            root.addAppender(appender)
            try {
                FileDirectoryModeStore(file).load().shouldBeNull()
                appender.list.none { it.formattedMessage.contains("SECRET") } shouldBe true
            } finally {
                root.detachAppender(appender)
            }
        }
    })
