@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onionwire

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import net.lapisphilosophorum.lapisnet.directory.AnonymousPeerRecord
import net.lapisphilosophorum.lapisnet.directory.DirectoryAnonymityMode
import net.lapisphilosophorum.lapisnet.directory.DirectoryModeRetirement
import net.lapisphilosophorum.lapisnet.directory.DirectoryModeTransition
import net.lapisphilosophorum.lapisnet.directory.DirectoryPublicationChannel
import net.lapisphilosophorum.lapisnet.directory.FileDirectoryModeStore
import net.lapisphilosophorum.lapisnet.directory.PeerRecord
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptor
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundle
import java.nio.file.Files
import java.util.concurrent.CompletableFuture

private class RecordingChannel : DirectoryPublicationChannel {
    val records = ArrayList<AnonymousPeerRecord>()
    override val exposesOrigin: Boolean get() = false

    override fun publishAnonymousPeerRecord(record: AnonymousPeerRecord): CompletableFuture<Boolean> {
        records += record
        return CompletableFuture.completedFuture(true)
    }

    override fun publishPrekeyBundle(bundle: PrekeyBundle) = CompletableFuture.completedFuture(true)

    override fun publishServiceDescriptor(descriptor: OnionServiceDescriptor) = CompletableFuture.completedFuture(true)
}

class AnonymityModeTransitionWiringTest :
    FunSpec({
        val identity = DualKeyIdentity.generate()
        var clock = System.currentTimeMillis()
        val tick = { clock++ }

        fun publisher(
            store: FileDirectoryModeStore,
            channel: RecordingChannel,
            tombstones: MutableList<PeerRecord>,
        ) = AnonymousDirectoryPublisher(
            identity,
            Ed25519KeyPair.generate(),
            null,
            channel,
            store,
            clockMillis = tick,
            tombstonePublisher = { tombstones += it },
        )

        test(
            "OFF start persists OFF; OFF to ON sends exactly one tombstone above every OFF sequence; ON to OFF revokes",
        ) {
            val file = Files.createTempDirectory("mode").resolve("directory-mode.state")
            val offSequences = ArrayList<Long>()

            // 1. normal start (first ever): nothing to retire, OFF is persisted, the own records get persisted sequences
            run {
                val store = FileDirectoryModeStore(file)
                val transition = DirectoryModeTransition(identity, store, tick)
                DirectoryModeRetirement.onNormalStart(transition) { error("nothing to retire") } shouldBe true
                store.load()!!.mode shouldBe DirectoryAnonymityMode.OFF
                repeat(3) { offSequences += transition.nextSequence(DirectoryAnonymityMode.OFF) }
            }
            (offSequences == offSequences.sorted() && offSequences.toSet().size == 3) shouldBe true

            // 2. restart in ON: one tombstone, its sequence above all OFF records, never repeated by the next tick
            val tombstones = ArrayList<PeerRecord>()
            val channel = RecordingChannel()
            run {
                val p = publisher(FileDirectoryModeStore(file), channel, tombstones)
                p.tick() shouldBe true
                p.tick() shouldBe true
                p.close()
            }
            tombstones.size shouldBe 1
            tombstones.single().addresses.size shouldBe 0
            (tombstones.single().sequenceNumber > offSequences.max()) shouldBe true
            (channel.records.single().sequenceNumber > tombstones.single().sequenceNumber) shouldBe true
            FileDirectoryModeStore(file).load()!!.mode shouldBe DirectoryAnonymityMode.ON

            // 3. a restart in ON again: the state is ON, no second tombstone
            run {
                val p = publisher(FileDirectoryModeStore(file), RecordingChannel(), tombstones)
                p.tick()
                p.close()
            }
            tombstones.size shouldBe 1

            // 4. back to OFF: a revocation above every anonymous record is published once, then OFF is persisted
            val revocations = ArrayList<AnonymousPeerRecord>()
            run {
                val store = FileDirectoryModeStore(file)
                val transition = DirectoryModeTransition(identity, store, tick)
                DirectoryModeRetirement.onNormalStart(transition) { revocations += it } shouldBe true
                store.load()!!.mode shouldBe DirectoryAnonymityMode.OFF
            }
            revocations.size shouldBe 1
            (revocations.single().sequenceNumber > channel.records.maxOf { it.sequenceNumber }) shouldBe true
            revocations.single().revoked shouldBe true

            // 5. another normal start: nothing more to retire
            run {
                val transition = DirectoryModeTransition(identity, FileDirectoryModeStore(file), tick)
                DirectoryModeRetirement.onNormalStart(transition) { error("already retired") } shouldBe true
            }
        }

        test("a first start directly in ON sends no tombstone") {
            val file = Files.createTempDirectory("mode").resolve("directory-mode.state")
            val tombstones = ArrayList<PeerRecord>()
            val channel = RecordingChannel()
            val p = publisher(FileDirectoryModeStore(file), channel, tombstones)
            p.tick() shouldBe true
            p.close()
            tombstones.size shouldBe 0
            channel.records.size shouldBe 1
        }

        test("a revocation that can not be sent keeps the anonymity state for a retry at the next start") {
            val file = Files.createTempDirectory("mode").resolve("directory-mode.state")
            run {
                val p = publisher(FileDirectoryModeStore(file), RecordingChannel(), ArrayList())
                p.tick()
                p.close()
            }
            val store = FileDirectoryModeStore(file)
            val transition = DirectoryModeTransition(identity, store, tick)
            DirectoryModeRetirement.onNormalStart(transition) { throw IllegalStateException("no mesh peer") } shouldBe
                false
            store.load()!!.mode shouldBe DirectoryAnonymityMode.ON
            // the next start retries with a higher sequence
            val second = ArrayList<AnonymousPeerRecord>()
            DirectoryModeRetirement.onNormalStart(
                DirectoryModeTransition(identity, FileDirectoryModeStore(file), tick),
            ) {
                second += it
            } shouldBe true
            second.size shouldBe 1
            FileDirectoryModeStore(file).load()!!.mode shouldBe DirectoryAnonymityMode.OFF
        }

        test("a damaged mode file counts as a first start: no tombstone, no revocation") {
            val file = Files.createTempDirectory("mode").resolve("directory-mode.state")
            Files.write(file, byteArrayOf(1, 2, 3))
            val tombstones = ArrayList<PeerRecord>()
            val p = publisher(FileDirectoryModeStore(file), RecordingChannel(), tombstones)
            p.tick()
            p.close()
            tombstones.size shouldBe 0
            FileDirectoryModeStore(
                file,
            ).load().shouldBeInstanceOf<net.lapisphilosophorum.lapisnet.directory.DirectoryModeState>()
        }
    })
