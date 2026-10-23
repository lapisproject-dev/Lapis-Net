package net.lapisphilosophorum.lapisnet.onionwire

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.directory.AnonymousPeerRecord
import net.lapisphilosophorum.lapisnet.directory.DirectoryAnonymityMode
import net.lapisphilosophorum.lapisnet.directory.DirectoryModeState
import net.lapisphilosophorum.lapisnet.directory.DirectoryPublicationChannel
import net.lapisphilosophorum.lapisnet.directory.InMemoryDirectoryModeStore
import net.lapisphilosophorum.lapisnet.directory.PeerRecord
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptor
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundle
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyStore
import java.nio.file.Files
import java.util.concurrent.CompletableFuture

private class OkChannel : DirectoryPublicationChannel {
    override val exposesOrigin = false

    override fun publishAnonymousPeerRecord(record: AnonymousPeerRecord) = CompletableFuture.completedFuture(true)

    override fun publishPrekeyBundle(bundle: PrekeyBundle) = CompletableFuture.completedFuture(true)

    override fun publishServiceDescriptor(descriptor: OnionServiceDescriptor) = CompletableFuture.completedFuture(true)
}

class AnonymousDirectoryPublisherTombstoneTest :
    FunSpec({
        val identity = DualKeyIdentity.generate()
        val prekeys = PrekeyStore.create(Files.createTempDirectory("tombstone-prekeys"), identity)

        fun publisher(
            store: InMemoryDirectoryModeStore,
            tombstone: (PeerRecord) -> Unit,
        ) = AnonymousDirectoryPublisher(
            identity,
            Ed25519KeyPair.generate(),
            prekeys,
            OkChannel(),
            store,
            tombstonePublisher = tombstone,
        )

        fun normalModeStore() =
            InMemoryDirectoryModeStore(
                DirectoryModeState(DirectoryAnonymityMode.OFF, System.currentTimeMillis() - 5000),
            )

        test("a brand-new identity starting directly in anonymity mode never publishes an identity-bound tombstone") {
            val sent = ArrayList<PeerRecord>()
            val store = InMemoryDirectoryModeStore()
            publisher(store) { sent += it }.use { it.tick() shouldBe true }
            sent.size shouldBe 0
            store.load()!!.mode shouldBe DirectoryAnonymityMode.ON
        }

        test("after a persisted normal-mode state the tombstone is sent exactly once") {
            val sent = ArrayList<PeerRecord>()
            publisher(normalModeStore()) { sent += it }.use {
                it.tick() shouldBe true
                it.tick() shouldBe true
            }
            sent.size shouldBe 1
            sent[0].addresses.size shouldBe 0
        }

        test("a tombstone publisher that throws is retried on the next tick; the mode stays OFF until it succeeded") {
            var attempts = 0
            val store = normalModeStore()
            publisher(store) {
                attempts++
                if (attempts == 1) throw IllegalStateException("no mesh peer")
            }.use {
                runCatching { it.tick() }.isFailure shouldBe true
                store.load()!!.mode shouldBe DirectoryAnonymityMode.OFF
                it.tick() shouldBe true
            }
            attempts shouldBe 2
            store.load()!!.mode shouldBe DirectoryAnonymityMode.ON
        }
    })
