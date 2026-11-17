@file:OptIn(ExperimentalOnionApi::class)

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
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptor
import net.lapisphilosophorum.lapisnet.onionwire.anonymity.AnonymityRuntime
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
            clock: () -> Long = System::currentTimeMillis,
            tombstone: (PeerRecord) -> Unit,
        ) = AnonymousDirectoryPublisher(
            identity,
            Ed25519KeyPair.generate(),
            prekeys,
            OkChannel(),
            store,
            clockMillis = clock,
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

        test("a tombstone publisher that throws is retried after the backoff; the mode stays OFF until it succeeded") {
            var attempts = 0
            var now = System.currentTimeMillis()
            val store = normalModeStore()
            publisher(store, { now }) {
                attempts++
                if (attempts == 1) throw IllegalStateException("no relay accepted it")
            }.use {
                runCatching { it.tick() }.isFailure shouldBe true
                store.load()!!.mode shouldBe DirectoryAnonymityMode.OFF
                it.publications shouldBe 0
                now += 5_000
                it.tick() shouldBe true
            }
            attempts shouldBe 2
            store.load()!!.mode shouldBe DirectoryAnonymityMode.ON
        }

        test("a failing tombstone is retried along the backoff, not once per second, and holds the record back") {
            var attempts = 0
            var now = System.currentTimeMillis()
            publisher(normalModeStore(), { now }) {
                attempts++
                // a slow failure (circuit timeout): the backoff counts from when the publisher gave up
                now += 2_000
                throw IllegalStateException("no relay supports tombstones yet")
            }.use {
                runCatching { it.tick() }.isFailure shouldBe true
                attempts shouldBe 1
                it.nextDelayMillis() shouldBe 5_000L
                // within the backoff: no new attempt, no anonymous record (fail-closed)
                now += 4_000
                it.tick() shouldBe false
                attempts shouldBe 1
                it.publications shouldBe 0
                // the backoff grows: 5 s, 15 s, 45 s, then the retry interval (1 min)
                now += 1_000
                runCatching { it.tick() }.isFailure shouldBe true
                attempts shouldBe 2
                it.nextDelayMillis() shouldBe 15_000L
                now += 15_000
                runCatching { it.tick() }.isFailure shouldBe true
                it.nextDelayMillis() shouldBe 45_000L
                now += 45_000
                runCatching { it.tick() }.isFailure shouldBe true
                it.nextDelayMillis() shouldBe 60_000L
                attempts shouldBe 4
                it.publications shouldBe 0
            }
        }

        test("the production tombstone path throws and cancels the future when no relay answers in time") {
            val pending = CompletableFuture<Boolean>()
            val channel =
                object : DirectoryPublicationChannel by OkChannel() {
                    override fun publishTombstone(tombstone: PeerRecord) = pending
                }
            val tombstone =
                PeerRecord.create(
                    identity,
                    emptyList(),
                    emptySet(),
                    1,
                    System.currentTimeMillis() / 1000 + 600,
                )
            runCatching {
                AnonymityRuntime.publishTombstoneOrThrow(channel, tombstone, waitSeconds = 1)
            }.isFailure shouldBe true
            pending.isCancelled shouldBe true
            val refused =
                object : DirectoryPublicationChannel by OkChannel() {
                    override fun publishTombstone(tombstone: PeerRecord) = CompletableFuture.completedFuture(false)
                }
            runCatching {
                AnonymityRuntime.publishTombstoneOrThrow(refused, tombstone)
            }.isFailure shouldBe true
        }
    })
