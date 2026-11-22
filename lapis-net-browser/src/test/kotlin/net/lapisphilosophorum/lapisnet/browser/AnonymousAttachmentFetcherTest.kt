package net.lapisphilosophorum.lapisnet.browser

import io.ipfs.cid.Cid
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import net.lapisphilosophorum.lapisnet.dmonion.attachment.AnonymousAttachmentLimits
import net.lapisphilosophorum.lapisnet.dmonion.attachment.AttachmentFetchClient
import net.lapisphilosophorum.lapisnet.dmonion.attachment.AttachmentFetchFailure
import net.lapisphilosophorum.lapisnet.dmonion.attachment.AttachmentFetchResult
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.storage.LookupLimits
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/** An in-memory blob store that records what it is asked. */
private class MemoryStore : AttachmentBlobStore {
    val local = ConcurrentHashMap<Cid, ByteArray>()
    val unserved = ConcurrentHashMap<Cid, ByteArray>()
    val remote = ConcurrentHashMap<Cid, ByteArray>()
    val remoteCalls = CopyOnWriteArrayList<Cid>()
    val order = CopyOnWriteArrayList<String>()

    override fun getLocal(cid: Cid): ByteArray? {
        order += "local"
        return local[cid] ?: unserved[cid]
    }

    override fun putUnserved(bytes: ByteArray) {
        unserved[rawCidOf(bytes)] = bytes
    }

    override fun getThroughRemote(
        cid: Cid,
        timeout: Duration,
    ): ByteArray? {
        order += "remote"
        remoteCalls += cid
        return remote[cid]
    }
}

/** A client whose futures the test completes; records the calls. */
private class HeldClient(
    private val order: MutableList<String>,
) : AttachmentFetchClient {
    val calls = AtomicInteger()
    val futures = CopyOnWriteArrayList<CompletableFuture<AttachmentFetchResult>>()

    /** The future of each call by the CID it asked for: which coroutine reaches the client first is not deterministic. */
    val futuresByCid = java.util.concurrent.ConcurrentHashMap<Cid, CompletableFuture<AttachmentFetchResult>>()

    @Volatile var answer: AttachmentFetchResult? = null

    override fun fetch(
        sender: Secp256k1PublicKey,
        cid: Cid,
        attachmentKey: ByteArray,
        maxBytes: Int,
    ): CompletableFuture<AttachmentFetchResult> {
        order += "client"
        calls.incrementAndGet()
        val f = CompletableFuture<AttachmentFetchResult>()
        answer?.let { f.complete(it) }
        futures += f
        futuresByCid[cid] = f
        return f
    }
}

class AnonymousAttachmentFetcherTest :
    FunSpec({
        val sender = DualKeyIdentity.generate().secp256k1KeyPair.publicKey
        val key = ByteArray(32) { 1 }

        test("order: local, then the client, then (only when the sender is unreachable) the MAILBOX lookup") {
            val store = MemoryStore()
            val client = HeldClient(store.order)
            val fetcher = AnonymousAttachmentFetcher(store, { client })
            val blob = "small blob".toByteArray()
            val cid = rawCidOf(blob)
            store.remote[cid] = blob
            client.answer = AttachmentFetchResult.Unavailable(AttachmentFetchFailure.NOT_REACHABLE)
            runBlocking {
                fetcher.fetch(sender, cid, key, blob.size)
            }.shouldBeInstanceOf<AnonymousAttachmentFetcher.Outcome.Bytes>()
                .bytes shouldBe blob
            store.order shouldBe listOf("local", "client", "remote")

            // a local blob asks nobody
            store.order.clear()
            store.local[cid] = blob
            runBlocking {
                fetcher.fetch(sender, cid, key, blob.size)
            }.shouldBeInstanceOf<AnonymousAttachmentFetcher.Outcome.Bytes>()
            store.order shouldBe listOf("local")
        }

        test("the fallback runs only for NOT_REACHABLE/CLOSED and only up to 131,066 bytes") {
            val store = MemoryStore()
            val client = HeldClient(store.order)
            val fetcher = AnonymousAttachmentFetcher(store, { client })
            val cid = rawCidOf("x".toByteArray())
            for (reason in AttachmentFetchFailure.entries) {
                store.remoteCalls.clear()
                client.answer = AttachmentFetchResult.Unavailable(reason)
                val outcome = runBlocking { fetcher.fetch(sender, cid, key, LookupLimits.MAX_CONTENT) }
                val expectFallback =
                    reason == AttachmentFetchFailure.NOT_REACHABLE || reason == AttachmentFetchFailure.CLOSED
                store.remoteCalls.size shouldBe (if (expectFallback) 1 else 0)
                outcome shouldBe
                    when (reason) {
                        AttachmentFetchFailure.NOT_READY -> AnonymousAttachmentFetcher.Outcome.NotReady
                        AttachmentFetchFailure.TIMEOUT -> AnonymousAttachmentFetcher.Outcome.Timeout
                        AttachmentFetchFailure.TOO_LARGE -> AnonymousAttachmentFetcher.Outcome.TooLarge
                        AttachmentFetchFailure.RATE_LIMITED -> AnonymousAttachmentFetcher.Outcome.Busy
                        else -> AnonymousAttachmentFetcher.Outcome.Unavailable
                    }
            }
            store.remoteCalls.clear()
            client.answer = AttachmentFetchResult.Unavailable(AttachmentFetchFailure.NOT_REACHABLE)
            runBlocking { fetcher.fetch(sender, cid, key, LookupLimits.MAX_CONTENT + 1) } shouldBe
                AnonymousAttachmentFetcher.Outcome.Unavailable
            store.remoteCalls.size shouldBe 0
            LookupLimits.MAX_CONTENT shouldBe 131_066
        }

        test("verified bytes are stored unserved: the second fetch is local") {
            val store = MemoryStore()
            val client = HeldClient(store.order)
            val fetcher = AnonymousAttachmentFetcher(store, { client })
            val blob = ByteArray(5_000) { 3 }
            val cid = rawCidOf(blob)
            client.answer = AttachmentFetchResult.Found(blob)
            runBlocking {
                fetcher.fetch(sender, cid, key, blob.size)
            }.shouldBeInstanceOf<AnonymousAttachmentFetcher.Outcome.Bytes>()
            store.unserved[cid] shouldBe blob
            store.local[cid] shouldBe null
            runBlocking {
                fetcher.fetch(sender, cid, key, blob.size)
            }.shouldBeInstanceOf<AnonymousAttachmentFetcher.Outcome.Bytes>()
            client.calls.get() shouldBe 1
        }

        test("no key, no client, above the maximum: no network") {
            val store = MemoryStore()
            val client = HeldClient(store.order)
            val cid = rawCidOf("y".toByteArray())
            runBlocking { AnonymousAttachmentFetcher(store, { client }).fetch(sender, cid, null, 10) } shouldBe
                AnonymousAttachmentFetcher.Outcome.Unavailable
            runBlocking { AnonymousAttachmentFetcher(store, { null }).fetch(sender, cid, key, 10) } shouldBe
                AnonymousAttachmentFetcher.Outcome.NotReady
            runBlocking {
                AnonymousAttachmentFetcher(store, { client }).fetch(
                    sender,
                    cid,
                    key,
                    AnonymousAttachmentLimits.MAX_BLOB_BYTES + 1,
                )
            } shouldBe AnonymousAttachmentFetcher.Outcome.TooLarge
            client.calls.get() shouldBe 0
            store.remoteCalls.size shouldBe 0
        }

        test("at most two fetches at once; a third is Busy; cancelling the coroutine cancels the future").config(
            timeout = 60.seconds,
        ) {
            val store = MemoryStore()
            val client = HeldClient(store.order)
            val fetcher = AnonymousAttachmentFetcher(store, { client })
            runBlocking(Dispatchers.Default) {
                val cidOne = rawCidOf(byteArrayOf(1))
                val cidTwo = rawCidOf(byteArrayOf(2))
                val one = launch { fetcher.fetch(sender, cidOne, key, 10) }
                val two = async { fetcher.fetch(sender, cidTwo, key, 10) }
                while (client.futures.size < 2) delay(10)
                fetcher.fetch(sender, rawCidOf(byteArrayOf(3)), key, 10) shouldBe
                    AnonymousAttachmentFetcher.Outcome.Busy
                one.cancelAndJoin()
                client.futuresByCid.getValue(cidOne).isCancelled shouldBe true
                // the slot is free again
                client.answer = AttachmentFetchResult.NotFound
                fetcher.fetch(sender, rawCidOf(byteArrayOf(4)), key, 10) shouldBe
                    AnonymousAttachmentFetcher.Outcome.Unavailable
                client.futuresByCid.getValue(cidTwo).complete(AttachmentFetchResult.NotFound)
                two.await() shouldBe AnonymousAttachmentFetcher.Outcome.Unavailable
            }
        }
    })
