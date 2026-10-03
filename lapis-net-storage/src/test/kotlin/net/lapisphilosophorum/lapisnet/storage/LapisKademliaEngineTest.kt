package net.lapisphilosophorum.lapisnet.storage

import io.ipfs.multihash.Multihash
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.libp2p.core.Stream
import io.libp2p.core.multiformats.Multiaddr
import io.libp2p.host.MemoryAddressBook
import org.peergos.blockstore.RamBlockstore
import org.peergos.protocol.dht.pb.Dht
import java.lang.reflect.Proxy
import java.util.concurrent.CompletableFuture

/**
 * Nabu's `getKClosestPeers` did `new ArrayList<>(addressBook.getAddrs(..).join())` and
 * jvm-libp2p's `MemoryAddressBook` returns `null` for a peer it has never heard of, so one routing
 * table entry without an address-book entry broke every FIND_NODE / GET_PROVIDERS / GET_VALUE answer
 * with an NPE (finding F5 of the V0.9.11 plan, "Stolperfalle 5").
 */
class LapisKademliaEngineTest :
    FunSpec({
        val limits = DhtLimits(maxAddressesPerPeer = 4, maxAddressesPerIp = 4)

        fun engine(): Pair<LapisKademliaEngine, MemoryAddressBook> {
            val book = MemoryAddressBook()
            val engine =
                LapisKademliaEngine(
                    Multihash.deserialize(realPeerId().bytes),
                    BoundedProviderStore(limits),
                    BoundedRecordStore(8),
                    RamBlockstore(),
                    limits,
                )
            engine.setAddressBook(book)
            return engine to book
        }

        test("getKClosestPeers skips a routing-table peer that has no address-book entry instead of throwing") {
            val (engine, book) = engine()
            val known = realPeerId()
            val unknown = realPeerId()
            engine.addOutgoingConnection(known)
            engine.addOutgoingConnection(unknown)
            book.setAddrs(known, 0, Multiaddr("/ip4/1.2.3.4/tcp/1")).join()

            val closest = engine.getKClosestPeers(ByteArray(32) { 1 }, 20)

            closest.map { it.peerId.toBase58() } shouldBe listOf(known.toBase58())
        }

        test("getKClosestPeers caps each peer's addresses and drops DNS-form ones") {
            val (engine, book) = engine()
            val peer = realPeerId()
            engine.addOutgoingConnection(peer)
            val many = (1..50).map { Multiaddr("/ip4/1.2.3.4/tcp/$it") } + Multiaddr("/dns4/example.org/tcp/1")
            book.setAddrs(peer, 0, *many.toTypedArray()).join()

            val closest = engine.getKClosestPeers(ByteArray(32) { 1 }, 20)

            closest shouldHaveSize 1
            closest.single().addresses shouldHaveSize limits.maxAddressesPerPeer
            closest.single().addresses.none { it.toString().contains("dns") } shouldBe true
        }

        test("getKClosestPeers without an address book is empty, not an NPE") {
            val engine =
                LapisKademliaEngine(
                    Multihash.deserialize(realPeerId().bytes),
                    BoundedProviderStore(limits),
                    BoundedRecordStore(8),
                    RamBlockstore(),
                    limits,
                )
            engine.getKClosestPeers(ByteArray(32), 20) shouldHaveSize 0
        }

        fun countingStream(closed: MutableList<String>): Stream =
            Proxy.newProxyInstance(Stream::class.java.classLoader, arrayOf(Stream::class.java)) { _, method, _ ->
                closed += method.name
                if (method.returnType ==
                    CompletableFuture::class.java
                ) {
                    CompletableFuture.completedFuture(Unit)
                } else {
                    null
                }
            } as Stream

        val getValue = Dht.Message.MessageType.GET_VALUE

        test("a request that makes the base class throw an Exception closes the stream and is counted") {
            val (engine, _) = engine()
            val calls = mutableListOf<String>()
            engine.guarded(getValue, countingStream(calls)) { throw IllegalStateException("boom") } shouldBe false
            calls shouldBe listOf("close")
            engine.failedInboundRequests shouldBe 1
        }

        test("a StackOverflowError from the base class is the request's failure: stream closed, counted, no throw") {
            val (engine, _) = engine()
            val calls = mutableListOf<String>()
            engine.guarded(Dht.Message.MessageType.PUT_VALUE, countingStream(calls)) {
                throw StackOverflowError()
            } shouldBe false
            calls shouldBe listOf("close")
            engine.failedInboundRequests shouldBe 1
        }

        test("a real unbounded recursion is survived the same way") {
            val (engine, _) = engine()

            fun recurse(depth: Int): Int = 1 + recurse(depth + 1)
            val calls = mutableListOf<String>()
            engine.guarded(getValue, countingStream(calls)) { recurse(0) } shouldBe false
            engine.failedInboundRequests shouldBe 1
        }

        test("an OutOfMemoryError is not swallowed") {
            val (engine, _) = engine()
            val calls = mutableListOf<String>()
            shouldThrow<OutOfMemoryError> {
                engine.guarded(getValue, countingStream(calls)) { throw OutOfMemoryError() }
            }
            calls shouldBe emptyList()
        }

        test("a request that completes normally leaves the stream alone") {
            val (engine, _) = engine()
            val calls = mutableListOf<String>()
            engine.guarded(getValue, countingStream(calls)) { } shouldBe true
            calls shouldBe emptyList()
            engine.failedInboundRequests shouldBe 0
        }
    })
