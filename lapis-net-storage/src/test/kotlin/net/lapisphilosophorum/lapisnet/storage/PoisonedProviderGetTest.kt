package net.lapisphilosophorum.lapisnet.storage

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.ints.shouldBeLessThanOrEqual
import io.kotest.matchers.longs.shouldBeLessThan
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerId
import io.libp2p.core.multiformats.Multiaddr
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import org.peergos.protocol.dht.pb.Dht
import java.time.Duration
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.time.Duration.Companion.seconds

/**
 * V0.9.11 / finding D: `ADD_PROVIDER` is unauthenticated apart from "the provider is the sender", so
 * any peer can fill this node's provider store with records whose addresses point wherever it likes -
 * and `get()` without an explicit peer turns those records into dial targets (reachable from the
 * browser and mail APIs, which call `storage.get(cid)` with no peers). Nabu's store keeps every record
 * with every address; its `get()` path dialled them synchronously on the caller's thread.
 *
 * The poisoning peers here connect, announce, and disconnect - leaving only the record - and point at
 * a TCP listener that accepts and stalls, the worst case for a dial.
 */
class PoisonedProviderGetTest :
    FunSpec({
        val cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { 9 })

        /** Connects a fresh peer to [victim], announces itself as provider of [cid] with [addresses], disconnects. */
        fun poison(
            victim: LapisNode,
            victimStorage: NabuStorage,
            addresses: List<ByteArray>,
            messages: Int = 1,
        ): PeerId {
            val attacker = ScriptedDhtPeer.start()
            val message =
                Dht.Message
                    .newBuilder()
                    .setType(Dht.Message.MessageType.ADD_PROVIDER)
                    .keyBytes(cid.bareMultihash().toBytes())
                    .addProviderPeers(peerProto(attacker.peerId, addresses))
                    .build()
            repeat(messages) { attacker.send(victim, message) }
            awaitCondition {
                victimStorage.localProviderRecords(cid).any { it.id.toByteArray().contentEquals(attacker.peerId.bytes) }
            } shouldBe true
            attacker.stop()
            return attacker.peerId
        }

        fun poisonAddresses(
            listener: CountingListener,
            count: Int,
        ): List<ByteArray> = (0 until count).map { Multiaddr("/ip4/127.0.0.1/tcp/${listener.port + it}").serialize() }

        test(
            "80 ADD_PROVIDERs of ~1000 addresses leave one bounded record, and get() still returns within its timeout",
        ).config(
            timeout = 60.seconds,
        ) {
            val victim = newNode()
            CountingListener().use { silent ->
                try {
                    val storage = storageOn(victim)
                    val poisoner = poison(victim, storage, poisonAddresses(silent, 1000), messages = 80)

                    val records = storage.localProviderRecords(cid)
                    records.size shouldBe 1
                    records.single().addrsCount shouldBeLessThanOrEqual DhtLimits().maxAddressesPerPeer

                    val start = System.nanoTime()
                    storage.get(cid, timeout = Duration.ofSeconds(2)) shouldBe null
                    TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) shouldBeLessThan 2_500

                    victim.host.addressBook
                        .getAddrs(poisoner)
                        .join()
                        .orEmpty()
                        .size shouldBeLessThanOrEqual
                        DhtLimits().maxAddressesPerIp
                } finally {
                    victim.stop()
                }
            }
        }

        test("twelve poisoning identities leave at most maxProvidersPerKey records").config(timeout = 90.seconds) {
            val victim = newNode()
            CountingListener().use { silent ->
                try {
                    val storage = storageOn(victim)
                    repeat(12) { poison(victim, storage, poisonAddresses(silent, 3)) }
                    storage.localProviderRecords(cid).size shouldBe DhtLimits().maxProvidersPerKey
                } finally {
                    victim.stop()
                }
            }
        }

        test("30 repeated get() calls do not grow the poisoner's address-book entry and each returns promptly").config(
            timeout = 60.seconds,
        ) {
            val victim = newNode()
            CountingListener().use { silent ->
                try {
                    val storage = storageOn(victim)
                    val poisoner = poison(victim, storage, poisonAddresses(silent, 50))
                    repeat(30) {
                        val start = System.nanoTime()
                        storage.get(cid, timeout = Duration.ofMillis(300)) shouldBe null
                        TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) shouldBeLessThan 1_500
                        victim.host.addressBook
                            .getAddrs(poisoner)
                            .join()
                            .orEmpty()
                            .size shouldBeLessThanOrEqual
                            DhtLimits().maxAddressesPerIp
                    }
                } finally {
                    victim.stop()
                }
            }
        }

        test(
            "an honest provider among seven poisoned ones is still found and fetched from",
        ).config(timeout = 90.seconds) {
            val victim = newNode()
            val honest = newNode()
            CountingListener().use { silent ->
                try {
                    val limits = DhtLimits(fetchConnectTimeout = Duration.ofSeconds(1))
                    val storage = storageOn(victim, limits)
                    val honestStorage = storageOn(honest)
                    val payload = "the real block, announced by the honest provider".toByteArray()
                    val realCid = honestStorage.put(payload)

                    // seven poisoned records for the REAL cid, inserted first
                    repeat(7) {
                        val attacker = ScriptedDhtPeer.start()
                        val message =
                            Dht.Message
                                .newBuilder()
                                .setType(Dht.Message.MessageType.ADD_PROVIDER)
                                .keyBytes(realCid.bareMultihash().toBytes())
                                .addProviderPeers(peerProto(attacker.peerId, poisonAddresses(silent, 3)))
                                .build()
                        attacker.send(victim, message)
                        awaitCondition { storage.localProviderRecords(realCid).size >= it + 1 } shouldBe true
                        attacker.stop()
                    }
                    // the honest provider announces last (its record is the 8th and newest)
                    honestStorage.connectToDhtPeer(addressOf(victim)) shouldBe true
                    honestStorage.provide(realCid, Duration.ofSeconds(5)) shouldBe 1
                    awaitCondition { storage.localProviderRecords(realCid).size == 8 } shouldBe true

                    storage.get(realCid, timeout = Duration.ofSeconds(15)) shouldBe payload
                } finally {
                    victim.stop()
                    honest.stop()
                }
            }
        }

        test(
            "when every fetch slot and the queue behind it are busy, get() answers null at once instead of waiting",
        ).config(
            timeout = 60.seconds,
        ) {
            val victim = newNode()
            CountingListener().use { silent ->
                val pool = Executors.newFixedThreadPool(10)
                try {
                    val storage =
                        storageOn(
                            victim,
                            DhtLimits(
                                maxConcurrentFetches = 1,
                                maxProvidersPerKey = 1,
                                fetchConnectTimeout = Duration.ofSeconds(3),
                            ),
                        )
                    val calls =
                        (0 until 10).map { i ->
                            val peer = realPeerId()
                            storage.registerPeerAddress(
                                Multiaddr("/ip4/127.0.0.1/tcp/${silent.port}/p2p/${peer.toBase58()}"),
                            )
                            val wanted =
                                Cid.buildCidV1(
                                    Cid.Codec.Raw,
                                    Multihash.Type.sha2_256,
                                    ByteArray(32) { (100 + i).toByte() },
                                )
                            pool.submit<Long> {
                                val start = System.nanoTime()
                                storage.get(wanted, setOf(peer), Duration.ofSeconds(3)) shouldBe null
                                TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start)
                            }
                        }
                    val elapsed = calls.map { it.get(15, TimeUnit.SECONDS) }
                    // one call holds the single slot, one waits in the queue, the other eight are turned away at once
                    (elapsed.count { it < 800 } >= 6) shouldBe true
                } finally {
                    pool.shutdownNow()
                    victim.stop()
                }
            }
        }
    })
