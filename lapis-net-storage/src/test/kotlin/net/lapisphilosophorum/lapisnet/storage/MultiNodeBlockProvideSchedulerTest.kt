package net.lapisphilosophorum.lapisnet.storage

import io.ipfs.cid.Cid
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.longs.shouldBeLessThan
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import java.nio.file.Files
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

private val FAST_PROVIDE =
    BlockProvideConfig(
        reprovideInterval = 2.seconds,
        reprovideJitterFraction = 0.0,
        firstProvideDelayMax = Duration.ZERO,
        maxProvidesPerCycle = 8,
        cycleInterval = 200.milliseconds,
        cycleJitter = Duration.ZERO,
        initialDelay = Duration.ZERO,
        perProvideTimeout = 5.seconds,
        cycleBudget = 20.seconds,
        failureRetryMin = 500.milliseconds,
    )

private fun awaitTrue(
    timeoutMillis: Long = 30_000,
    condition: () -> Boolean,
): Boolean {
    val deadline = System.nanoTime() + timeoutMillis * 1_000_000
    while (System.nanoTime() < deadline) {
        if (runCatching(condition).getOrDefault(false)) return true
        Thread.sleep(100)
    }
    return runCatching(condition).getOrDefault(false)
}

/**
 * A hub H, a holder, a consumer and two further nodes. Every node and H have each other in their DHT routing tables;
 * the holder additionally knows H and the two further nodes directly. The consumer knows ONLY H.
 *
 * Why the holder is linked directly: on loopback the holder's walk did not get past H (observed while writing this
 * test: every provide reported `sent ADD_PROVIDER to 1 of 1`), so a node known only to H would never receive the
 * record. That is a property of the walk on loopback, not of the scheduler; it is reported, not changed, in wave Q20.
 */
private class Rig : AutoCloseable {
    val nodes = mutableListOf<LapisNode>()
    val hubNode = node()
    val hub = NabuStorage.attach(hubNode, Files.createTempDirectory("q20-hub"))
    val holderNode = node()
    val holder = attachToHub(holderNode, "holder")
    val consumerNode = node()
    val consumer = attachToHub(consumerNode, "consumer")
    val otherNodes = (0 until 2).map { node() }
    val others = otherNodes.mapIndexed { i, n -> attachToHub(n, "other-$i") }

    init {
        for (n in otherNodes) linkHolderTo(n)
    }

    fun linkHolderTo(n: LapisNode) {
        holder.connectToDhtPeer(n.listenAddresses().first().withP2P(n.peerId)) shouldBe true
    }

    fun node(): LapisNode =
        LapisNode.create(DualKeyIdentity.generate(), mdnsEnabled = false).also {
            it.start(bootstrapPeers = emptyList())
            nodes += it
        }

    fun attachToHub(
        n: LapisNode,
        name: String,
    ): NabuStorage {
        val storage = NabuStorage.attach(n, Files.createTempDirectory("q20-$name"))
        storage.connectToDhtPeer(hubNode.listenAddresses().first().withP2P(hubNode.peerId)) shouldBe true
        // connectToDhtPeer fills only the CALLER's routing table; the hub must know the node too, or its FIND_NODE
        // answers would never name it
        hub.connectToDhtPeer(n.listenAddresses().first().withP2P(n.peerId)) shouldBe true
        return storage
    }

    fun peersHolding(cid: Cid): List<NabuStorage> =
        (listOf(hub, consumer) + others).filter { holderNode.peerId in it.heldProviderRecords(cid) }

    override fun close() {
        nodes.forEach { runCatching { it.stop() } }
    }
}

private fun cycleUntil(
    scheduler: BlockProvideScheduler,
    timeoutMillis: Long = 30_000,
    condition: () -> Boolean,
): Boolean =
    awaitTrue(timeoutMillis) {
        scheduler.runCycle()
        condition()
    }

/**
 * Wave Q20, over real loopback nodes: [BlockProvideScheduler] with a real [NabuStorage] target sends real
 * `ADD_PROVIDER`s. Checked on the receiving peers' own provider stores ([NabuStorage.heldProviderRecords]): on
 * loopback Nabu's responder names itself without addresses for a block it holds, so a `findProviders` result alone
 * would not prove an announcement.
 */
class MultiNodeBlockProvideSchedulerTest :
    FunSpec({
        test("a tracked block is announced; a consumer that knows only the hub finds the holder and fetches it").config(
            timeout = 120.seconds,
        ) {
            Rig().use { rig ->
                val scheduler = BlockProvideScheduler(rig.holder.asProvideTarget(), FAST_PROVIDE)
                val payload = "Q20 provided post body".toByteArray()
                val cid = rig.holder.put(payload)
                scheduler.track(cid) shouldBe true
                cycleUntil(scheduler) {
                    rig.hub.heldProviderRecords(cid).isNotEmpty() &&
                        rig.others.all { rig.holderNode.peerId in it.heldProviderRecords(cid) }
                } shouldBe true
                rig.hub.heldProviderRecords(cid) shouldBe setOf(rig.holderNode.peerId)
                // the consumer has never talked to the holder: the hub's provider record (with addresses) leads it there
                rig.consumer.findProviders(cid) shouldContain rig.holderNode.peerId
                val fetched = rig.consumer.get(cid)
                fetched shouldNotBe null
                fetched!!.toList() shouldBe payload.toList()
                scheduler.stats().announced.let { (it >= 1) shouldBe true }
            }
        }

        test("without tracking nothing is announced: no peer holds a provider record").config(timeout = 120.seconds) {
            Rig().use { rig ->
                val scheduler = BlockProvideScheduler(rig.holder.asProvideTarget(), FAST_PROVIDE)
                val cid = rig.holder.put("held, never tracked".toByteArray())
                repeat(10) {
                    scheduler.runCycle()
                    Thread.sleep(100)
                }
                rig.peersHolding(cid) shouldBe emptyList()
            }
        }

        test("maxTracked = 3 with 5 blocks: only the 3 newest are announced").config(timeout = 120.seconds) {
            Rig().use { rig ->
                val scheduler = BlockProvideScheduler(rig.holder.asProvideTarget(), FAST_PROVIDE.copy(maxTracked = 3))
                val cids = (0 until 5).map { rig.holder.put("capped body $it".toByteArray()) }
                cids.forEach { scheduler.track(it) }
                cycleUntil(scheduler) { cids.drop(2).all { rig.hub.heldProviderRecords(it).isNotEmpty() } } shouldBe
                    true
                // a few more cycles: the evicted ones must still not show up anywhere
                repeat(5) {
                    scheduler.runCycle()
                    Thread.sleep(100)
                }
                cids.take(2).forEach { rig.peersHolding(it) shouldBe emptyList() }
            }
        }

        test("an unserved (private) block is never announced, even when tracked").config(timeout = 120.seconds) {
            Rig().use { rig ->
                val scheduler = BlockProvideScheduler(rig.holder.asProvideTarget(), FAST_PROVIDE)
                val cid = rig.holder.putUnserved("received over an anonymous path".toByteArray())
                scheduler.track(cid)
                repeat(5) {
                    scheduler.runCycle()
                    Thread.sleep(100)
                }
                scheduler.isTracked(cid) shouldBe false
                scheduler.stats().notServedDropped shouldBe 1
                scheduler.stats().attempted shouldBe 0
                rig.peersHolding(cid) shouldBe emptyList()
            }
        }

        test("re-provide: a peer that joins with an empty store gets the record after the re-provide interval").config(
            timeout = 120.seconds,
        ) {
            Rig().use { rig ->
                val scheduler = BlockProvideScheduler(rig.holder.asProvideTarget(), FAST_PROVIDE)
                val cid = rig.holder.put("re-provided body".toByteArray())
                scheduler.track(cid)
                cycleUntil(scheduler) { rig.hub.heldProviderRecords(cid).isNotEmpty() } shouldBe true
                // a fresh node (empty provider store, as after a restart) joins through the hub
                val freshNode = rig.node()
                val fresh = rig.attachToHub(freshNode, "fresh")
                rig.linkHolderTo(freshNode)
                fresh.heldProviderRecords(cid) shouldBe emptySet()
                cycleUntil(scheduler) { rig.holderNode.peerId in fresh.heldProviderRecords(cid) } shouldBe true
                fresh.findProviders(cid) shouldContain rig.holderNode.peerId
            }
        }

        test("a stopped storage ends the cycle promptly with STORAGE_STOPPED").config(timeout = 120.seconds) {
            Rig().use { rig ->
                val scheduler = BlockProvideScheduler(rig.holder.asProvideTarget(), FAST_PROVIDE)
                repeat(4) { scheduler.track(rig.holder.put("stop body $it".toByteArray())) }
                rig.holder.stop()
                val start = System.nanoTime()
                scheduler.runCycle().endedBy shouldBe BlockProvideScheduler.EndReason.STORAGE_STOPPED
                (System.nanoTime() - start) shouldBeLessThan 5_000_000_000L
                scheduler.stats().attempted shouldBe 0
            }
        }
    })
