@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.dmonion.attachment

import io.ipfs.cid.Cid
import io.kotest.assertions.withClue
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import net.lapisphilosophorum.lapisnet.directory.AnonymousCapability
import net.lapisphilosophorum.lapisnet.directory.DirectoryReachability
import net.lapisphilosophorum.lapisnet.dmonion.DmOnionNode
import net.lapisphilosophorum.lapisnet.dmonion.FrameChannel
import net.lapisphilosophorum.lapisnet.dmonion.RelayHost
import net.lapisphilosophorum.lapisnet.dmonion.SyntheticLocator
import net.lapisphilosophorum.lapisnet.dmonion.awaitCondition
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptor
import net.lapisphilosophorum.lapisnet.onionwire.OnionServiceApp
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.time.Duration.Companion.seconds

/** Counts the answer messages that reach the fetching side (one stream message is one relay cell on the circuit). */
private class CountingPort(
    private val delegate: OnionAttachmentRuntimePort,
) : OnionAttachmentRuntimePort by delegate {
    val lastCount = AtomicInteger()

    override fun connect(
        descriptor: OnionServiceDescriptor,
        timeout: Duration,
    ): CompletableFuture<FrameChannel> =
        delegate.connect(descriptor, timeout).thenApply { inner ->
            lastCount.set(0)
            object : FrameChannel by inner {
                override fun onReceive(callback: (ByteArray) -> Unit) =
                    inner.onReceive { m ->
                        lastCount.incrementAndGet()
                        callback(m)
                    }
            }
        }
}

/**
 * Real nodes on loopback, the same rig as the DM-over-circuits test: six relays in a full mesh, A and B in anonymity mode
 * (connected only to relays). A serves attachment blobs it "sent" (a map standing in for the browser's outbound source;
 * the browser wiring is covered by the API tests) over its onion service; B fetches them through a rendezvous circuit.
 * Network diversity holds only with the synthetic locator, NOT over real networks. Verified on loopback only.
 */
class MultiNodeAnonymousAttachmentTest :
    FunSpec({
        val relays = List(6) { RelayHost() }
        for (i in relays.indices) for (j in i + 1 until relays.size) relays[i].connectTo(relays[j])
        val locator = SyntheticLocator()
        relays.forEachIndexed { i, r -> locator.put(r.key, 20 + i, i) }
        val caps = setOf(AnonymousCapability.DM, AnonymousCapability.MAIL)
        val a = DmOnionNode(relays, locator, capabilities = caps)
        val b = DmOnionNode(relays, locator, capabilities = caps)
        val key = ByteArray(32) { 42 }
        val offered = ConcurrentHashMap<Cid, ByteArray>()
        var server: OnionAttachmentServer? = null
        a.onStarted = { node ->
            val s =
                OnionAttachmentServer(
                    OutboundAttachmentSource { cid ->
                        offered[cid]?.let { blob -> OutboundAttachment(key, blob.size) { node.storage.getLocal(cid) } }
                    },
                )
            server = s
            node.runtime.serviceRouter().register(OnionServiceApp.ATTACHMENT, s::handle)
        }
        a.onStopping = { server?.close() }
        lateinit var port: CountingPort
        lateinit var client: OnionAttachmentClient

        fun offer(blob: ByteArray): Cid {
            val cid = a.storage.putUnserved(blob)
            offered[cid] = blob
            return cid
        }

        fun fetch(
            sender: Secp256k1PublicKey,
            cid: Cid,
            withKey: ByteArray = key,
        ): AttachmentFetchResult =
            client.fetch(sender, cid, withKey, AnonymousAttachmentLimits.MAX_BLOB_BYTES).get(240, TimeUnit.SECONDS)

        afterSpec {
            runCatching { client.close() }
            runCatching { a.stop() }
            runCatching { b.stop() }
            relays.forEach { runCatching { it.close() } }
        }

        test("A and B start in anonymity mode and B sees A behind its onion service").config(timeout = 600.seconds) {
            a.start()
            b.start()
            a.awaitPublished() shouldBe true
            b.awaitPublished() shouldBe true
            val converged =
                awaitCondition(Duration.ofSeconds(360)) {
                    b.runtime.resolveIdentity(a.key) is DirectoryReachability.Hidden
                }
            withClue(b.diagnosticsLine()) { converged shouldBe true }
            port = CountingPort(OnionAttachmentRuntimePortImpl(b.runtime))
            client = OnionAttachmentClient(port)
        }

        test("B fetches a 300 KB blob (four-chunk class) from A's service and gets exactly the bytes")
            .config(timeout = 300.seconds) {
                val blob = ByteArray(300_000) { (it * 31 % 256).toByte() }
                val result = fetch(a.key, offer(blob))
                withClue(b.diagnosticsLine()) {
                    result.shouldBeInstanceOf<AttachmentFetchResult.Found>().bytes shouldBe blob
                }
                b.storage.getLocal(rawCid(blob)) shouldBe null // the client stores nothing; the browser does
            }

        test("a 262,125-byte and a 300,100-byte blob cost the same number of cells (both the 512 KiB class)")
            .config(timeout = 300.seconds) {
                AttachmentTransferClass.forLength(262_125) shouldBe AttachmentTransferClass.forLength(300_100)
                fetch(a.key, offer(ByteArray(262_125) { 1 })).shouldBeInstanceOf<AttachmentFetchResult.Found>()
                val small = port.lastCount.get()
                fetch(a.key, offer(ByteArray(300_100) { 2 })).shouldBeInstanceOf<AttachmentFetchResult.Found>()
                port.lastCount.get() shouldBe small
                (small > 0) shouldBe true
            }

        test("exactly MAX_BLOB_BYTES arrives; a wrong token is NOT_FOUND").config(timeout = 400.seconds) {
            val blob = ByteArray(AnonymousAttachmentLimits.MAX_BLOB_BYTES) { (it % 249).toByte() }
            val cid = offer(blob)
            val result = fetch(a.key, cid)
            withClue(b.diagnosticsLine()) {
                result.shouldBeInstanceOf<AttachmentFetchResult.Found>().bytes shouldBe blob
            }
            fetch(a.key, cid, withKey = ByteArray(32) { 7 }) shouldBe AttachmentFetchResult.NotFound
        }

        test("A offline: NOT_REACHABLE, nothing stays open").config(timeout = 400.seconds) {
            val cid = offer(ByteArray(1_000) { 3 })
            a.stop()
            val result = fetch(a.key, cid)
            result shouldBe AttachmentFetchResult.Unavailable(AttachmentFetchFailure.NOT_REACHABLE)
            client.inFlight() shouldBe 0
        }
    })
