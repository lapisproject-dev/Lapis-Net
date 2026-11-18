package net.lapisphilosophorum.lapisnet.browser

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import net.lapisphilosophorum.lapisnet.storage.RemoteBlockState
import net.lapisphilosophorum.lapisnet.storage.RemoteBlockView
import net.lapisphilosophorum.lapisnet.storage.RemoteContentSource
import net.lapisphilosophorum.lapisnet.storage.StorageNetworkMode
import java.nio.file.Files
import java.security.MessageDigest
import java.time.Duration
import java.util.concurrent.atomic.AtomicInteger

private fun cidOf(bytes: ByteArray): Cid =
    Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, MessageDigest.getInstance("SHA-256").digest(bytes))

private val author = Secp256k1KeyPair.generate().publicKey

private fun entry(
    cid: Cid,
    publishedAt: Long,
) = TimelineEntry(
    cid = cid,
    author = author,
    publishedAtEpochSeconds = publishedAt,
    credibility = Credibility(CredibilityLevel.NO_PATH, 0),
    ltrWeightMsat = 0.0,
    ltrRecordCount = 0,
    karmaScore = 0.0,
    karmaVoteCount = 0,
    filteredOut = false,
)

/** A remote side that schedules a lookup at most once per CID and remembers it as running. */
private class FakeRemote {
    val local = HashMap<Cid, ByteArray>()
    val states = HashMap<Cid, RemoteBlockState>()
    val scheduledOrder = ArrayList<Cid>()
    val calls = AtomicInteger()

    fun view(
        cid: Cid,
        schedule: Boolean,
    ): NabuStorage.LocalOrRemote {
        calls.incrementAndGet()
        local[cid]?.let { return NabuStorage.LocalOrRemote(it, RemoteBlockState.CACHED, newlyScheduled = false) }
        states[cid]?.let { return NabuStorage.LocalOrRemote(null, it, newlyScheduled = false) }
        if (!schedule) return NabuStorage.LocalOrRemote(null, RemoteBlockState.NONE, newlyScheduled = false)
        states[cid] = RemoteBlockState.FETCHING
        scheduledOrder += cid
        return NabuStorage.LocalOrRemote(null, RemoteBlockState.FETCHING, newlyScheduled = true)
    }
}

/** A source that counts every call that could block or schedule outside [blockState]. */
private class CountingSource : RemoteContentSource {
    val blocking = AtomicInteger()
    val cachedCalls = AtomicInteger()
    val states = AtomicInteger()

    override fun fetchBlock(
        cid: Cid,
        maxBytes: Int,
        timeout: Duration,
    ): ByteArray? {
        blocking.incrementAndGet()
        return null
    }

    override fun resolveIpnsRecord(
        name: ByteArray,
        timeout: Duration,
    ): ByteArray? {
        blocking.incrementAndGet()
        return null
    }

    override fun blockIfCached(cid: Cid): ByteArray? {
        cachedCalls.incrementAndGet()
        return null
    }

    override fun blockState(
        cid: Cid,
        schedule: Boolean,
    ): RemoteBlockView {
        states.incrementAndGet()
        return if (schedule) {
            RemoteBlockView(RemoteBlockState.FETCHING, null, newlyScheduled = true)
        } else {
            RemoteBlockView.NONE
        }
    }
}

/** Wave V0.10.0-J3: the timeline bodies in both modes. */
class TimelineBodyResolverTest :
    FunSpec({
        test("mode on: at most eight new lookups per request, newest first; the next request starts the next eight") {
            val remote = FakeRemote()
            val gets = AtomicInteger()
            val resolver =
                TimelineBodyResolver(true, { gets.incrementAndGet().let { null } }, remote::view)
            // twenty missing bodies, published at 1..20 (shuffled input order)
            val entries = (1..20).map { i -> entry(cidOf("post $i".toByteArray()), i.toLong()) }.shuffled()
            val first = resolver.resolve(entries)
            remote.scheduledOrder.size shouldBe 8
            val newest = entries.sortedByDescending { it.publishedAtEpochSeconds }.map { it.cid }
            remote.scheduledOrder shouldBe newest.take(8)
            first.size shouldBe 20
            newest.take(8).forEach { first.getValue(it).contentState shouldBe CONTENT_STATE_FETCHING }
            newest.drop(8).forEach { first.getValue(it).contentState shouldBe CONTENT_STATE_UNAVAILABLE }
            first.values.all { it.text == CONTENT_UNAVAILABLE_MARKER } shouldBe true
            resolver.resolve(entries)
            remote.scheduledOrder shouldBe newest.take(16)
            // never the plain (possibly scheduling) storage lookup in this mode
            gets.get() shouldBe 0
        }

        test("mode on: the four content states; a local body is returned as text") {
            val remote = FakeRemote()
            val here = "held here".toByteArray()
            val cLocal = cidOf(here)
            val cMissing = cidOf("missing".toByteArray())
            val cGone = cidOf("gone".toByteArray())
            val cFetching = cidOf("fetching".toByteArray())
            remote.local[cLocal] = here
            remote.states[cMissing] = RemoteBlockState.NOT_FOUND
            remote.states[cGone] = RemoteBlockState.UNAVAILABLE
            val resolver = TimelineBodyResolver(true, { error("never") }, remote::view)
            val out =
                resolver.resolve(listOf(entry(cLocal, 4), entry(cMissing, 3), entry(cGone, 2), entry(cFetching, 1)))
            out.getValue(cLocal) shouldBe TimelineBodyResolver.Body("held here", CONTENT_STATE_LOCAL)
            out.getValue(cMissing) shouldBe
                TimelineBodyResolver.Body(CONTENT_UNAVAILABLE_MARKER, CONTENT_STATE_NOT_FOUND)
            out.getValue(cGone) shouldBe
                TimelineBodyResolver.Body(CONTENT_UNAVAILABLE_MARKER, CONTENT_STATE_UNAVAILABLE)
            out.getValue(cFetching) shouldBe
                TimelineBodyResolver.Body(CONTENT_UNAVAILABLE_MARKER, CONTENT_STATE_FETCHING)
        }

        test("mode on: a storage fault degrades that entry to unavailable") {
            val boom = cidOf("boom".toByteArray())
            val ok = cidOf("ok".toByteArray())
            val resolver =
                TimelineBodyResolver(true, { null }, { cid, _ ->
                    if (cid == boom) error("disk") else NabuStorage.LocalOrRemote(null, RemoteBlockState.NONE, false)
                })
            val out = resolver.resolve(listOf(entry(boom, 2), entry(ok, 1)))
            out.getValue(boom).contentState shouldBe CONTENT_STATE_UNAVAILABLE
            out.getValue(ok).contentState shouldBe CONTENT_STATE_UNAVAILABLE
        }

        test("mode off: exactly the earlier behaviour through storage.get; the remote view is never asked") {
            val remote = FakeRemote()
            val here = "plain".toByteArray()
            val cHere = cidOf(here)
            val cMissing = cidOf("absent".toByteArray())
            val cFault = cidOf("fault".toByteArray())
            val resolver =
                TimelineBodyResolver(false, { cid ->
                    when (cid) {
                        cHere -> here
                        cFault -> error("local fault with /some/path")
                        else -> null
                    }
                }, remote::view)
            val out = resolver.resolve(listOf(entry(cHere, 1), entry(cMissing, 2), entry(cFault, 3)))
            out.getValue(cHere) shouldBe TimelineBodyResolver.Body("plain", CONTENT_STATE_LOCAL)
            out.getValue(cMissing) shouldBe
                TimelineBodyResolver.Body(CONTENT_UNAVAILABLE_MARKER, CONTENT_STATE_UNAVAILABLE)
            out.getValue(cFault) shouldBe
                TimelineBodyResolver.Body(CONTENT_UNAVAILABLE_MARKER, CONTENT_STATE_UNAVAILABLE)
            remote.calls.get() shouldBe 0
        }

        test("mode on with a real LOCAL_ONLY storage: no blocking fetch, no scheduling get, local bodies served") {
            val node = LapisNode.create(DualKeyIdentity.generate(), mdnsEnabled = false).also { it.start() }
            val source = CountingSource()
            try {
                val storage =
                    NabuStorage.attach(
                        node,
                        Files.createTempDirectory("j3-timeline"),
                        networkMode = StorageNetworkMode.LOCAL_ONLY,
                        remote = source,
                    )
                val held = storage.putUnserved("held".toByteArray())
                val entries =
                    listOf(entry(held, 100)) + (1..12).map { i -> entry(cidOf("far $i".toByteArray()), i.toLong()) }
                val out = TimelineBodyResolver(storage, anonymity = true).resolve(entries)
                out.getValue(held) shouldBe TimelineBodyResolver.Body("held", CONTENT_STATE_LOCAL)
                out.values.count { it.contentState == CONTENT_STATE_FETCHING } shouldBe 8
                source.blocking.get() shouldBe 0
                source.cachedCalls.get() shouldBe 0
                source.states.get() shouldBe 12
            } finally {
                node.stop()
            }
        }
    })
