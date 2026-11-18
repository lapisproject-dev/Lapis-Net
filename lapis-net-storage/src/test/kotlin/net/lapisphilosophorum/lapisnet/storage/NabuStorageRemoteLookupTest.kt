package net.lapisphilosophorum.lapisnet.storage

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import java.nio.file.Files
import java.security.MessageDigest
import java.time.Duration
import java.time.Instant
import java.util.concurrent.atomic.AtomicInteger

private fun rawCid(bytes: ByteArray): Cid =
    Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, MessageDigest.getInstance("SHA-256").digest(bytes))

/** A source that returns fixed bytes for every block and counts the blocking fetches. */
private class FixedSource(
    private val answer: (Cid) -> ByteArray?,
) : RemoteContentSource {
    val fetches = AtomicInteger()

    override fun fetchBlock(
        cid: Cid,
        maxBytes: Int,
        timeout: Duration,
    ): ByteArray? {
        fetches.incrementAndGet()
        return answer(cid)
    }

    override fun resolveIpnsRecord(
        name: ByteArray,
        timeout: Duration,
    ): ByteArray? = null
}

/** Wave V0.10.0-J2: the blocking circuit lookup of a LOCAL_ONLY storage, the deferred source and the verifier. */
class NabuStorageRemoteLookupTest :
    FunSpec({
        fun localOnly(remote: RemoteContentSource?): Pair<LapisNode, NabuStorage> {
            val node = LapisNode.create(DualKeyIdentity.generate(), mdnsEnabled = false).also { it.start() }
            val storage =
                NabuStorage.attach(
                    node,
                    Files.createTempDirectory("j2-local-only"),
                    networkMode = StorageNetworkMode.LOCAL_ONLY,
                    remote = remote,
                )
            return node to storage
        }

        test("getThroughRemote: a matching block is returned and stored unserved; a second call stays local") {
            val bytes = "fetched through a circuit".toByteArray()
            val cid = rawCid(bytes)
            val source = FixedSource { if (it == cid) bytes else null }
            val (node, storage) = localOnly(source)
            try {
                storage.getThroughRemote(cid, Duration.ofSeconds(5)) shouldBe bytes
                storage.getLocal(cid) shouldBe bytes
                storage.getThroughRemote(cid, Duration.ofSeconds(5)) shouldBe bytes
                source.fetches.get() shouldBe 1
            } finally {
                node.stop()
            }
        }

        test("getThroughRemote: a manipulated block is rejected and not stored") {
            val cid = rawCid("what the CID names".toByteArray())
            val source = FixedSource { "something else".toByteArray() }
            val (node, storage) = localOnly(source)
            try {
                storage.getThroughRemote(cid, Duration.ofSeconds(5)).shouldBeNull()
                storage.getLocal(cid).shouldBeNull()
            } finally {
                node.stop()
            }
        }

        test("getThroughRemote: a block larger than the lookup limit is rejected even if it matches") {
            val big = ByteArray(LookupLimits.MAX_CONTENT + 1) { 1 }
            val cid = rawCid(big)
            val (node, storage) = localOnly(FixedSource { big })
            try {
                storage.getThroughRemote(cid, Duration.ofSeconds(5)).shouldBeNull()
            } finally {
                node.stop()
            }
        }

        test("getThroughRemote throws in network mode; the relay functions throw in local-only mode") {
            val node = LapisNode.create(DualKeyIdentity.generate(), mdnsEnabled = false).also { it.start() }
            try {
                val network = NabuStorage.attach(node, Files.createTempDirectory("j2-network"))
                val cid = rawCid(byteArrayOf(1))
                shouldThrow<IllegalStateException> { network.getThroughRemote(cid, Duration.ofSeconds(1)) }
            } finally {
                node.stop()
            }
            val (n2, local) = localOnly(null)
            try {
                shouldThrow<IllegalStateException> {
                    local.fetchTransient(
                        rawCid(byteArrayOf(2)),
                        Duration.ofSeconds(1),
                    )
                }
                shouldThrow<IllegalStateException> {
                    local.resolveIpnsRecordRaw(IpnsIdentity.generate().key, Duration.ofSeconds(1))
                }
            } finally {
                n2.stop()
            }
        }

        test("an unbound deferred source answers null everywhere; bound it delegates; unbound again it is null") {
            val bytes = "late".toByteArray()
            val cid = rawCid(bytes)
            val deferred = DeferredRemoteContentSource()
            val (node, storage) = localOnly(deferred)
            try {
                deferred.isBound shouldBe false
                deferred.fetchBlock(cid, 100, Duration.ofSeconds(1)).shouldBeNull()
                deferred.resolveIpnsRecord(IpnsIdentity.generate().key, Duration.ofSeconds(1)).shouldBeNull()
                deferred.blockIfCached(cid).shouldBeNull()
                storage.getThroughRemote(cid, Duration.ofSeconds(1)).shouldBeNull()
                deferred.bind(FixedSource { bytes })
                deferred.fetchBlock(cid, 100, Duration.ofSeconds(1)) shouldBe bytes
                deferred.unbind()
                deferred.fetchBlock(cid, 100, Duration.ofSeconds(1)).shouldBeNull()
                storage.getThroughRemote(cid, Duration.ofSeconds(1)).shouldBeNull()
            } finally {
                node.stop()
            }
        }

        test("verifier: CID shape, block match, IPNS key shape, signature, expiry and publisher") {
            val bytes = "block".toByteArray()
            val cid = rawCid(bytes)
            val wire = RemoteContentVerifier.rawSha256CidBytes(cid)!!
            wire.size shouldBe 36
            RemoteContentVerifier.parseRawSha256Cid(wire) shouldBe cid
            RemoteContentVerifier.parseRawSha256Cid(wire.copyOf(35)).shouldBeNull()
            RemoteContentVerifier.parseRawSha256Cid(wire.copyOf().also { it[1] = 0x70 }).shouldBeNull() // dag-pb
            // a declared multihash length that Nabu would allocate blindly never reaches Cid.cast
            RemoteContentVerifier.parseRawSha256Cid(byteArrayOf(1, 0x55, 0x12, 0x7F) + ByteArray(32)).shouldBeNull()
            RemoteContentVerifier.blockMatchesCid(cid, bytes) shouldBe true
            RemoteContentVerifier.blockMatchesCid(cid, "other".toByteArray()) shouldBe false

            val publisher = IpnsIdentity.generate()
            val stranger = IpnsIdentity.generate()
            RemoteContentVerifier.isIpnsRoutingKey(publisher.key) shouldBe true
            RemoteContentVerifier.isIpnsRoutingKey(wire) shouldBe false
            RemoteContentVerifier.isIpnsRoutingKey(publisher.key.copyOf(publisher.key.size - 1)) shouldBe false
            val now = Instant.now()
            val record = publisher.record(sequence = 3)
            RemoteContentVerifier.ipnsRecordValid(publisher.key, record, now) shouldBe true
            // publisher mismatch: a valid record under another name
            RemoteContentVerifier.ipnsRecordValid(stranger.key, record, now) shouldBe false
            // broken signature
            RemoteContentVerifier.ipnsRecordValid(publisher.key, tamper(record) { it.setSequence(9) }, now) shouldBe
                false
            // expired
            val expired = publisher.record(notValidAfter = now.minus(Duration.ofHours(2)))
            RemoteContentVerifier.ipnsRecordValid(publisher.key, expired, now) shouldBe false
            // wrong key type
            RemoteContentVerifier.ipnsRecordValid(wire, record, now) shouldBe false
        }
    })
