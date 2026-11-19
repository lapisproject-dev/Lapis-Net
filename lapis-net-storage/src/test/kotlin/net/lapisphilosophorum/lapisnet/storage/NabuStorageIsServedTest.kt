package net.lapisphilosophorum.lapisnet.storage

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import java.nio.file.Files
import java.security.MessageDigest
import java.time.Duration

/** Wave Q20: [NabuStorage.isServed] sees only the served store; [NabuStorage.provide] clamps its fanout. */
class NabuStorageIsServedTest :
    FunSpec({
        test("isServed is true after put, false after putUnserved and for a missing CID; the adapter agrees") {
            val node = LapisNode.create(DualKeyIdentity.generate(), mdnsEnabled = false)
            node.start()
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("is-served"))
                val served = storage.put("served block".toByteArray())
                val unserved = storage.putUnserved("private block".toByteArray())
                val missing =
                    Cid.buildCidV1(
                        Cid.Codec.Raw,
                        Multihash.Type.sha2_256,
                        MessageDigest.getInstance("SHA-256").digest("nowhere".toByteArray()),
                    )
                storage.isServed(served) shouldBe true
                storage.isServed(unserved) shouldBe false
                storage.getLocal(unserved) shouldBe "private block".toByteArray() // still readable locally
                storage.isServed(missing) shouldBe false
                val target = storage.asProvideTarget()
                target.isServed(served) shouldBe true
                target.isServed(unserved) shouldBe false
                target.isStopped() shouldBe false
                storage.stop()
                target.isStopped() shouldBe true
                storage.isStopped shouldBe true
            } finally {
                runCatching { node.stop() }
            }
        }

        test("provide clamps fanout to 1..provideFanout and sends to at most that many peers") {
            val nodes = (0 until 4).map { LapisNode.create(DualKeyIdentity.generate(), mdnsEnabled = false) }
            try {
                nodes.forEach { it.start() }
                val storages =
                    nodes.mapIndexed {
                        i,
                        n,
                        ->
                        NabuStorage.attach(n, Files.createTempDirectory("fanout-$i"))
                    }
                val holder = storages[0]
                for (i in 1 until nodes.size) {
                    holder.connectToDhtPeer(nodes[i].listenAddresses().first().withP2P(nodes[i].peerId)) shouldBe true
                }
                val cid = holder.put("fanout".toByteArray())
                holder.provide(cid, Duration.ofSeconds(5), fanout = 1) shouldBe 1
                holder.provide(cid, Duration.ofSeconds(5), fanout = 0) shouldBe 1 // clamped up to 1
                holder.provide(cid, Duration.ofSeconds(5), fanout = 2) shouldBe 2
                // clamped to provideFanout; only 3 peers are known
                holder.provide(cid, Duration.ofSeconds(5), fanout = 1000) shouldBe 3
                holder.asProvideTarget().provide(cid, Duration.ofSeconds(5), 2) shouldBe 2
            } finally {
                nodes.forEach { runCatching { it.stop() } }
            }
        }

        test("in LOCAL_ONLY provide with a fanout is still refused and counted") {
            val node = LapisNode.create(DualKeyIdentity.generate(), mdnsEnabled = false)
            node.start()
            try {
                val storage =
                    NabuStorage.attach(
                        node,
                        Files.createTempDirectory("is-served-local"),
                        networkMode = StorageNetworkMode.LOCAL_ONLY,
                    )
                val cid = storage.put("local".toByteArray())
                val before = storage.refusedNetworkOperations
                shouldThrow<AnonymousStorageRefusedException> { storage.provide(cid, Duration.ofSeconds(2), 3) }
                shouldThrow<AnonymousStorageRefusedException> {
                    storage.asProvideTarget().provide(cid, Duration.ofSeconds(2), 3)
                }
                storage.refusedNetworkOperations shouldBe before + 2
                // isServed is local only and works in LOCAL_ONLY
                storage.isServed(cid) shouldBe true
            } finally {
                runCatching { node.stop() }
            }
        }
    })
