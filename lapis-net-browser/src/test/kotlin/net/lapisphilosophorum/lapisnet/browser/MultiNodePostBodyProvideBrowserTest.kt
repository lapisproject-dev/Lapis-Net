package net.lapisphilosophorum.lapisnet.browser

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerInfo
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.networking.config.NodeWiringOptions
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files
import kotlin.time.Duration.Companion.seconds

private fun awaitCondition(
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

/** Two browser nodes connected by gossip and DHT, plus a storage-only observer C on the DHT. */
private class Mesh(
    providePostBodies: Boolean,
) : AutoCloseable {
    val config = BrowserConfig(NodeWiringOptions(providePostBodies = providePostBodies))
    val a = startWiredTestServer(config = config, postBodyProvideConfig = FAST_POST_PROVIDE)
    val b = startWiredTestServer(config = config, postBodyProvideConfig = FAST_POST_PROVIDE)
    val observerNode = LapisNode.create(DualKeyIdentity.generate()).also { it.start(bootstrapPeers = emptyList()) }
    val observer = NabuStorage.attach(observerNode, Files.createTempDirectory("q20-observer"))

    init {
        // gossip mesh A <-> B
        a.nodeForTesting.connect(PeerInfo(b.nodeForTesting.peerId, b.nodeForTesting.listenAddresses()))
        // DHT: everyone knows everyone, so a provide by A or B reaches C
        val all = listOf(a.storageForTesting to a.nodeForTesting, b.storageForTesting to b.nodeForTesting)
        for ((storage, _) in all) {
            storage.connectToDhtPeer(observerNode.listenAddresses().first().withP2P(observerNode.peerId)) shouldBe true
        }
        a.storageForTesting.connectToDhtPeer(
            b.nodeForTesting
                .listenAddresses()
                .first()
                .withP2P(b.nodeForTesting.peerId),
        ) shouldBe true
        observer.connectToDhtPeer(
            a.nodeForTesting
                .listenAddresses()
                .first()
                .withP2P(a.nodeForTesting.peerId),
        ) shouldBe true
    }

    override fun close() {
        runCatching { a.stop() }
        runCatching { b.stop() }
        runCatching { observerNode.stop() }
    }
}

/**
 * Wave Q20, end to end over real loopback nodes: A posts, B receives the post by gossip, and BOTH send a real
 * `ADD_PROVIDER` for the body to the observer C (checked on C's own provider store, because on loopback Nabu's
 * responder names itself without addresses and would make a `findProviders` result prove nothing).
 */
class MultiNodePostBodyProvideBrowserTest :
    FunSpec({
        test("own and gossiped posts are announced alike: C holds provider records from A and from B").config(
            timeout = 180.seconds,
        ) {
            Mesh(providePostBodies = true).use { mesh ->
                val text = "Q20 body announced by its author and by a receiver"
                // the gossip mesh needs a moment after connect; publish until B has it
                lateinit var cid: io.ipfs.cid.Cid
                val received =
                    awaitCondition(60_000) {
                        cid =
                            mesh.a.postsForTesting.announce(
                                PostAnnouncement.create(
                                    mesh.a.identityForTesting().secp256k1KeyPair,
                                    "$text ${System.nanoTime()}".toByteArray(),
                                ),
                            )
                        awaitCondition(2_000) {
                            mesh.b.postsForTesting
                                .currentPosts()
                                .any { it.cid == cid }
                        }
                    }
                received shouldBe true
                mesh.b.postBodyProviderForTesting!!.isTracked(cid) shouldBe true
                val holders = setOf(mesh.a.nodeForTesting.peerId, mesh.b.nodeForTesting.peerId)
                awaitCondition { mesh.observer.heldProviderRecords(cid).containsAll(holders) } shouldBe true
                // and C's lookup names a holder
                awaitCondition {
                    mesh.observer
                        .findProviders(cid, 8)
                        .intersect(holders)
                        .isNotEmpty()
                } shouldBe true
            }
        }

        test("provide-post-bodies=false: C never receives a provider record for the body").config(
            timeout = 180.seconds,
        ) {
            Mesh(providePostBodies = false).use { mesh ->
                lateinit var cid: io.ipfs.cid.Cid
                val received =
                    awaitCondition(60_000) {
                        cid =
                            mesh.a.postsForTesting.announce(
                                PostAnnouncement.create(
                                    mesh.a.identityForTesting().secp256k1KeyPair,
                                    "Q20 not announced ${System.nanoTime()}".toByteArray(),
                                ),
                            )
                        awaitCondition(2_000) {
                            mesh.b.postsForTesting
                                .currentPosts()
                                .any { it.cid == cid }
                        }
                    }
                received shouldBe true
                // FAST_POST_PROVIDE would announce within well under a second; wait several cycles' worth
                Thread.sleep(5_000)
                mesh.observer.heldProviderRecords(cid) shouldBe emptySet()
            }
        }
    })
