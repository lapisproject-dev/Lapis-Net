package net.lapisphilosophorum.lapisnet.browser

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.longs.shouldBeLessThan
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.config.AnonymityMode
import net.lapisphilosophorum.lapisnet.networking.config.NodeWiringOptions
import net.lapisphilosophorum.lapisnet.networking.dcutr.HolePunchMode
import net.lapisphilosophorum.lapisnet.networking.deriveLibp2pPeerId
import net.lapisphilosophorum.lapisnet.storage.BlockProvideConfig
import java.nio.file.Files
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/** Fast cycles; every tracked CID is due at once. */
internal val FAST_POST_PROVIDE =
    BlockProvideConfig(
        reprovideInterval = 2.seconds,
        reprovideJitterFraction = 0.0,
        firstProvideDelayMax = Duration.ZERO,
        cycleInterval = 200.milliseconds,
        cycleJitter = Duration.ZERO,
        initialDelay = 100.milliseconds,
        perProvideTimeout = 5.seconds,
        cycleBudget = 10.seconds,
        failureRetryMin = 500.milliseconds,
    )

/** Wave Q20: what `BrowserServer.start` wires for `provide-post-bodies`. */
class PostBodyProviderWiringTest :
    FunSpec({
        test(
            "normal mode: the scheduler and its supervisor job exist; own posts are tracked",
        ).config(timeout = 90.seconds) {
            val server = startWiredTestServer(postBodyProvideConfig = FAST_POST_PROVIDE)
            try {
                val provider = server.postBodyProviderForTesting.shouldNotBeNull()
                val job = server.postBodyProviderJobForTesting.shouldNotBeNull()
                job.name shouldBe "post-body-provider"
                job.isCancelled shouldBe false
                val cid =
                    server.postsForTesting.announce(
                        PostAnnouncement.create(server.identityForTesting().secp256k1KeyPair, "wired".toByteArray()),
                    )
                provider.isTracked(cid) shouldBe true
                // with no DHT peer the cycle runs, announces nothing and does not crash the job
                val deadline = System.nanoTime() + 20_000_000_000L
                while (job.runCount < 3 && System.nanoTime() < deadline) Thread.sleep(50)
                (job.runCount >= 3) shouldBe true
                job.failureCount shouldBe 0
                provider.stats().announced shouldBe 0
            } finally {
                server.stop()
            }
        }

        test("provide-post-bodies=false: no scheduler and no job").config(timeout = 90.seconds) {
            val server =
                startWiredTestServer(config = BrowserConfig(NodeWiringOptions(providePostBodies = false)))
            try {
                server.postBodyProviderForTesting.shouldBeNull()
                server.postBodyProviderJobForTesting.shouldBeNull()
            } finally {
                server.stop()
            }
        }

        test("anonymity mode: no scheduler, no job, and this wave refuses no extra storage operation").config(
            timeout = 120.seconds,
        ) {
            // providePostBodies = true in code: effective() must still switch it off
            val config =
                BrowserConfig(
                    NodeWiringOptions(
                        anonymity = AnonymityMode.ON,
                        holePunching = HolePunchMode.OFF,
                        providePostBodies = true,
                    ),
                )
            val server = startWiredTestServer(config = config, dataDirectory = Files.createTempDirectory("q20-anon"))
            try {
                server.postBodyProviderForTesting.shouldBeNull()
                server.postBodyProviderJobForTesting.shouldBeNull()
                val before = server.storageForTesting.refusedNetworkOperations
                // a gossiped post reaches the validator; with no scheduler nothing tries to provide it
                val bytes =
                    PostAnnouncementCodec.encode(
                        PostAnnouncement.create(DualKeyIdentity.generate().secp256k1KeyPair, "anon".toByteArray()),
                    )
                PostAnnouncementGossip.onGossipMessage(
                    bytes,
                    DualKeyIdentity.generate().deriveLibp2pPeerId(),
                    server.storageForTesting,
                    PostAnnouncementIndex(),
                )
                Thread.sleep(1_000)
                server.storageForTesting.refusedNetworkOperations shouldBe before
            } finally {
                server.stop()
            }
        }

        test("stop returns promptly with the provide job running, cancels it and terminates the worker pool").config(
            timeout = 90.seconds,
        ) {
            val server = startWiredTestServer(postBodyProvideConfig = FAST_POST_PROVIDE)
            val job = server.postBodyProviderJobForTesting.shouldNotBeNull()
            val deadline = System.nanoTime() + 20_000_000_000L
            while (job.runCount < 2 && System.nanoTime() < deadline) Thread.sleep(50)
            val start = System.nanoTime()
            server.stop()
            (System.nanoTime() - start) shouldBeLessThan 30_000_000_000L
            job.isCancelled shouldBe true
            server.postBodyProviderForTesting.shouldNotBeNull().trackedCount() shouldBe 0
            // the supervisor's pool (the thread the cycle ran on) has terminated
            server.supervisorForTesting.isTerminated() shouldBe true
        }
    })
