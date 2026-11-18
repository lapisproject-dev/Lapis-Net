package net.lapisphilosophorum.lapisnet.onionwire.lookup

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files
import java.time.Duration

class NabuLookupSinkTest :
    FunSpec({
        test("the outcomes of the production sink: found, too large, not found") {
            val node =
                LapisNode.create(DualKeyIdentity.generate(), mdnsEnabled = false).also {
                    it.start(bootstrapPeers = emptyList())
                }
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("sink"))
                val sink = NabuLookupSink(storage)
                val block = ByteArray(3000) { 4 }
                val cid = storage.put(block)
                sink
                    .fetchBlock(
                        cid,
                        131_066,
                        Duration.ofSeconds(2),
                    ).shouldBeInstanceOf<LookupOutcome.Found>()
                    .bytes shouldBe
                    block
                sink.fetchBlock(cid, 100, Duration.ofSeconds(2)) shouldBe LookupOutcome.TooLarge(3000)
                // no DHT peers: nothing to ask, answered at once
                sink.fetchBlock(rawCid("missing".toByteArray()), 131_066, Duration.ofSeconds(2)) shouldBe
                    LookupOutcome.NotFound
                sink.resolveIpnsRecord(TestIpnsPublisher().routingKey, Duration.ofSeconds(2)) shouldBe
                    LookupOutcome.NotFound
            } finally {
                node.stop()
            }
        }
    })
