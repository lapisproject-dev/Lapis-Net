package net.lapisphilosophorum.lapisnet.directory

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldNotContain
import io.kotest.matchers.types.shouldBeInstanceOf
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.onion.IntroPointEntry
import net.lapisphilosophorum.lapisnet.onion.OnionKeyBinding
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptor
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files
import java.time.Instant

class AnonymousDirectoryResolveTest :
    FunSpec({
        val node = LapisNode.create(DualKeyIdentity.generate())
        node.start(bootstrapPeers = emptyList())
        val storage = NabuStorage.attach(node, Files.createTempDirectory("anonymous-directory-test"))
        val pubsub = GossipPubSub.attach(node)
        val peerDirectory = PeerDirectoryGossip.attach(pubsub, storage)
        val descriptors = OnionServiceDescriptorIndex()
        val directory = AnonymousDirectory(peerDirectory, descriptors, null) { Instant.now() }
        val now = { Instant.now().epochSecond }

        afterSpec {
            peerDirectory.stop()
            pubsub.stop()
            runCatching { node.stop() }
        }

        fun descriptorFor(service: Ed25519KeyPair): OnionServiceDescriptor {
            val relays = List(3) { DualKeyIdentity.generate() }
            val intro =
                relays.map {
                    IntroPointEntry(
                        OnionKeyBinding.create(it.secp256k1KeyPair, X25519KeyPair.generate().publicKey, now() + 86_400),
                        Ed25519KeyPair.generate().publicKey,
                    )
                }
            return OnionServiceDescriptor.create(
                service,
                X25519KeyPair.generate().publicKey,
                intro,
                1,
                now() + 3600,
                now(),
            )
        }

        test("an unknown identity is Unknown") {
            directory.resolve(AnonymousPublisher().key) shouldBe DirectoryReachability.Unknown
        }

        test("an anonymous record with a known descriptor resolves to Hidden") {
            val p = AnonymousPublisher()
            val d = descriptorFor(p.serviceKey)
            descriptors.add(d, now()) shouldBe DescriptorIngestOutcome.ACCEPTED
            peerDirectory.anonymousRecords.add(p.record(10), now()) shouldBe AnonymousIngestOutcome.ACCEPTED
            val r = directory.resolve(p.key).shouldBeInstanceOf<DirectoryReachability.Hidden>()
            r.descriptor shouldBe d
            r.toString() shouldNotContain p.serviceKey.publicKey.fingerprint()
        }

        test("an anonymous record without a descriptor resolves to HiddenDescriptorMissing") {
            val p = AnonymousPublisher()
            peerDirectory.anonymousRecords.add(p.record(10), now()) shouldBe AnonymousIngestOutcome.ACCEPTED
            directory.resolve(p.key).shouldBeInstanceOf<DirectoryReachability.HiddenDescriptorMissing>()
        }

        test("an address record alone resolves to Direct") {
            val p = AnonymousPublisher()
            val r = p.peerRecord(sequence = 5)
            peerDirectory.announce(r)
            directory.resolve(p.key).shouldBeInstanceOf<DirectoryReachability.Direct>().record shouldBe r
        }

        test("the newer type wins by sequence number, in both directions") {
            val p = AnonymousPublisher()
            peerDirectory.announce(p.peerRecord(sequence = 5))
            peerDirectory.anonymousRecords.add(p.record(6), now()) shouldBe AnonymousIngestOutcome.ACCEPTED
            directory.resolve(p.key).shouldBeInstanceOf<DirectoryReachability.HiddenDescriptorMissing>()
            peerDirectory.announce(p.peerRecord(sequence = 7, port = 4005))
            directory.resolve(p.key).shouldBeInstanceOf<DirectoryReachability.Direct>()
        }

        test("a revocation without a newer address record resolves to Revoked") {
            val p = AnonymousPublisher()
            peerDirectory.anonymousRecords.add(p.record(10), now())
            peerDirectory.anonymousRecords.add(p.revocation(11), now()) shouldBe AnonymousIngestOutcome.ACCEPTED
            directory.resolve(p.key) shouldBe DirectoryReachability.Revoked
        }

        test("every reachability prints redacted") {
            val p = AnonymousPublisher()
            val rec = p.record(1)
            val shown =
                listOf(
                    DirectoryReachability.Hidden(rec, descriptorFor(p.serviceKey)).toString(),
                    DirectoryReachability.HiddenDescriptorMissing(rec).toString(),
                    DirectoryReachability.Direct(p.peerRecord(1)).toString(),
                )
            shown.forEach { it shouldNotContain "127.0.0.1" }
            shown.forEach { it shouldNotContain p.key.fingerprint() }
        }
    })
