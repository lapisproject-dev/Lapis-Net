package net.lapisphilosophorum.lapisnet.storage

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import java.nio.file.Files
import java.time.Duration
import java.time.Instant
import kotlin.time.Duration.Companion.seconds

/**
 * Wave V0.10.0-J2: the relay side of a circuit lookup on real loopback nodes. A holds and announces, B is the DHT
 * peer in between, C is the LOOKUP relay. C fetches for an anonymous client WITHOUT keeping the block.
 */
class NabuStorageLookupRelayTest :
    FunSpec({
        test("fetchTransient fetches through the DHT, keeps nothing, announces nothing").config(timeout = 90.seconds) {
            val a = LapisNode.create(DualKeyIdentity.generate()).also { it.start(bootstrapPeers = emptyList()) }
            val b = LapisNode.create(DualKeyIdentity.generate()).also { it.start(bootstrapPeers = emptyList()) }
            val c = LapisNode.create(DualKeyIdentity.generate()).also { it.start(bootstrapPeers = emptyList()) }
            try {
                val storageA = NabuStorage.attach(a, Files.createTempDirectory("j2-holder"))
                NabuStorage.attach(b, Files.createTempDirectory("j2-dht"))
                val relay = NabuStorage.attach(c, Files.createTempDirectory("j2-relay"))
                val bAddress = b.listenAddresses().first().withP2P(b.peerId)
                storageA.connectToDhtPeer(bAddress) shouldBe true
                relay.connectToDhtPeer(bAddress) shouldBe true
                val payload = ByteArray(9000) { (it % 251).toByte() }
                val cid = storageA.put(payload)
                storageA.provide(cid)

                val fetched = relay.fetchTransient(cid, Duration.ofSeconds(20)).shouldNotBeNull()
                fetched.toList() shouldBe payload.toList()
                // not kept: neither in the served store nor anywhere else, and no provider record of its own
                relay.getLocal(cid).shouldBeNull()
                relay.localProviderRecords(cid).size shouldBe 0
                // a second lookup does not store it either. (Whether it finds the block again depends on the holder:
                // Nabu's responder does not resend a block it sent to the same peer recently - see docs/anonymity.adoc.)
                relay.fetchTransient(cid, Duration.ofSeconds(5))
                relay.getLocal(cid).shouldBeNull()
                relay.localProviderRecords(cid).size shouldBe 0
            } finally {
                listOf(a, b, c).forEach { runCatching { it.stop() } }
            }
        }

        test("fetchTransient never answers from the unserved store").config(timeout = 30.seconds) {
            val c = LapisNode.create(DualKeyIdentity.generate()).also { it.start(bootstrapPeers = emptyList()) }
            try {
                val relay = NabuStorage.attach(c, Files.createTempDirectory("j2-relay-private"))
                val cid = relay.putUnserved("received over an anonymous path".toByteArray())
                relay.fetchTransient(cid, Duration.ofSeconds(2)).shouldBeNull()
                val served = relay.put("public".toByteArray())
                relay.fetchTransient(served, Duration.ofSeconds(2)) shouldBe "public".toByteArray()
            } finally {
                c.stop()
            }
        }

        test(
            "resolveIpnsRecordRaw returns the raw record with the newest valid sequence",
        ).config(timeout = 60.seconds) {
            val a = newTestNode()
            val b = newTestNode()
            val c = newTestNode()
            try {
                val storageA = storageOn(a.node)
                storageOn(b.node)
                val relay = storageOn(c.node)
                storageA.connectToDhtPeer(addressOf(b.node)) shouldBe true
                relay.connectToDhtPeer(addressOf(b.node)) shouldBe true
                val expiry = Instant.now().plus(Duration.ofHours(1))
                storageA.publishIpnsValue(a.signingKey, "v1".toByteArray(), 1, expiry)
                storageA.publishIpnsValue(a.signingKey, "v2".toByteArray(), 2, expiry)
                val key = RemoteContentVerifier.ipnsRoutingKey(a.peerId)
                val raw = relay.resolveIpnsRecordRaw(key, Duration.ofSeconds(10)).shouldNotBeNull()
                RemoteContentVerifier.ipnsRecordValid(key, raw, Instant.now()) shouldBe true
                val v = IpnsRecordCodec.validate(key, raw, Instant.now(), DhtLimits()).shouldNotBeNull()
                v.sequence shouldBe 2
                String(v.value) shouldBe "v2"
                // a key of another shape is refused without a walk
                relay.resolveIpnsRecordRaw(key.copyOf(key.size - 1), Duration.ofSeconds(2)).shouldBeNull()
            } finally {
                listOf(a, b, c).forEach { runCatching { it.node.stop() } }
            }
        }
    })
