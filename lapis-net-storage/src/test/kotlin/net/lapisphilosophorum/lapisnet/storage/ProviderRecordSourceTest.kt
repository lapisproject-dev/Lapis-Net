package net.lapisphilosophorum.lapisnet.storage

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.deriveLibp2pPeerId
import org.peergos.protocol.dht.pb.Dht
import java.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * V0.9.14: the DHT rendezvous records for mail and direct messages rely on provider records being
 * source-authenticated - a node can only announce ITSELF as provider of a key. Nabu v0.8.0 keeps a provider
 * record only if the provider ID equals the sender of the `ADD_PROVIDER` (found in its bytecode); this pins that
 * behavior so a Nabu update cannot silently change it. Also: looking up a key for which no block exists anywhere
 * (a rendezvous key) ends cleanly with an empty set.
 */
class ProviderRecordSourceTest :
    FunSpec({
        val rendezvousKey = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { 42 })

        test("an ADD_PROVIDER that names another peer as provider is not stored, one naming the sender is").config(
            timeout = 60.seconds,
        ) {
            val victim = newNode()
            try {
                val storage = storageOn(victim)
                val attacker = ScriptedDhtPeer.start()
                val innocent = DualKeyIdentity.generate().deriveLibp2pPeerId()

                fun announce(provider: io.libp2p.core.PeerId) =
                    Dht.Message
                        .newBuilder()
                        .setType(Dht.Message.MessageType.ADD_PROVIDER)
                        .keyBytes(rendezvousKey.bareMultihash().toBytes())
                        .addProviderPeers(peerProto(provider))
                        .build()

                attacker.send(victim, announce(innocent))
                Thread.sleep(1500)
                attacker.send(victim, announce(attacker.peerId))
                awaitCondition {
                    storage
                        .localProviderRecords(
                            rendezvousKey,
                        ).any { it.id.toByteArray().contentEquals(attacker.peerId.bytes) }
                } shouldBe true
                storage
                    .localProviderRecords(rendezvousKey)
                    .any { it.id.toByteArray().contentEquals(innocent.bytes) } shouldBe false
                attacker.stop()
            } finally {
                victim.stop()
            }
        }

        test("a lookup for a rendezvous key nobody has a block for returns an empty set") {
            val node = newNode()
            try {
                storageOn(node).findProviders(rendezvousKey, 8, Duration.ofSeconds(2)) shouldBe emptySet()
            } finally {
                node.stop()
            }
        }
    })
