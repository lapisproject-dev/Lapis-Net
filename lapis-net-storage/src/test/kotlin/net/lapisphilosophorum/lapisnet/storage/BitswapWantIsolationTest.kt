package net.lapisphilosophorum.lapisnet.storage

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.Stream
import io.prometheus.client.Counter
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import org.peergos.BlockRequestAuthoriser
import org.peergos.Hash
import org.peergos.blockstore.RamBlockstore
import org.peergos.protocol.bitswap.Bitswap
import org.peergos.protocol.bitswap.BitswapEngine
import org.peergos.protocol.bitswap.pb.MessageOuterClass
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.time.Duration.Companion.seconds

/** A Bitswap peer that records every CID it is asked for and never answers. */
private class RecordingBitswapPeer(
    val node: LapisNode,
) {
    val wanted = CopyOnWriteArrayList<Cid>()

    init {
        val engine =
            object : BitswapEngine(
                RamBlockstore(),
                BlockRequestAuthoriser { _, _, _ -> CompletableFuture.completedFuture(true) },
                Bitswap.MAX_MESSAGE_SIZE,
                false,
            ) {
                override fun receiveMessage(
                    msg: MessageOuterClass.Message,
                    source: Stream,
                    sentBytes: Counter,
                ) {
                    if (msg.hasWantlist()) {
                        msg.wantlist.entriesList.forEach {
                            wanted +=
                                Cid.cast(
                                    it.block.toByteArray(),
                                )
                        }
                    }
                }
            }
        val bitswap = Bitswap(engine)
        bitswap.setAddressBook(node.host.addressBook)
        node.host.addProtocolHandler(bitswap)
    }
}

/**
 * The CID is the access token for a block (reads are always authorised), so a want that was asked of one
 * peer must not appear in another peer's wantlist. Nabu's own `getWants` for a peer returns every pending
 * want of the process, so a block requested from the sender of a direct message was also announced to a
 * provider the DHT named for an unrelated block - and kept being re-sent to it.
 */
class BitswapWantIsolationTest :
    FunSpec({
        fun cidOf(text: String) =
            Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, Hash.sha256(text.toByteArray()))

        test("a block asked of one peer is never announced to another peer, not even by the re-send").config(
            timeout = 60.seconds,
        ) {
            val node = newNode()
            val first = RecordingBitswapPeer(newNode())
            val second = RecordingBitswapPeer(newNode())
            try {
                val storage = storageOn(node)
                storage.registerPeerAddress(addressOf(first.node))
                storage.registerPeerAddress(addressOf(second.node))
                val secret = cidOf("access token of a direct message attachment")
                val other = cidOf("a block some provider was named for")

                storage.get(secret, peers = setOf(first.node.peerId), timeout = Duration.ofSeconds(1)) shouldBe null
                storage.get(other, peers = setOf(second.node.peerId), timeout = Duration.ofSeconds(1)) shouldBe null

                awaitCondition { first.wanted.contains(secret) && second.wanted.contains(other) } shouldBe true
                // Bitswap's own re-send thread runs every five seconds
                Thread.sleep(6_500)

                second.wanted.contains(secret) shouldBe false
                first.wanted.contains(other) shouldBe false
            } finally {
                listOf(node, first.node, second.node).forEach { runCatching { it.stop() } }
            }
        }
    })
