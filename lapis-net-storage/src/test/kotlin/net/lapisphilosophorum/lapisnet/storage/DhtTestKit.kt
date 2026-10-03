package net.lapisphilosophorum.lapisnet.storage

import com.google.protobuf.ByteString
import io.ipfs.multihash.Multihash
import io.libp2p.core.PeerId
import io.libp2p.core.Stream
import io.libp2p.core.multiformats.Multiaddr
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import org.peergos.blockstore.RamBlockstore
import org.peergos.protocol.dht.Kademlia
import org.peergos.protocol.dht.KademliaEngine
import org.peergos.protocol.dht.RamProviderStore
import org.peergos.protocol.dht.pb.Dht
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.file.Files
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/** A started [LapisNode] with no bootstrap peers (loopback only). */
internal fun newNode(): LapisNode =
    LapisNode.create(DualKeyIdentity.generate()).also {
        it.start(bootstrapPeers = emptyList())
    }

internal fun storageOn(
    node: LapisNode,
    limits: DhtLimits = DhtLimits(),
    clock: () -> Long = System::nanoTime,
): NabuStorage = NabuStorage.attachWithClock(node, Files.createTempDirectory("dht-test"), true, limits, clock)

internal fun addressOf(node: LapisNode): Multiaddr = node.listenAddresses().first().withP2P(node.peerId)

/** Polls [condition] until it holds or [timeoutMs] passes; returns whether it held. */
internal fun awaitCondition(
    timeoutMs: Long = 10_000,
    pollMs: Long = 50,
    condition: () -> Boolean,
): Boolean {
    val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs)
    while (System.nanoTime() < deadline) {
        if (condition()) return true
        Thread.sleep(pollMs)
    }
    return condition()
}

internal fun Dht.Message.Builder.keyBytes(bytes: ByteArray): Dht.Message.Builder = setKey(ByteString.copyFrom(bytes))

internal fun peerProto(
    id: PeerId,
    addresses: List<ByteArray> = emptyList(),
): Dht.Message.Peer =
    Dht.Message.Peer
        .newBuilder()
        .setId(ByteString.copyFrom(id.bytes))
        .addAllAddrs(addresses.map { ByteString.copyFrom(it) })
        .build()

/**
 * A Kademlia responder whose behaviour the TEST scripts: it records every request and answers via
 * [responder] (silence by default). This is what lets tests play a hostile or broken peer against the
 * real [NabuStorage] over a real loopback connection.
 */
internal class ScriptedKademliaEngine(
    ourPeerId: Multihash,
) : KademliaEngine(ourPeerId, RamProviderStore(16), BoundedRecordStore(16), RamBlockstore()) {
    val received = CopyOnWriteArrayList<Dht.Message>()

    @Volatile
    var responder: (Dht.Message, Stream) -> Unit = { _, _ -> }

    override fun receiveRequest(
        msg: Dht.Message,
        source: PeerId,
        stream: Stream,
    ) {
        received += msg
        responder(msg, stream)
    }
}

/** A raw libp2p node speaking the LAN Kademlia protocol through a [ScriptedKademliaEngine]. */
internal class ScriptedDhtPeer private constructor(
    val node: LapisNode,
    val engine: ScriptedKademliaEngine,
    val kademlia: Kademlia,
) {
    val peerId: PeerId get() = node.peerId
    val address: Multiaddr get() = addressOf(node)

    /** Answers every request of type [type] with the message [reply] builds from the request. */
    fun answer(
        type: Dht.Message.MessageType,
        reply: (Dht.Message) -> Dht.Message,
    ) {
        engine.responder = { msg, stream ->
            if (msg.type == type) stream.writeAndFlush(reply(msg))
        }
    }

    /** Opens a stream to [target] FROM this peer and sends [message] (no reply expected or read). */
    fun send(
        target: LapisNode,
        message: Dht.Message,
    ) {
        val controller = kademlia.dial(node.host, target.peerId, addressOf(target)).controller.get(10, TimeUnit.SECONDS)
        controller.send(message).get(10, TimeUnit.SECONDS)
    }

    fun stop() {
        runCatching { node.stop() }
    }

    companion object {
        fun start(): ScriptedDhtPeer {
            val node = newNode()
            val engine = ScriptedKademliaEngine(Multihash.deserialize(node.peerId.bytes))
            val kademlia = Kademlia(engine, true)
            kademlia.setAddressBook(node.host.addressBook)
            node.host.addProtocolHandler(kademlia)
            return ScriptedDhtPeer(node, engine, kademlia)
        }
    }
}

/**
 * A TCP listener on a loopback address (127.0.0.1 unless told otherwise) that counts accepted connections and never speaks - to a libp2p dial it
 * is a host that accepts the connection and then stalls the Noise handshake.
 */
internal class CountingListener(
    host: String = "127.0.0.1",
) : AutoCloseable {
    private val server = ServerSocket(0, 256, InetAddress.getByName(host))
    private val accepted = AtomicInteger()
    private val sockets = CopyOnWriteArrayList<Socket>()
    val port: Int get() = server.localPort
    val acceptedCount: Int get() = accepted.get()

    init {
        Thread {
            while (!server.isClosed) {
                try {
                    sockets += server.accept()
                    accepted.incrementAndGet()
                } catch (_: Exception) {
                    break
                }
            }
        }.apply {
            isDaemon = true
            start()
        }
    }

    override fun close() {
        runCatching { server.close() }
        sockets.forEach { runCatching { it.close() } }
    }
}
