package net.lapisphilosophorum.lapisnet.dmonion.attachment

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import net.lapisphilosophorum.lapisnet.directory.DirectoryReachability
import net.lapisphilosophorum.lapisnet.dmonion.DmCircuitFraming
import net.lapisphilosophorum.lapisnet.dmonion.FakeChannel
import net.lapisphilosophorum.lapisnet.dmonion.FrameChannel
import net.lapisphilosophorum.lapisnet.dmonion.Peer
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptor
import net.lapisphilosophorum.lapisnet.storage.RemoteContentVerifier
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.PriorityQueue
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** Virtual time: tasks run only when the test advances the clock, in order of their due time. */
class ManualScheduler(
    start: Long = 1_000_000L,
) : AttachmentScheduler {
    private class Task(
        val due: Long,
        val seq: Long,
        val run: () -> Unit,
    ) {
        @Volatile var cancelled = false
    }

    private val lock = Any()
    private val queue = PriorityQueue<Task>(compareBy<Task>({ it.due }, { it.seq }))
    private var seq = 0L

    @Volatile private var now = start

    @Volatile var closed = false
        private set

    override fun nowMillis(): Long = now

    override fun schedule(
        delayMillis: Long,
        task: () -> Unit,
    ): AttachmentTimer? {
        synchronized(lock) {
            if (closed) return null
            val t = Task(now + maxOf(0L, delayMillis), seq++, task)
            queue.add(t)
            return AttachmentTimer { t.cancelled = true }
        }
    }

    /** Runs every task due within [millis] (tasks scheduled meanwhile included), then sets the clock to the end. */
    fun advance(millis: Long) {
        val target = now + millis
        while (true) {
            val next =
                synchronized(lock) {
                    val head = queue.peek() ?: return@synchronized null
                    if (head.due > target) return@synchronized null
                    queue.poll()
                } ?: break
            now = maxOf(now, next.due)
            if (!next.cancelled) next.run()
        }
        now = target
    }

    fun pending(): Int = synchronized(lock) { queue.count { !it.cancelled } }

    override fun close() {
        synchronized(lock) {
            closed = true
            queue.clear()
        }
    }
}

/** A channel that refuses every send after the first [okSends] (a full link). */
class FailingChannel(
    private val inner: FakeChannel,
    private val okSends: Int,
) : FrameChannel by inner {
    val sends = AtomicInteger()

    override fun send(data: ByteArray): Boolean {
        if (sends.incrementAndGet() > okSends) {
            inner.close()
            return false
        }
        return inner.send(data)
    }
}

/** A scripted runtime port for the attachment client. */
class FakeAttachmentPort : OnionAttachmentRuntimePort {
    @Volatile var ready = true

    @Volatile var reachability: (Secp256k1PublicKey) -> DirectoryReachability = { DirectoryReachability.Unknown }

    @Volatile var connectFails = false

    /** Called with the service end of every new pair, before the client end is returned. */
    @Volatile var onConnect: (FakeChannel) -> Unit = {}
    val connects = AtomicInteger()
    val clientEnds = CopyOnWriteArrayList<FakeChannel>()
    val serviceEnds = CopyOnWriteArrayList<FakeChannel>()

    /** When set, connects stay pending until the test completes this future (with the client end it is handed). */
    @Volatile var hold: CompletableFuture<FrameChannel>? = null

    override fun ready(): Boolean = ready

    override fun resolveIdentity(identity: Secp256k1PublicKey): DirectoryReachability = reachability(identity)

    override fun connect(
        descriptor: OnionServiceDescriptor,
        timeout: java.time.Duration,
    ): CompletableFuture<FrameChannel> {
        connects.incrementAndGet()
        if (connectFails) return CompletableFuture.failedFuture(IllegalStateException("no route"))
        val (client, service) = FakeChannel.pair()
        clientEnds += client
        serviceEnds += service
        onConnect(service)
        hold?.let { return it }
        return CompletableFuture.completedFuture(client)
    }
}

/** A peer that is reachable as an onion service. */
fun hiddenPeer(): Pair<Peer, DirectoryReachability.Hidden> {
    val peer = Peer()
    return peer to DirectoryReachability.Hidden(peer.record(), peer.descriptor())
}

fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

fun rawCid(bytes: ByteArray): Cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, sha256(bytes))

fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

/**
 * The fetch token as wave Q21 computed it before wave Q21-Token: HMAC-SHA256 directly under the attachment key. Used
 * only to show that such a token is refused now. A new [Mac] instance per call.
 */
fun legacyDirectToken(
    attachmentKey: ByteArray,
    cid: Cid,
): ByteArray {
    val cidBytes = requireNotNull(RemoteContentVerifier.rawSha256CidBytes(cid))
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(SecretKeySpec(attachmentKey, "HmacSHA256"))
    mac.update("LapisNet:attachment-fetch:v1".toByteArray(Charsets.US_ASCII))
    return mac.doFinal(cidBytes)
}

/** One decoded answer frame: the declared payload length and the payload. */
class AnswerFrame(
    val type: Int,
    val payload: ByteArray,
) {
    val header: AttachmentFetchCodec.ChunkHeader get() = AttachmentFetchCodec.decodeChunkHeader(payload, payload.size)
}

/** Splits the concatenated stream messages of an answer into frames. */
fun answerFrames(messages: List<ByteArray>): List<AnswerFrame> {
    val all = messages.fold(ByteArray(0)) { a, b -> a + b }
    val out = ArrayList<AnswerFrame>()
    var offset = 0
    while (offset + DmCircuitFraming.HEADER_SIZE <= all.size) {
        val buf = ByteBuffer.wrap(all, offset, DmCircuitFraming.HEADER_SIZE)
        val type = buf.get().toInt() and 0xFF
        val length = buf.getInt()
        offset += DmCircuitFraming.HEADER_SIZE
        out += AnswerFrame(type, all.copyOfRange(offset, offset + length))
        offset += length
    }
    check(offset == all.size) { "trailing bytes" }
    return out
}

/** The request stream messages for [cid] with [token] (the way the client sends them). */
fun requestMessages(
    cid: Cid,
    token: ByteArray,
    maxPayload: Int = 910,
): List<ByteArray> =
    DmCircuitFraming.chunks(
        AttachmentFetchCodec.requestFrame(AttachmentFetchCodec.encodeRequest(cid, token, java.security.SecureRandom())),
        maxPayload,
    )

/** The stream messages of a scripted answer built from [payloads]. */
fun answerMessages(
    payloads: List<ByteArray>,
    maxPayload: Int = 910,
): List<ByteArray> = payloads.flatMap { DmCircuitFraming.chunks(AttachmentFetchCodec.chunkFrame(it), maxPayload) }

/** A chunk payload with a hand-written header (for manipulation tests). */
fun rawChunk(
    status: Int,
    classIndex: Int,
    chunkIndex: Int,
    chunkCount: Int,
    totalLength: Int,
    payloadLength: Int,
    data: ByteArray = ByteArray(0),
): ByteArray {
    val out = ByteArray(payloadLength)
    ByteBuffer
        .wrap(out)
        .put(status.toByte())
        .put(classIndex.toByte())
        .putShort(chunkIndex.toShort())
        .putShort(chunkCount.toShort())
        .putInt(totalLength)
        .put(data)
    return out
}
