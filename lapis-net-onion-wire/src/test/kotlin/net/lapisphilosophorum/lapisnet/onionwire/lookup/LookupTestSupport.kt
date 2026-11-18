package net.lapisphilosophorum.lapisnet.onionwire.lookup

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.libp2p.core.PeerId
import io.libp2p.core.crypto.KeyType
import io.libp2p.core.crypto.PrivKey
import io.libp2p.core.crypto.generateKeyPair
import net.lapisphilosophorum.lapisnet.storage.RemoteContentVerifier
import org.peergos.protocol.ipns.IPNS
import java.security.MessageDigest
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneOffset
import java.time.temporal.ChronoUnit

internal fun rawCid(bytes: ByteArray): Cid =
    Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, MessageDigest.getInstance("SHA-256").digest(bytes))

internal fun cidKey(cid: Cid): ByteArray = RemoteContentVerifier.rawSha256CidBytes(cid)!!

/** An Ed25519 IPNS publisher for tests: its routing key and a signed record. */
internal class TestIpnsPublisher(
    val key: PrivKey = generateKeyPair(KeyType.ED25519).first,
) {
    val peerId: PeerId = PeerId.fromPubKey(key.publicKey())
    val routingKey: ByteArray = RemoteContentVerifier.ipnsRoutingKey(peerId)

    fun record(
        value: ByteArray = "value".toByteArray(),
        sequence: Long = 1,
        notValidAfter: Instant = Instant.now().plusSeconds(3600),
    ): ByteArray {
        val expiry = LocalDateTime.ofInstant(notValidAfter.truncatedTo(ChronoUnit.SECONDS), ZoneOffset.UTC)
        return IPNS.createSignedRecord(value, expiry, sequence, 300_000_000_000L, key)
    }
}

/** Timer seam: tasks run when [advance] passes their due time. */
internal class ManualScheduler(
    private val clock: net.lapisphilosophorum.lapisnet.onionwire.WireTestClock,
) {
    private class Task(
        val due: Long,
        val task: Runnable,
    )

    private val tasks = ArrayList<Task>()

    fun schedule(
        delay: Long,
        task: Runnable,
    ): Boolean {
        synchronized(tasks) { tasks += Task(clock.millis + delay, task) }
        return true
    }

    /** Runs everything due within [millis] in due order, advancing the clock step by step. */
    fun advance(millis: Long) {
        val end = clock.millis + millis
        while (true) {
            val next =
                synchronized(tasks) {
                    tasks.filter { it.due <= end }.minByOrNull { it.due }?.also { tasks.remove(it) }
                } ?: break
            if (next.due > clock.millis) clock.millis = next.due
            next.task.run()
        }
        clock.millis = end
    }

    fun pending(): Int = synchronized(tasks) { tasks.size }
}
