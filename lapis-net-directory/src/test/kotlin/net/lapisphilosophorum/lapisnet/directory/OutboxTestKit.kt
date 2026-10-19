package net.lapisphilosophorum.lapisnet.directory

import io.ipfs.cid.Cid
import io.libp2p.core.PeerId
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.storage.NabuStorageException
import java.time.Instant
import java.util.Random

internal fun newKey(): Secp256k1PublicKey = DualKeyIdentity.generate().secp256k1KeyPair.publicKey

private val kitRandom = Random(7)

/** An outbox entry with a random opaque payload of [payloadSize] bytes. */
internal fun outboxEntry(
    recipient: Secp256k1PublicKey = newKey(),
    kind: OutboxEntryKind = OutboxEntryKind.DM_MAILBOX_POINTER,
    expiresInSeconds: Long = 3600,
    payloadSize: Int = 200,
): OutboxEntry =
    OutboxEntry(
        kind,
        recipient,
        Instant.now().epochSecond + expiresInSeconds,
        ByteArray(payloadSize).also { kitRandom.nextBytes(it) },
    )

/** A [DirectoryDhtValue] of [publisher] carrying [entries] (and, by default, no directory parts). */
internal fun DirectoryPublisher.valueWithOutbox(
    entries: List<OutboxEntry>,
    withRecord: Boolean = false,
    withBundle: Boolean = false,
): DirectoryDhtValue {
    val record = if (withRecord) PeerRecordCodec.encode(peerRecord()) else null
    val bundleBytes =
        if (withBundle) {
            net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundleCodec
                .encode(bundle())
        } else {
            null
        }
    return DirectoryDhtValue(key, identity.binding, record, bundleBytes, entries)
}

/** A perfectly reliable fake of the rendezvous provider records, counting its calls. */
internal class FakeRendezvousStore : RendezvousStore {
    val provided = mutableListOf<Cid>()
    val findCalls = mutableListOf<Cid>()
    val providers = HashMap<Cid, MutableSet<PeerId>>()
    var failProvideFor: Set<Cid> = emptySet()
    var failFind: Boolean = false
    var provideResult: Int = 3

    override fun provide(
        cid: Cid,
        timeout: java.time.Duration,
    ): Int {
        if (cid in failProvideFor) throw NabuStorageException("provide failed")
        provided += cid
        providers.getOrPut(cid) { HashSet() }
        return provideResult
    }

    override fun findProviders(
        cid: Cid,
        max: Int,
        timeout: java.time.Duration,
    ): Set<PeerId> {
        findCalls += cid
        if (failFind) throw NabuStorageException("find failed")
        return providers[cid].orEmpty().take(max).toSet()
    }
}
