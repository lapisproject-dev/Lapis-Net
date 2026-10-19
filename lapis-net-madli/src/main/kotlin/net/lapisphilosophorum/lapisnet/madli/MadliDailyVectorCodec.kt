package net.lapisphilosophorum.lapisnet.madli

import io.libp2p.core.PeerId
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.IOException
import java.security.MessageDigest

/**
 * Thrown when decoding a [MadliDailyVector]'s canonical byte encoding fails structurally (bad
 * magic, unsupported version, truncated/overrun buffer, out-of-range field, malformed `PeerId`
 * bytes). Never thrown for signature verification failures - [MadliDailyVectorCodec.decode] does
 * not verify signatures, see its doc comment. Mirrors `MalformedKarmaVoteException`'s established
 * same-file-as-its-codec organization.
 */
class MalformedMadliDailyVectorException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/**
 * Canonical, deterministic byte encoding for [MadliDailyVector] - used both to build the digest
 * that gets signed and to compute a vector's content id (the gossip dedup key, see
 * [MadliVectorIndex]). Mirrors `KarmaVoteCodec`'s sequential length-prefixed layout and
 * big-endian integer convention exactly.
 *
 * Layout of [encodeSignedBody]'s output: `magic(4="LNMV") | version(1) | observer(33) |
 * peerIdLen(2) | peerId(peerIdLen) | epochDay(8) | reachabilityMicros(4) |
 * medianBandwidthBytesPerSec(8) | medianLatencyMillis(4) | deliveryIntegrityMicros(4) |
 * routingHelpfulnessMicros(4) | observationCount(4)`. [encode] appends the 64-byte signature
 * after that.
 *
 * **Wire format v2 (relay reliability, V0.9.12).** `magic | version=2 | observer(33) |
 * peerIdLen(2) | peerId | epochDay(8) | flags(1) | [core block, iff bit0] | [relay block, iff
 * bit1] | signature(64)`. The core block is exactly v1's six metric fields; the relay block is
 * `relayReliabilityMicros(4) | relayAttemptCount(4)`. **Canonical encoding = exactly one encoding
 * per statement:** a vector with core metrics only is ALWAYS v1 (so v1 stays byte-identical to
 * what v0.10.1 wrote and validates), and a v2 vector must carry the relay block. The decoder
 * rejects unknown flag bits, `flags == 0`, and v2 with `flags == bit0` (non-canonical), so no two
 * different byte strings (and hence content ids) express the same statement.
 *
 * **`epochDay` is NOT range-checked against wall-clock time here - deliberate.** This codec is
 * used by [MadliGossip]'s validator, which must be clock-independent and deterministic (see that
 * class's doc comment). A negative or absurd `epochDay` is structurally accepted at decode time; it
 * is defused at read time by [MadliDecayCalculator]/[MadliAggregator] (future-dated vectors clamp
 * to a decay factor of exactly 1.0, never more) and bounded by [MadliVectorIndex]'s per-pair
 * distinct-day cap (invariant B).
 */
object MadliDailyVectorCodec {
    private val MAGIC = "LNMV".toByteArray(Charsets.US_ASCII)
    const val VERSION_V1: Byte = 1
    const val VERSION_V2: Byte = 2
    private const val FLAG_CORE = 0x01
    private const val FLAG_RELAY = 0x02
    private const val KNOWN_FLAGS = FLAG_CORE or FLAG_RELAY
    private const val PUBLIC_KEY_SIZE = 33
    private const val SIGNATURE_SIZE = 64

    /** Cap on an encoded libp2p `PeerId`'s byte length. A real Ed25519/identity-multihash libp2p
     * `PeerId` is ~34-38 bytes (and the `PeerId` constructor itself hard-rejects anything outside
     * 32..50 bytes) - 128 is generous headroom above that, mirroring
     * `KarmaVoteCodec.MAX_CID_BYTES`'s "generous headroom, not derived from a specific future
     * need" reasoning. */
    const val MAX_PEER_ID_BYTES = 128

    /** [domainSeparatedDigest][net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest]
     * treats the whole signed body as a single part, capped at this size - mirrors
     * `KarmaVoteCodec.MAX_BODY_SIZE`'s reasoning. This body's worst case (magic+version+observer+
     * peerIdLen+MAX_PEER_ID_BYTES+epochDay+five metric fields) is well under 1 KB, far under the
     * limit. */
    const val MAX_BODY_SIZE = 0xFFFF

    /** Builds the exact bytes that get domain-separated-digested and signed - see
     * [MadliDailyVector.Companion.create]. Core-only input yields the byte-identical v1 layout;
     * any input with [relayMetrics] yields v2. */
    fun encodeSignedBody(
        observer: Secp256k1PublicKey,
        observedPeer: PeerId,
        epochDay: Long,
        metrics: MadliMetrics?,
        relayMetrics: MadliRelayMetrics?,
    ): ByteArray {
        require(metrics != null || relayMetrics != null) { "vector must carry core metrics, relay metrics, or both" }
        val peerIdBytes = observedPeer.bytes
        require(peerIdBytes.size in 1..MAX_PEER_ID_BYTES) {
            "peer id must be 1..$MAX_PEER_ID_BYTES bytes, was ${peerIdBytes.size}"
        }
        val isV1 = relayMetrics == null

        val out = ByteArrayOutputStream()
        DataOutputStream(out).apply {
            write(MAGIC)
            writeByte((if (isV1) VERSION_V1 else VERSION_V2).toInt())
            write(observer.bytes)
            writeShort(peerIdBytes.size)
            write(peerIdBytes)
            writeLong(epochDay)
            if (!isV1) {
                writeByte((if (metrics != null) FLAG_CORE or FLAG_RELAY else FLAG_RELAY))
            }
            if (metrics != null) {
                writeInt(metrics.reachabilityMicros)
                writeLong(metrics.medianBandwidthBytesPerSec)
                writeInt(metrics.medianLatencyMillis)
                writeInt(metrics.deliveryIntegrityMicros)
                writeInt(metrics.routingHelpfulnessMicros)
                writeInt(metrics.observationCount)
            }
            if (relayMetrics != null) {
                writeInt(relayMetrics.relayReliabilityMicros)
                writeInt(relayMetrics.relayAttemptCount)
            }
        }
        val body = out.toByteArray()
        require(body.size <= MAX_BODY_SIZE) { "encoded vector body exceeds $MAX_BODY_SIZE bytes: ${body.size}" }
        return body
    }

    /** As the other [encodeSignedBody] overload, pulling fields off an existing [vector]. */
    fun encodeSignedBody(vector: MadliDailyVector): ByteArray =
        encodeSignedBody(
            observer = vector.observer,
            observedPeer = vector.observedPeer,
            epochDay = vector.epochDay,
            metrics = vector.metrics,
            relayMetrics = vector.relayMetrics,
        )

    /** The full canonical artifact: signed body followed by the 64-byte signature. This is what
     * [MadliGossip] hands to `NabuStorage.put()` and publishes over GossipSub, and the preimage of
     * [contentId]. */
    fun encode(vector: MadliDailyVector): ByteArray = encodeSignedBody(vector) + vector.signature

    /** Plain (not domain-separated) SHA-256 of [encode] - the gossip dedup / index lookup key,
     * not itself a signed value. A fresh [MessageDigest] instance is created per call -
     * [MessageDigest] is not thread-safe. */
    fun contentId(vector: MadliDailyVector): ByteArray = sha256(encode(vector))

    /**
     * Structural decode only - does **not** verify the signature, matching
     * `KarmaVoteCodec.decode`'s exact contract. A vector typically arrives from an untrusted peer
     * over gossip; callers must explicitly call [MadliDailyVector.Companion.verify] before
     * trusting it.
     *
     * @throws MalformedMadliDailyVectorException if the bytes are structurally invalid, including
     * an out-of-range field, trailing bytes after the signature, or a malformed `PeerId`.
     */
    fun decode(bytes: ByteArray): MadliDailyVector {
        try {
            val input = DataInputStream(ByteArrayInputStream(bytes))

            val magic = ByteArray(MAGIC.size).also { input.readFully(it) }
            if (!magic.contentEquals(MAGIC)) throw MalformedMadliDailyVectorException("bad magic")

            val version = input.readByte()
            if (version != VERSION_V1 && version != VERSION_V2) {
                throw MalformedMadliDailyVectorException("unsupported version $version")
            }

            val observerBytes = ByteArray(PUBLIC_KEY_SIZE).also { input.readFully(it) }

            val peerIdLen = input.readUnsignedShort()
            if (peerIdLen !in 1..MAX_PEER_ID_BYTES) {
                throw MalformedMadliDailyVectorException("invalid peer id length: $peerIdLen")
            }
            val peerIdBytes = ByteArray(peerIdLen).also { input.readFully(it) }

            val epochDay = input.readLong()

            val hasCore: Boolean
            val hasRelay: Boolean
            if (version == VERSION_V1) {
                hasCore = true
                hasRelay = false
            } else {
                val flags = input.readUnsignedByte()
                if (flags and KNOWN_FLAGS.inv() != 0) {
                    throw MalformedMadliDailyVectorException("unknown flag bits: $flags")
                }
                if (flags == 0) throw MalformedMadliDailyVectorException("v2 vector with no blocks")
                hasCore = flags and FLAG_CORE != 0
                hasRelay = flags and FLAG_RELAY != 0
                if (!hasRelay) {
                    throw MalformedMadliDailyVectorException("non-canonical v2 vector without relay block")
                }
            }

            val metrics =
                if (hasCore) {
                    MadliMetrics(
                        reachabilityMicros = input.readInt(),
                        medianBandwidthBytesPerSec = input.readLong(),
                        medianLatencyMillis = input.readInt(),
                        deliveryIntegrityMicros = input.readInt(),
                        routingHelpfulnessMicros = input.readInt(),
                        observationCount = input.readInt(),
                    )
                } else {
                    null
                }
            val relayMetrics =
                if (hasRelay) {
                    MadliRelayMetrics(
                        relayReliabilityMicros = input.readInt(),
                        relayAttemptCount = input.readInt(),
                    )
                } else {
                    null
                }

            val signature = ByteArray(SIGNATURE_SIZE).also { input.readFully(it) }
            if (input.available() > 0) throw MalformedMadliDailyVectorException("trailing bytes after signature")

            return MadliDailyVector.fromDecoded(
                observer = Secp256k1PublicKey(observerBytes),
                observedPeer = PeerId(peerIdBytes),
                epochDay = epochDay,
                metrics = metrics,
                relayMetrics = relayMetrics,
                signature = signature,
            )
        } catch (e: EOFException) {
            throw MalformedMadliDailyVectorException("truncated vector bytes", e)
        } catch (e: IOException) {
            throw MalformedMadliDailyVectorException("failed to decode vector", e)
        } catch (e: MalformedMadliDailyVectorException) {
            throw e
        } catch (e: RuntimeException) {
            // Covers IllegalArgumentException from MadliMetrics's/Secp256k1PublicKey's own
            // constructor validation and IllegalArgumentException from PeerId's constructor (its
            // 32..50-byte length check) - decode() must never leak an arbitrary third-party
            // exception type to callers.
            throw MalformedMadliDailyVectorException("invalid vector field", e)
        }
    }

    private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)
}
