package net.lapisphilosophorum.lapisnet.storage

import com.google.protobuf.InvalidProtocolBufferException
import crypto.pb.Crypto
import io.libp2p.core.PeerId
import io.libp2p.core.crypto.PrivKey
import io.libp2p.crypto.keys.unmarshalEd25519PublicKey
import org.peergos.protocol.ipns.IPNS
import org.peergos.protocol.ipns.pb.Ipns
import java.time.Duration
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneOffset
import java.time.format.DateTimeParseException
import java.time.temporal.ChronoUnit

/** A signed IPNS record that passed every check of [IpnsRecordCodec.validate]. */
internal class ValidatedIpnsRecord(
    val publisher: PeerId,
    val raw: ByteArray,
    val value: ByteArray,
    val sequence: Long,
    val notValidAfter: Instant,
    val ttl: Duration,
) {
    /** Higher sequence wins; at equal sequence the later expiry wins (as Nabu's `IpnsRecord.compareTo`). */
    fun isNewerThan(other: ValidatedIpnsRecord): Boolean =
        sequence > other.sequence || (sequence == other.sequence && notValidAfter.isAfter(other.notValidAfter))

    fun sameRecordAs(other: ValidatedIpnsRecord): Boolean = raw.contentEquals(other.raw)
}

/**
 * Creates and validates IPNS records (IPNS record spec v2, Ed25519 names only) without using Nabu's
 * `IPNS.parseAndValidateIpnsEntry`, which has three defects for this use (V0.9.13):
 * - it parses the signed `data` with Peergos' CBOR parser, which has no depth limit - a validly signed
 *   record of a few KiB with thousands of nested arrays overflows the stack;
 * - it compares the expiry with `LocalDateTime.now()`, i.e. in the machine's own time zone, so the
 *   expiry shifts by the UTC offset;
 * - its key handling (`Cid.cast`, `Multihash.deserialize`) allocates before it bounds-checks, and its
 *   record store is keyed in a way that does not find identity-multihash (Ed25519) names.
 *
 * [validate] never parses CBOR. It reads the signed fields from the protobuf, RE-ENCODES the CBOR a
 * correct signer would have produced (`IPNS.createCborDataForIpnsEntry`, deterministic) and requires it to be
 * byte-identical to the signed `data`. A `data` that is anything else - nested, padded, re-ordered - does
 * not match and is rejected unparsed. All time arithmetic is done in UTC on [Instant].
 */
internal object IpnsRecordCodec {
    private val MAX_TTL: Duration = Duration.ofDays(7)
    private const val SIGNATURE_BYTES = 64
    private const val MAX_VALIDITY_CHARS = 64
    private const val VALIDITY_TYPE_EOL = 0L
    private val SIGNATURE_PREFIX = "ipns-signature:".toByteArray(Charsets.UTF_8)

    /**
     * A signed record carrying [value], valid until [notValidAfter] (truncated to whole seconds).
     * Pure serialisation and signing, no network. Throws [IllegalArgumentException] for a non-Ed25519
     * key, an empty value, a negative sequence, a non-positive TTL or a record above [maxRecordBytes].
     */
    fun create(
        signingKey: PrivKey,
        value: ByteArray,
        sequence: Long,
        notValidAfter: Instant,
        ttl: Duration,
        maxRecordBytes: Int = IPNS_RECORD_HARD_LIMIT,
    ): ByteArray {
        require(signingKey.keyType == Crypto.KeyType.Ed25519) { "IPNS records are signed with Ed25519 only" }
        require(value.isNotEmpty()) { "value must not be empty" }
        require(sequence >= 0) { "sequence must not be negative" }
        require(!ttl.isNegative && !ttl.isZero && ttl <= MAX_TTL) { "ttl must be positive and at most $MAX_TTL" }
        val expiry = LocalDateTime.ofInstant(notValidAfter.truncatedTo(ChronoUnit.SECONDS), ZoneOffset.UTC)
        val record = IPNS.createSignedRecord(value, expiry, sequence, ttl.toNanos(), signingKey)
        require(record.size <= maxRecordBytes) { "signed record is ${record.size} bytes, limit is $maxRecordBytes" }
        return record
    }

    /**
     * Every check, cheapest first; `null` as soon as one fails. [now] is the caller's UTC clock
     * reading. The record is accepted only if its expiry lies in `[now - skew, now + maxRecordValidity + skew]`.
     */
    fun validate(
        key: ByteArray,
        recordBytes: ByteArray,
        now: Instant,
        limits: DhtLimits,
    ): ValidatedIpnsRecord? {
        if (recordBytes.size > limits.maxIpnsRecordBytes) return null
        val publisher = parseIpnsKey(key) ?: return null
        val entry =
            try {
                Ipns.IpnsEntry.parseFrom(recordBytes)
            } catch (_: InvalidProtocolBufferException) {
                return null
            } catch (_: RuntimeException) {
                return null
            }
        if (!entry.hasSignatureV2() || !entry.hasData()) return null
        if (entry.validityType != Ipns.IpnsEntry.ValidityType.EOL) return null
        if (entry.unknownFields.serializedSize != 0) return null
        if (entry.sequence < 0 || entry.ttl < 0) return null
        if (entry.value.isEmpty) return null
        if (entry.signatureV2.size() != SIGNATURE_BYTES) return null

        val validity = entry.validity.toByteArray()
        val expiry = parseValidity(validity) ?: return null
        val notValidAfter = expiry.toInstant(ZoneOffset.UTC)

        // The signed bytes must be exactly what a correct signer produces from the visible fields.
        val expected =
            IPNS.createCborDataForIpnsEntry(
                entry.value.toByteArray(),
                expiry,
                VALIDITY_TYPE_EOL,
                entry.sequence,
                entry.ttl,
            )
        if (!expected.contentEquals(entry.data.toByteArray())) return null

        if (entry.hasPubKey()) {
            val embedded = entry.pubKey.toByteArray()
            val derived = key.copyOfRange(IPNS_KEY_PROTOBUF_OFFSET, IPNS_KEY_SIZE)
            if (!embedded.contentEquals(derived)) return null
        }

        if (notValidAfter.isBefore(now.minus(limits.maxClockSkew))) return null
        if (notValidAfter.isAfter(now.plus(limits.maxRecordValidity).plus(limits.maxClockSkew))) return null

        val publicKey =
            runCatching { unmarshalEd25519PublicKey(key.copyOfRange(IPNS_KEY_RAW_OFFSET, IPNS_KEY_SIZE)) }
                .getOrNull() ?: return null
        val signed = SIGNATURE_PREFIX + entry.data.toByteArray()
        val signatureOk = runCatching { publicKey.verify(signed, entry.signatureV2.toByteArray()) }.getOrDefault(false)
        if (!signatureOk) return null

        return ValidatedIpnsRecord(
            publisher = publisher,
            raw = recordBytes.copyOf(),
            value = entry.value.toByteArray(),
            sequence = entry.sequence,
            notValidAfter = notValidAfter,
            ttl = Duration.ofNanos(entry.ttl),
        )
    }

    /**
     * The validity string (`yyyy-MM-dd'T'HH:mm:ss.nZ`, UTC) as a [LocalDateTime], or `null` unless it
     * is exactly the canonical form [IPNS.formatExpiry] would print for the date it names.
     */
    private fun parseValidity(bytes: ByteArray): LocalDateTime? {
        if (bytes.isEmpty() || bytes.size > MAX_VALIDITY_CHARS) return null
        if (bytes.any { it < 0x20 || it > 0x7E }) return null
        val text = String(bytes, Charsets.US_ASCII)
        if (!text.endsWith("Z")) return null
        val parsed =
            try {
                LocalDateTime.parse(text.dropLast(1), IPNS.rfc3339nano)
            } catch (_: DateTimeParseException) {
                return null
            }
        return if (IPNS.formatExpiry(parsed) == text) parsed else null
    }
}
