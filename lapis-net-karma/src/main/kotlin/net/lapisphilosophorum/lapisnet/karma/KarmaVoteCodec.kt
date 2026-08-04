package net.lapisphilosophorum.lapisnet.karma

import io.ipfs.cid.Cid
import net.lapisphilosophorum.lapisnet.core.cid.CidBytesValidation
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.IOException
import java.security.MessageDigest

/**
 * Thrown when decoding a [KarmaVote]'s canonical byte encoding fails structurally (bad magic,
 * unsupported version, truncated/overrun buffer, out-of-range field, unknown anchor type). Never
 * thrown for signature verification failures - [KarmaVoteCodec.decode] does not verify signatures,
 * see its doc comment. Mirrors
 * [net.lapisphilosophorum.lapisnet.virtus.MalformedLtrRecordException]'s established
 * same-file-as-its-codec organization.
 */
class MalformedKarmaVoteException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/** Anchor-type discriminator byte for [NoAnchorClaim] - see [KarmaVoteCodec]'s class doc comment. */
private const val ANCHOR_TYPE_NONE: Byte = 0

/** Anchor-type discriminator byte for [ChainAnchorClaim] - see [KarmaVoteCodec]'s class doc comment. */
private const val ANCHOR_TYPE_CHAIN: Byte = 1

/** Exact encoded length of a [ChainAnchorClaim]'s anchor bytes:
 * `genesisTxid(32) | genesisBlockHeight(4) | tipHeightAtVote(4)`. */
private const val CHAIN_ANCHOR_BYTES_SIZE = 40
private const val BTC_TXID_SIZE = 32

/**
 * Canonical, deterministic byte encoding for [KarmaVote] - used both to build the digest that gets
 * signed and to compute a vote's content id (the gossip dedup key, see [KarmaVoteIndex]). Mirrors
 * [net.lapisphilosophorum.lapisnet.virtus.LtrRecordCodec]'s sequential length-prefixed layout and
 * big-endian integer convention exactly.
 *
 * Layout of [encodeSignedBody]'s output: `magic(4="LNKV") | version(1) | voter(33) | cidLen(2) |
 * cid(cidLen) | timestampSeconds(8) | anchorType(1) | anchorLen(2) | anchorBytes(anchorLen) |
 * nonce(8)`. [encode] appends the 64-byte signature after that.
 *
 * `anchorType = 0` ([ANCHOR_TYPE_NONE]) is [NoAnchorClaim] - `anchorLen` MUST be `0` (a zero-length
 * body). `anchorType = 1` ([ANCHOR_TYPE_CHAIN]) is [ChainAnchorClaim] - `anchorLen` MUST be exactly
 * [CHAIN_ANCHOR_BYTES_SIZE] (40). Any other `anchorType` byte is rejected outright by [decode] -
 * never silently accepted as opaque bytes, mirroring [net.lapisphilosophorum.lapisnet.virtus.LtrRecordCodec]'s
 * identical discipline for its own `proofType` byte.
 */
object KarmaVoteCodec {
    private val MAGIC = "LNKV".toByteArray(Charsets.US_ASCII)
    private const val VERSION: Byte = 1
    private const val PUBLIC_KEY_SIZE = 33
    private const val SIGNATURE_SIZE = 64
    private const val NONCE_SIZE = 8

    /** Cap on an encoded CID's byte length - mirrors
     * [net.lapisphilosophorum.lapisnet.virtus.LtrRecordCodec.MAX_CID_BYTES] exactly. */
    const val MAX_CID_BYTES = 128

    /** Cap on an encoded anchor's byte length - generous headroom above [CHAIN_ANCHOR_BYTES_SIZE]
     * (40), mirroring [net.lapisphilosophorum.lapisnet.virtus.LtrRecordCodec.MAX_PROOF_BYTES]'s
     * reasoning (bounded well below [MAX_BODY_SIZE], not derived from any specific future need). */
    const val MAX_ANCHOR_BYTES = 256

    /** [domainSeparatedDigest][net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest]
     * treats the whole signed body as a single part, capped at this size - mirrors
     * [net.lapisphilosophorum.lapisnet.virtus.LtrRecordCodec.MAX_BODY_SIZE]'s reasoning. Worst case
     * here is tiny (magic+version+voter+cid+timestamp+anchor header+[MAX_ANCHOR_BYTES]+nonce well
     * under 1 KB), well under the limit. */
    const val MAX_BODY_SIZE = 0xFFFF

    /** Builds the exact bytes that get domain-separated-digested and signed - see
     * [KarmaVote.Companion.create]. */
    fun encodeSignedBody(
        voter: Secp256k1PublicKey,
        targetCid: Cid,
        timestampSeconds: Long,
        timeAnchor: TimeAnchorClaim,
        nonce: ByteArray,
    ): ByteArray {
        require(nonce.size == NONCE_SIZE) { "nonce must be exactly $NONCE_SIZE bytes" }
        val cidBytes = targetCid.toBytes()
        require(cidBytes.size in 1..MAX_CID_BYTES) { "cid must be 1..$MAX_CID_BYTES bytes, was ${cidBytes.size}" }

        val (anchorType, anchorBytes) = encodeAnchor(timeAnchor)
        require(anchorBytes.size <= MAX_ANCHOR_BYTES) {
            "encoded anchor exceeds $MAX_ANCHOR_BYTES bytes: ${anchorBytes.size}"
        }

        val out = ByteArrayOutputStream()
        DataOutputStream(out).apply {
            write(MAGIC)
            writeByte(VERSION.toInt())
            write(voter.bytes)
            writeShort(cidBytes.size)
            write(cidBytes)
            writeLong(timestampSeconds)
            writeByte(anchorType.toInt())
            writeShort(anchorBytes.size)
            write(anchorBytes)
            write(nonce)
        }
        val body = out.toByteArray()
        require(body.size <= MAX_BODY_SIZE) { "encoded vote body exceeds $MAX_BODY_SIZE bytes: ${body.size}" }
        return body
    }

    /** As the other [encodeSignedBody] overload, pulling fields off an existing [vote]. */
    fun encodeSignedBody(vote: KarmaVote): ByteArray =
        encodeSignedBody(
            voter = vote.voter,
            targetCid = vote.targetCid,
            timestampSeconds = vote.timestampSeconds,
            timeAnchor = vote.timeAnchor,
            nonce = vote.nonce,
        )

    /** The full canonical artifact: signed body followed by the 64-byte signature. This is what
     * [KarmaGossip] hands to `NabuStorage.put()` and publishes over GossipSub, and the preimage of
     * [contentId]. */
    fun encode(vote: KarmaVote): ByteArray = encodeSignedBody(vote) + vote.signature

    /** Plain (not domain-separated) SHA-256 of [encode] - the gossip dedup / index lookup key, not
     * itself a signed value. */
    fun contentId(vote: KarmaVote): ByteArray = sha256(encode(vote))

    /**
     * Structural decode only - does **not** verify the signature, matching
     * [net.lapisphilosophorum.lapisnet.virtus.LtrRecordCodec.decode]'s exact contract. A vote
     * typically arrives from an untrusted peer over gossip; callers must explicitly call
     * [KarmaVote.Companion.verify] before trusting it.
     *
     * @throws MalformedKarmaVoteException if the bytes are structurally invalid, including an
     * out-of-range field, trailing bytes after the signature, or an unrecognized `anchorType` -
     * every value other than [ANCHOR_TYPE_NONE]/[ANCHOR_TYPE_CHAIN] is rejected immediately, never
     * silently accepted.
     */
    fun decode(bytes: ByteArray): KarmaVote {
        try {
            val input = DataInputStream(ByteArrayInputStream(bytes))

            val magic = ByteArray(MAGIC.size).also { input.readFully(it) }
            if (!magic.contentEquals(MAGIC)) throw MalformedKarmaVoteException("bad magic")

            val version = input.readByte()
            if (version != VERSION) throw MalformedKarmaVoteException("unsupported version $version")

            val voterBytes = ByteArray(PUBLIC_KEY_SIZE).also { input.readFully(it) }

            val cidLen = input.readUnsignedShort()
            if (cidLen !in 1..MAX_CID_BYTES) throw MalformedKarmaVoteException("invalid CID length: $cidLen")
            val cidBytes = ByteArray(cidLen).also { input.readFully(it) }
            // Field-length cap above bounds the WIRE bytes for this field, not the multihash length
            // declared INSIDE those bytes - see CidBytesValidation's class doc comment for why
            // Cid.cast() must never see bytes that fail this check.
            if (!CidBytesValidation.isSafeToCast(cidBytes)) {
                throw MalformedKarmaVoteException("cid declares an unsafe multihash length")
            }

            val timestampSeconds = input.readLong()

            val anchorType = input.readByte()
            val anchorLen = input.readUnsignedShort()
            if (anchorLen > MAX_ANCHOR_BYTES) throw MalformedKarmaVoteException("anchor too long: $anchorLen")
            val anchorBytes = ByteArray(anchorLen).also { input.readFully(it) }
            val timeAnchor = decodeAnchor(anchorType, anchorBytes)

            val nonce = ByteArray(NONCE_SIZE).also { input.readFully(it) }

            val signature = ByteArray(SIGNATURE_SIZE).also { input.readFully(it) }
            if (input.available() > 0) throw MalformedKarmaVoteException("trailing bytes after signature")

            return KarmaVote.fromDecoded(
                voter = Secp256k1PublicKey(voterBytes),
                targetCid = Cid.cast(cidBytes),
                timestampSeconds = timestampSeconds,
                timeAnchor = timeAnchor,
                nonce = nonce,
                signature = signature,
            )
        } catch (e: EOFException) {
            throw MalformedKarmaVoteException("truncated vote bytes", e)
        } catch (e: IOException) {
            throw MalformedKarmaVoteException("failed to decode vote", e)
        } catch (e: MalformedKarmaVoteException) {
            throw e
        } catch (e: OutOfMemoryError) {
            // Defense in depth, independent of CidBytesValidation.isSafeToCast's guard above: if
            // some other unforeseen path ever attempts an oversized allocation while decoding a
            // vote, this must still surface as a clean malformed-input rejection, never an Error
            // escaping to KarmaGossip.onGossipMessage's caller. Deliberately narrow - only
            // OutOfMemoryError, not a blanket Throwable/Error catch, which would risk masking a
            // real JVM problem unrelated to this decode call.
            throw MalformedKarmaVoteException("vote field declared an oversized allocation", e)
        } catch (e: RuntimeException) {
            // Covers IllegalArgumentException from KarmaVote's/ChainAnchorClaim's own constructor
            // validation and io.ipfs.cid.Cid.CidEncodingException from Cid.cast() on malformed CID
            // bytes - decode() must never leak an arbitrary third-party exception type to callers.
            throw MalformedKarmaVoteException("invalid vote field", e)
        }
    }

    private fun encodeAnchor(anchor: TimeAnchorClaim): Pair<Byte, ByteArray> =
        when (anchor) {
            is NoAnchorClaim -> ANCHOR_TYPE_NONE to ByteArray(0)
            is ChainAnchorClaim -> {
                val out = ByteArrayOutputStream()
                DataOutputStream(out).apply {
                    write(anchor.genesisTxid)
                    writeInt(anchor.genesisBlockHeight)
                    writeInt(anchor.tipHeightAtVote)
                }
                ANCHOR_TYPE_CHAIN to out.toByteArray()
            }
        }

    private fun decodeAnchor(
        anchorType: Byte,
        anchorBytes: ByteArray,
    ): TimeAnchorClaim =
        when (anchorType) {
            ANCHOR_TYPE_NONE -> {
                if (anchorBytes.isNotEmpty()) {
                    throw MalformedKarmaVoteException(
                        "NoAnchorClaim payload must be zero-length, was ${anchorBytes.size}",
                    )
                }
                NoAnchorClaim
            }
            ANCHOR_TYPE_CHAIN -> {
                if (anchorBytes.size != CHAIN_ANCHOR_BYTES_SIZE) {
                    throw MalformedKarmaVoteException(
                        "ChainAnchorClaim payload must be exactly $CHAIN_ANCHOR_BYTES_SIZE bytes, " +
                            "was ${anchorBytes.size}",
                    )
                }
                val txid = anchorBytes.copyOfRange(0, BTC_TXID_SIZE)
                val heightsInput = DataInputStream(ByteArrayInputStream(anchorBytes, BTC_TXID_SIZE, 8))
                val genesisBlockHeight = heightsInput.readInt()
                val tipHeightAtVote = heightsInput.readInt()
                ChainAnchorClaim(genesisBlockHeight, txid, tipHeightAtVote)
            }
            else -> throw MalformedKarmaVoteException("unknown or unsupported anchorType: $anchorType")
        }

    private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)
}
