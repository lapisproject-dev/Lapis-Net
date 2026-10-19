package net.lapisphilosophorum.lapisnet.directory

import io.github.oshai.kotlinlogging.KotlinLogging
import io.libp2p.core.PeerId
import io.libp2p.crypto.keys.unmarshalEd25519PublicKey
import net.lapisphilosophorum.lapisnet.identity.IdentityBinding
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.ratchet.MalformedPrekeyBundleException
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundle
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundleCodec
import net.lapisphilosophorum.lapisnet.ratchet.verifyEncryptionBinding
import net.lapisphilosophorum.lapisnet.ratchet.verifySignedPrekey
import net.lapisphilosophorum.lapisnet.storage.IpnsValue

private val logger = KotlinLogging.logger {}

/** A [DirectoryDhtValue] whose every part passed [DirectoryDhtValidator.validate]. */
internal class ValidatedDirectoryEntry(
    val identity: Secp256k1PublicKey,
    val peerRecord: PeerRecord?,
    val peerRecordBytes: ByteArray?,
    val prekeyBundle: PrekeyBundle?,
    val prekeyBundleBytes: ByteArray?,
)

/**
 * Checks a value that came out of the DHT, completely, before anything of it is used. Not a
 * gossip validator: it runs on the calling thread of [DirectoryDht] and reads the clock it is given.
 *
 * The chain of mutual proof, in the order it is checked:
 * 1. the IPNS record was signed by the Ed25519 key whose peer ID is `resolved.publisher` (checked by
 *    `NabuStorage.resolveIpnsValue` - nobody else could have written a value under that name);
 * 2. that peer ID is the one derived from `binding.ed25519PublicKey` - the value says which Ed25519
 *    key it speaks for, and it is the key that signed it;
 * 3. `binding` is a valid [IdentityBinding] by `identity` - the secp256k1 identity vouches for that key;
 * 4. `identity` is the one the caller asked for.
 * Together: the holder of the Ed25519 private key wrote a value naming the identity, and the identity
 * names that key. Then each part is checked with the same checks its gossip validator makes, plus that it
 * belongs to this identity (and for a peer record, to this binding) and has not expired.
 *
 * One part failing verification rejects the whole value: an envelope with a forged half is not trusted for
 * the other half. A part that is merely expired is dropped instead (the IPNS record outlives the earlier
 * part by up to the storage layer's clock-skew tolerance); only a value with no valid part left is rejected.
 */
internal object DirectoryDhtValidator {
    fun validate(
        resolved: IpnsValue,
        expectedIdentity: Secp256k1PublicKey,
        nowEpochSecond: Long,
    ): ValidatedDirectoryEntry? =
        try {
            validateOrThrow(resolved, expectedIdentity, nowEpochSecond)
        } catch (e: MalformedDirectoryDhtValueException) {
            logger.debug { "rejected a malformed directory value" }
            null
        } catch (e: MalformedPeerRecordException) {
            logger.debug { "rejected a directory value with a malformed peer record" }
            null
        } catch (e: MalformedPrekeyBundleException) {
            logger.debug { "rejected a directory value with a malformed prekey bundle" }
            null
        } catch (e: RuntimeException) {
            logger.debug { "rejected a directory value: ${e.javaClass.simpleName}" }
            null
        }

    private fun validateOrThrow(
        resolved: IpnsValue,
        expectedIdentity: Secp256k1PublicKey,
        nowEpochSecond: Long,
    ): ValidatedDirectoryEntry? {
        val value = DirectoryDhtValueCodec.decode(resolved.value)
        val identity = value.identity
        val binding = value.binding

        val bindingPeerId = PeerId.fromPubKey(unmarshalEd25519PublicKey(binding.ed25519PublicKey.bytes))
        if (resolved.publisher != bindingPeerId) return reject("publisher is not the binding's transport key")
        if (identity != expectedIdentity) return reject("value is for another identity")
        if (!IdentityBinding.verify(identity, binding)) return reject("identity binding does not verify")

        var peerRecord: PeerRecord? = null
        val peerRecordBytes = value.peerRecordBytes
        if (peerRecordBytes != null) {
            val record = PeerRecordCodec.decode(peerRecordBytes)
            if (!PeerRecord.verify(record)) return reject("peer record signature does not verify")
            if (!record.verifyBinding()) return reject("peer record binding does not verify")
            if (!record.verifyPossession()) return reject("peer record possession proof does not verify")
            if (record.identity != identity ||
                record.binding != binding
            ) {
                return reject("peer record is for another identity")
            }
            // an expired part is dropped, not fatal: the IPNS layer tolerates clock skew past the earlier expiry
            if (record.notValidAfterEpochSecond >= nowEpochSecond) peerRecord = record
        }

        var bundle: PrekeyBundle? = null
        val bundleBytes = value.prekeyBundleBytes
        if (bundleBytes != null) {
            val decoded = PrekeyBundleCodec.decode(bundleBytes)
            if (!PrekeyBundle.verify(decoded)) return reject("prekey bundle signature does not verify")
            if (!decoded.verifyEncryptionBinding()) return reject("prekey bundle encryption binding does not verify")
            if (!decoded.verifySignedPrekey()) return reject("prekey bundle signed prekey does not verify")
            if (decoded.identity != identity) return reject("prekey bundle is for another identity")
            if (decoded.notValidAfterEpochSecond >= nowEpochSecond) bundle = decoded
        }
        if (peerRecord == null && bundle == null) return reject("every part has expired")
        return ValidatedDirectoryEntry(
            identity,
            peerRecord,
            peerRecordBytes.takeIf { peerRecord != null },
            bundle,
            bundleBytes.takeIf { bundle != null },
        )
    }

    private fun reject(reason: String): ValidatedDirectoryEntry? {
        logger.debug { "rejected a directory value: $reason" }
        return null
    }
}
