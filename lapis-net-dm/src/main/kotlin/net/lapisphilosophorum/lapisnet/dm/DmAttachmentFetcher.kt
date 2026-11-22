package net.lapisphilosophorum.lapisnet.dm

import io.github.oshai.kotlinlogging.KotlinLogging
import io.ipfs.cid.Cid
import net.lapisphilosophorum.lapisnet.directory.MultiaddrHygiene
import net.lapisphilosophorum.lapisnet.directory.PeerDirectoryGossip
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import net.lapisphilosophorum.lapisnet.storage.NabuStorageException

private val logger = KotlinLogging.logger {}

/**
 * Resolves an attachment blob referenced by a [DmAttachmentRef.cid]: local blockstore first (via
 * [NabuStorage.getLocal] - no network, no [net.lapisphilosophorum.lapisnet.storage.NabuStorage.findProviders]
 * call), and if absent, a DIRECT Bitswap fetch against [sender]'s CURRENTLY-gossiped address via
 * [peerDirectory] - **NEVER `findProviders`**, mirroring [MailboxPoller.attemptOne]'s exact same
 * "broken DHT (until V0.9.8), use gossip + explicit peer hint instead" reasoning (see that method's own doc
 * comment).
 *
 * Address hygiene ([MultiaddrHygiene.isBlockedPrivateOrLocal]) is applied to every candidate
 * address before it is ever registered/dialed, exactly like [MailboxPoller.attemptOne].
 *
 * Returns `null` if no [peerDirectory] record exists for [sender] (no network call attempted at
 * all), every published address is filtered by [MultiaddrHygiene], or the fetch itself times out or
 * fails - a cross-node fetch is a genuine, documented limitation (mirrors `lapis-net-mail`'s
 * `MailApi.kt` attachment route's own "cross-node fetch is a known limitation" note), never a crash.
 */
object DmAttachmentFetcher {
    /**
     * Fetches [ref]'s blob (see [fetch]), decodes it ([EncryptedDmAttachmentBlobCodec.decode]),
     * decrypts it ([DmAttachmentCipher.decrypt] under [DmAttachmentRef.encryptionKey]), and verifies
     * the decrypted plaintext's length against [DmAttachmentRef.size] - the actual, reachable
     * implementation [DmAttachmentRef.size]'s own doc comment describes. Returns `null` for EVERY
     * failure mode (unreachable, malformed, undecryptable, or a plaintext whose length does not
     * match [ref]'s declared [DmAttachmentRef.size] - a lying or corrupted ref) - never throws,
     * mirroring [fetch]'s own "never a crash" contract.
     *
     * **Known limitation, unchanged from [fetch]:** the length check above runs only AFTER the full
     * blob has already been pulled into memory - [storage]'s Bitswap fetch has no max-block-size
     * parameter to bound the wire transfer itself by [ref]'s declared size ahead of time. This is
     * the exact same shape/limitation as `lapis-net-mail`'s existing `MailApi.kt` attachment-download
     * route (`deps.storage.get(found.cid)`, unbounded) - not a regression this wave introduces, but
     * also not fixed by it. The check just below (against
     * [EncryptedDmAttachmentBlobCodec.MAX_BLOB_BYTES]) rejects an oversized blob before it is ever
     * handed to [EncryptedDmAttachmentBlobCodec.decode], but cannot undo the memory already spent
     * receiving it.
     */
    fun fetchAndDecrypt(
        ref: DmAttachmentRef,
        sender: Secp256k1PublicKey,
        peerDirectory: PeerDirectoryGossip,
        storage: NabuStorage,
    ): ByteArray? {
        val blobBytes = fetch(ref.cid, sender, peerDirectory, storage) ?: return null
        return decryptVerified(ref, blobBytes)
    }

    /**
     * Wave Q21: the pure second half of [fetchAndDecrypt] - the [EncryptedDmAttachmentBlobCodec.MAX_BLOB_BYTES] check,
     * decode, decrypt under [DmAttachmentRef.encryptionKey] and the comparison with [DmAttachmentRef.size] - for bytes
     * that arrived some other way (anonymity mode: the sender's onion service). `null` for every failure, never throws.
     * Nothing it logs names the CID, the sender or the key: the anonymity-mode caller must not leave them in a log.
     */
    fun decryptVerified(
        ref: DmAttachmentRef,
        blobBytes: ByteArray,
    ): ByteArray? {
        if (blobBytes.size > EncryptedDmAttachmentBlobCodec.MAX_BLOB_BYTES) {
            logger.debug { "DM attachment blob exceeds MAX_BLOB_BYTES - rejecting" }
            return null
        }
        val blob =
            try {
                EncryptedDmAttachmentBlobCodec.decode(blobBytes)
            } catch (e: MalformedEncryptedDmAttachmentBlobException) {
                logger.debug { "DM attachment blob failed to decode - rejecting" }
                return null
            }
        val plaintext =
            try {
                DmAttachmentCipher.decrypt(blob, ref.encryptionKey)
            } catch (e: DmAttachmentDecryptionException) {
                logger.debug { "DM attachment blob failed to decrypt - rejecting" }
                return null
            }
        if (plaintext.size.toLong() != ref.size) {
            logger.debug { "DM attachment plaintext length differs from the declared size - rejecting" }
            return null
        }
        return plaintext
    }

    fun fetch(
        cid: Cid,
        sender: Secp256k1PublicKey,
        peerDirectory: PeerDirectoryGossip,
        storage: NabuStorage,
    ): ByteArray? {
        storage.getLocal(cid)?.let { return it }

        val senderRecord = peerDirectory.lookup(sender) ?: return null
        val safeAddresses = senderRecord.addresses.filterNot { MultiaddrHygiene.isBlockedPrivateOrLocal(it) }
        if (safeAddresses.isEmpty()) {
            logger.debug {
                "claimed DM-attachment sender ${sender.fingerprint()}'s published addresses are all " +
                    "wildcard/multicast - refusing to dial"
            }
            return null
        }

        return try {
            safeAddresses.forEach { address ->
                val addressWithP2P = runCatching { address.withP2P(senderRecord.peerId) }.getOrNull()
                if (addressWithP2P == null) {
                    logger.debug {
                        "claimed DM-attachment sender ${sender.fingerprint()}'s published address $address " +
                            "already carries a conflicting /p2p component - skipping just this address"
                    }
                } else {
                    storage.registerPeerAddress(addressWithP2P)
                }
            }
            storage.get(cid, peers = setOf(senderRecord.peerId))
        } catch (e: NabuStorageException) {
            logger.debug(
                e,
            ) { "DM attachment fetch for $cid from ${sender.fingerprint()} failed - treating as unavailable" }
            null
        }
    }
}
