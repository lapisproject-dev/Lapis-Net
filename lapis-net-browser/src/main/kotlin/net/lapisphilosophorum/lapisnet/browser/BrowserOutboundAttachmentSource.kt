package net.lapisphilosophorum.lapisnet.browser

import io.ipfs.cid.Cid
import net.lapisphilosophorum.lapisnet.dm.DmHistoryEntry
import net.lapisphilosophorum.lapisnet.dm.DmStore
import net.lapisphilosophorum.lapisnet.dm.EncryptedDmAttachmentBlobCodec
import net.lapisphilosophorum.lapisnet.dmonion.attachment.OutboundAttachment
import net.lapisphilosophorum.lapisnet.dmonion.attachment.OutboundAttachmentSource
import net.lapisphilosophorum.lapisnet.mail.EncryptedAttachmentBlobCodec
import net.lapisphilosophorum.lapisnet.mail.SentFolder

/**
 * What this node's onion service may hand out to attachment fetches (wave Q21, decision Q21-G): ONLY attachments it sent
 * itself and that carry a key - outbound direct messages of [dmStore] and mails of [sentFolder]. Received or foreign
 * blobs are never offered, so the node never becomes a holder of other people's content; an unencrypted mail attachment
 * has no key, hence no fetch token, and is not offered either.
 *
 * Derived per request from data that exists anyway: no new persisted state. At most [maxEntries] entries (newest
 * first per conversation, then the sent folder, newest first) are examined per lookup; an attachment older than that is
 * not found (an open bound, see docs/anonymity.adoc). The scan cost is limited by the server's request rate.
 */
class BrowserOutboundAttachmentSource(
    private val dmStore: DmStore,
    private val sentFolder: SentFolder,
    private val blob: (Cid) -> ByteArray?,
    private val maxEntries: Int = MAX_ENTRIES,
) : OutboundAttachmentSource {
    override fun find(cid: Cid): OutboundAttachment? {
        var examined = 0
        for (peer in dmStore.peers()) {
            for (entry in dmStore.historyFor(peer).asReversed()) {
                if (++examined > maxEntries) return null
                if (entry !is DmHistoryEntry.Outbound) continue
                val ref = entry.content.attachments.firstOrNull { it.cid == cid } ?: continue
                val declared = ref.size + EncryptedDmAttachmentBlobCodec.OVERHEAD_BYTES
                if (declared > Int.MAX_VALUE) return null
                return OutboundAttachment(ref.encryptionKey, declared.toInt()) { blob(cid) }
            }
        }
        for (sent in sentFolder.latest().asReversed()) {
            if (++examined > maxEntries) return null
            val ref = sent.body.attachments.firstOrNull { it.cid == cid } ?: continue
            val key = ref.encryptionKey ?: return null
            val declared = ref.size + EncryptedAttachmentBlobCodec.OVERHEAD_BYTES
            if (declared > Int.MAX_VALUE) return null
            return OutboundAttachment(key, declared.toInt()) { blob(cid) }
        }
        return null
    }

    companion object {
        const val MAX_ENTRIES = 10_000
    }
}
