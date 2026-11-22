package net.lapisphilosophorum.lapisnet.browser

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.dm.DmAttachmentRef
import net.lapisphilosophorum.lapisnet.dm.DmContent
import net.lapisphilosophorum.lapisnet.dm.DmDeliveryState
import net.lapisphilosophorum.lapisnet.dm.DmInboundMessage
import net.lapisphilosophorum.lapisnet.dm.DmStore
import net.lapisphilosophorum.lapisnet.dm.EncryptedDmAttachmentBlobCodec
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.mail.AttachmentRef
import net.lapisphilosophorum.lapisnet.mail.EncryptedAttachmentBlobCodec
import net.lapisphilosophorum.lapisnet.mail.MailFrameCodec
import net.lapisphilosophorum.lapisnet.mail.MessageBody
import net.lapisphilosophorum.lapisnet.mail.MessageBodyCodec
import net.lapisphilosophorum.lapisnet.mail.MessageEnvelope
import net.lapisphilosophorum.lapisnet.mail.MessageEnvelopeCodec
import net.lapisphilosophorum.lapisnet.mail.SentFolder
import net.lapisphilosophorum.lapisnet.mail.SentMessage
import java.time.Instant

class BrowserOutboundAttachmentSourceTest :
    FunSpec({
        val me = DualKeyIdentity.generate()
        val peer = DualKeyIdentity.generate().secp256k1KeyPair.publicKey

        fun dmRef(n: Int) =
            DmAttachmentRef(
                rawCidOf(byteArrayOf(n.toByte())),
                "f$n",
                "text/plain",
                100L + n,
                ByteArray(32) {
                    n.toByte()
                },
            )

        test("finds only this node's own outbound DM and mail attachments that carry a key") {
            val dmStore = DmStore()
            val outbound = dmRef(1)
            val inbound = dmRef(2)
            dmStore.recordOutbound(peer, DmContent("o", listOf(outbound)), DmDeliveryState.SENT)
            dmStore.recordInbound(
                DmInboundMessage(
                    peer,
                    ByteArray(0),
                    DmContent("i", listOf(inbound)),
                    false,
                    ByteArray(1),
                    Instant.now().epochSecond,
                ),
            )

            val sentFolder = SentFolder()
            val keyed =
                AttachmentRef(rawCidOf(byteArrayOf(3)), "m", "text/plain", 50, encryptionKey = ByteArray(32) { 3 })
            val plain = AttachmentRef(rawCidOf(byteArrayOf(4)), "p", "text/plain", 60)
            val body = MessageBody("s", "b", listOf(keyed, plain))
            val bodyBytes = MessageBodyCodec.encode(body)
            val envelope = MessageEnvelope.create(me.secp256k1KeyPair, listOf(peer), MessageBodyCodec.cidFor(bodyBytes))
            sentFolder.add(
                SentMessage(
                    envelope,
                    body,
                    MessageBodyCodec.cidFor(bodyBytes),
                    null,
                    MailFrameCodec.encode(MessageEnvelopeCodec.encode(envelope), bodyBytes),
                ),
            )
            val loads = mutableListOf<io.ipfs.cid.Cid>()
            val source =
                BrowserOutboundAttachmentSource(dmStore, sentFolder, { cid ->
                    loads += cid
                    ByteArray(1)
                })

            val found = source.find(outbound.cid).shouldNotBeNull()
            found.attachmentKey shouldBe outbound.encryptionKey
            found.declaredBlobBytes shouldBe (101 + EncryptedDmAttachmentBlobCodec.OVERHEAD_BYTES)
            loads.size shouldBe 0 // nothing is loaded before admission
            found.loadBlob()
            loads shouldBe listOf(outbound.cid)

            source.find(inbound.cid).shouldBeNull()
            val mail = source.find(keyed.cid).shouldNotBeNull()
            mail.declaredBlobBytes shouldBe (50 + EncryptedAttachmentBlobCodec.OVERHEAD_BYTES)
            source.find(plain.cid).shouldBeNull()
            source.find(rawCidOf(byteArrayOf(9))).shouldBeNull()
            found.toString() shouldBe "OutboundAttachment(REDACTED)"
        }

        test("the scan stops after maxEntries entries") {
            val dmStore = DmStore()
            val old = dmRef(1)
            dmStore.recordOutbound(peer, DmContent("old", listOf(old)), DmDeliveryState.SENT)
            repeat(5) { dmStore.recordOutbound(peer, DmContent("n$it"), DmDeliveryState.SENT) }
            BrowserOutboundAttachmentSource(
                dmStore,
                SentFolder(),
                { null },
                maxEntries = 6,
            ).find(old.cid).shouldNotBeNull()
            BrowserOutboundAttachmentSource(
                dmStore,
                SentFolder(),
                { null },
                maxEntries = 5,
            ).find(old.cid).shouldBeNull()
        }
    })
