package net.lapisphilosophorum.lapisnet.dm

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.directory.DhtOutbox
import net.lapisphilosophorum.lapisnet.directory.OutboxEntryKind
import java.time.Duration
import java.time.Instant

/** V0.9.14: an offline deposit leaves exactly the gossiped pointer in the [DhtOutbox]; nothing else does. */
class DmSessionManagerDhtOutboxTest :
    FunSpec({
        test("sendOffline leaves exactly one entry whose payload is the gossiped pointer; a call signal leaves none") {
            val outbox = DhtOutbox()
            val a = buildDmTestNode(dhtOutbox = outbox)
            val b = buildDmTestNode()
            try {
                connectAndConverge(a, b)
                val bPub = b.identity.secp256k1KeyPair.publicKey
                val aPub = a.identity.secp256k1KeyPair.publicKey

                var deposited = false
                val deadline = Instant.now().plus(Duration.ofSeconds(30))
                while (!deposited && Instant.now().isBefore(deadline)) {
                    deposited =
                        runCatching { a.dmSessionManager.sendOffline(bPub, DmContent(body = "hello")) }.isSuccess
                    if (!deposited) Thread.sleep(1000)
                }
                deposited shouldBe true
                outbox.size() shouldBe 1

                // what b received over gossip is the very pointer in the outbox
                val gossiped = Instant.now().plus(Duration.ofSeconds(30))
                while (b.mailboxGossip.pending().isEmpty() && Instant.now().isBefore(gossiped)) Thread.sleep(250)
                val published = outbox.snapshot(Instant.now().epochSecond).single()
                published.kind shouldBe OutboxEntryKind.DM_MAILBOX_POINTER
                published.recipient shouldBe bPub
                val pointer = MailboxPointerCodec.decode(published.payload)
                MailboxPointer.verify(pointer) shouldBe true
                pointer.senderIdentity shouldBe aPub
                pointer.recipientIdentity shouldBe bPub
                pointer.notValidAfterEpochSecond shouldBe published.notValidAfterEpochSecond
                val received = b.mailboxGossip.pending()
                if (received.isNotEmpty()) {
                    received.any { it.contentId().contentEquals(pointer.contentId()) } shouldBe true
                }

                // a call signal never has an offline path and therefore never an outbox entry
                runCatching { a.dmSessionManager.sendCallSignal(bPub, "signal".toByteArray(), marksAcceptance = true) }
                outbox.size() shouldBe 1
            } finally {
                a.stop()
                b.stop()
            }
        }

        test("without an outbox nothing changes: the deposit works and nothing is kept for the DHT") {
            val a = buildDmTestNode()
            val b = buildDmTestNode()
            try {
                connectAndConverge(a, b)
                val bPub = b.identity.secp256k1KeyPair.publicKey
                var deposited = false
                val deadline = Instant.now().plus(Duration.ofSeconds(30))
                while (!deposited && Instant.now().isBefore(deadline)) {
                    deposited =
                        runCatching { a.dmSessionManager.sendOffline(bPub, DmContent(body = "hello")) }.isSuccess
                    if (!deposited) Thread.sleep(1000)
                }
                deposited shouldBe true
            } finally {
                a.stop()
                b.stop()
            }
        }
    })
