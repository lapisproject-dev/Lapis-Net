package net.lapisphilosophorum.lapisnet.directory

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.crypto.KeyType
import io.libp2p.core.crypto.generateKeyPair
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import org.peergos.protocol.ipns.IPNS
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneOffset

class DirectoryDhtOutboxCodecTest :
    FunSpec({
        val publisher = DirectoryPublisher()
        val fixed = DirectoryDhtValueCodec.FIXED_SIZE

        fun encodedOutboxOnly(vararg entries: OutboxEntry): ByteArray =
            DirectoryDhtValueCodec.encode(publisher.valueWithOutbox(entries.toList()))

        test("a value with an outbox round-trips, with and without the other parts") {
            val entries = listOf(outboxEntry(), outboxEntry(kind = OutboxEntryKind.MAIL_POINTER, payloadSize = 100))
            for ((rec, bun) in listOf(false to false, true to false, false to true, true to true)) {
                val value = publisher.valueWithOutbox(entries, rec, bun)
                val decoded = DirectoryDhtValueCodec.decode(DirectoryDhtValueCodec.encode(value))
                decoded shouldBe value
                decoded.outboxEntries shouldBe entries
                (decoded.peerRecordBytes != null) shouldBe rec
                (decoded.prekeyBundleBytes != null) shouldBe bun
            }
        }

        test("an outbox-only value is valid, a value with no part at all is not") {
            DirectoryDhtValueCodec.decode(encodedOutboxOnly(outboxEntry())).outboxEntries.size shouldBe 1
            shouldThrow<IllegalArgumentException> {
                DirectoryDhtValue(publisher.key, publisher.identity.binding, null, null, emptyList())
            }
        }

        test("the reserved flag bit 0x08 is still rejected, the outbox bit 0x04 is known") {
            val bytes = encodedOutboxOnly(outboxEntry())
            (bytes[5].toInt() and 0x04) shouldBe 0x04
            shouldThrow<MalformedDirectoryDhtValueException> {
                DirectoryDhtValueCodec.decode(bytes.copyOf().also { it[5] = (it[5].toInt() or 0x08).toByte() })
            }
        }

        test("an outbox count of zero or above the maximum is malformed") {
            val bytes = encodedOutboxOnly(outboxEntry())
            shouldThrow<MalformedDirectoryDhtValueException> {
                DirectoryDhtValueCodec.decode(bytes.copyOf().also { it[fixed] = 0 })
            }
            shouldThrow<MalformedDirectoryDhtValueException> {
                DirectoryDhtValueCodec.decode(
                    bytes.copyOf().also {
                        it[fixed] = (DirectoryDhtValueCodec.MAX_OUTBOX_ENTRIES_PER_VALUE + 1).toByte()
                    },
                )
            }
        }

        test("an unknown kind is malformed") {
            val bytes = encodedOutboxOnly(outboxEntry())
            shouldThrow<MalformedDirectoryDhtValueException> {
                DirectoryDhtValueCodec.decode(bytes.copyOf().also { it[fixed + 1] = 9 })
            }
        }

        test(
            "a payload length of 0, above the kind maximum, or beyond the bytes present is malformed before any allocation",
        ) {
            val bytes = encodedOutboxOnly(outboxEntry(payloadSize = 274))
            val lengthAt = fixed + 1 + 1 + 33 + 8

            fun patched(length: Int) =
                bytes.copyOf().also {
                    it[lengthAt] = (length ushr 8).toByte()
                    it[lengthAt + 1] = length.toByte()
                }
            shouldThrow<MalformedDirectoryDhtValueException> { DirectoryDhtValueCodec.decode(patched(0)) }
            shouldThrow<MalformedDirectoryDhtValueException> { DirectoryDhtValueCodec.decode(patched(275)) }
            val small = encodedOutboxOnly(outboxEntry(payloadSize = 200))
            shouldThrow<MalformedDirectoryDhtValueException> {
                DirectoryDhtValueCodec.decode(
                    small.copyOf().also {
                        it[lengthAt] = 0xFF.toByte()
                        it[lengthAt + 1] = 0xFF.toByte()
                    },
                )
            }
        }

        test("every truncation, trailing bytes and an off-curve recipient are malformed") {
            val bytes = encodedOutboxOnly(outboxEntry(), outboxEntry())
            for (cut in listOf(fixed, fixed + 1, fixed + 2, fixed + 20, fixed + 60, fixed + 100, bytes.size - 1)) {
                shouldThrow<MalformedDirectoryDhtValueException> { DirectoryDhtValueCodec.decode(bytes.copyOf(cut)) }
            }
            shouldThrow<MalformedDirectoryDhtValueException> { DirectoryDhtValueCodec.decode(bytes + byteArrayOf(0)) }
            val offCurve = bytes.copyOf()
            for (i in fixed + 2 until fixed + 2 + 33) offCurve[i] = 0x05
            shouldThrow<MalformedDirectoryDhtValueException> { DirectoryDhtValueCodec.decode(offCurve) }
        }

        test("encode refuses an outbox part above its byte budget and above the entry count") {
            shouldThrow<IllegalArgumentException> {
                encodedOutboxOnly(*Array(10) { outboxEntry(payloadSize = 274) })
            }
            shouldThrow<IllegalArgumentException> {
                encodedOutboxOnly(
                    *Array(DirectoryDhtValueCodec.MAX_OUTBOX_ENTRIES_PER_VALUE + 1) {
                        outboxEntry(kind = OutboxEntryKind.MAIL_POINTER, payloadSize = 1)
                    },
                )
            }
        }

        test("an outbox entry rejects an empty or oversized payload") {
            shouldThrow<IllegalArgumentException> { outboxEntry(payloadSize = 0) }
            shouldThrow<IllegalArgumentException> { outboxEntry(payloadSize = 275) }
            shouldThrow<IllegalArgumentException> {
                outboxEntry(
                    kind = OutboxEntryKind.MAIL_POINTER,
                    payloadSize = 131,
                )
            }
        }

        test("values with an outbox next to the largest peer record, and next to a small one, fit the IPNS limit") {
            fun ipnsSize(bytes: ByteArray): Int =
                IPNS
                    .createSignedRecord(
                        bytes,
                        LocalDateTime.now(ZoneOffset.UTC).plusDays(7),
                        System.currentTimeMillis(),
                        Long.MAX_VALUE / 2,
                        generateKeyPair(KeyType.ED25519).first,
                    ).size

            fun recordWith(addresses: Int): Pair<DualKeyIdentity, ByteArray> {
                val identity = DualKeyIdentity.generate()
                val record =
                    PeerRecord.create(
                        identity,
                        List(addresses) {
                            io.libp2p.core.multiformats
                                .Multiaddr("/ip4/10.0.0.$it/tcp/${4000 + it}")
                        },
                        setOf(PeerCapability.DM, PeerCapability.RELAY),
                        0,
                        Instant.now().epochSecond + 100,
                    )
                return identity to PeerRecordCodec.encode(record)
            }

            // a peer record with the most addresses, plus an entry
            val (bigIdentity, bigRecord) = recordWith(PeerRecordCodec.MAX_ADDRESSES)
            val bigKey = bigIdentity.secp256k1KeyPair.publicKey
            val bigValue =
                DirectoryDhtValue(bigKey, bigIdentity.binding, bigRecord, null, listOf(outboxEntry(payloadSize = 100)))
            val bigBytes = DirectoryDhtValueCodec.encode(bigValue)
            (bigBytes.size <= DirectoryDhtValueCodec.MAX_VALUE_BYTES) shouldBe true
            (ipnsSize(bigBytes) <= IPNS.MAX_RECORD_SIZE) shouldBe true
            // a small record leaves room for a large outbox
            val (smallIdentity, smallRecord) = recordWith(1)
            val smallValue =
                DirectoryDhtValue(
                    smallIdentity.secp256k1KeyPair.publicKey,
                    smallIdentity.binding,
                    smallRecord,
                    null,
                    List(7) { outboxEntry(payloadSize = 226) },
                )
            val smallBytes = DirectoryDhtValueCodec.encode(smallValue)
            (smallBytes.size <= DirectoryDhtValueCodec.MAX_VALUE_BYTES) shouldBe true
            (ipnsSize(smallBytes) <= IPNS.MAX_RECORD_SIZE) shouldBe true

            // the worst case the codec admits at all
            val worst = ByteArray(DirectoryDhtValueCodec.MAX_VALUE_BYTES) { (it * 31).toByte() }
            (ipnsSize(worst) <= IPNS.MAX_RECORD_SIZE) shouldBe true
        }

        test("the mirrored payload maxima are the documented ones") {
            OutboxEntryKind.DM_MAILBOX_POINTER.maxPayloadBytes shouldBe 274
            OutboxEntryKind.MAIL_POINTER.maxPayloadBytes shouldBe 130
            OutboxEntryKind.fromWireId(1) shouldBe OutboxEntryKind.DM_MAILBOX_POINTER
            OutboxEntryKind.fromWireId(2) shouldBe OutboxEntryKind.MAIL_POINTER
            OutboxEntryKind.fromWireId(3) shouldBe null
        }
    })
