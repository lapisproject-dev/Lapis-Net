@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onion

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.onion.fake.FixedClock
import net.lapisphilosophorum.lapisnet.onion.fake.InMemoryOnionNetwork
import net.lapisphilosophorum.lapisnet.onion.fake.Probe
import net.lapisphilosophorum.lapisnet.onion.fake.newTestRelay
import java.security.SecureRandom

class DirectoryPublishMessagesTest :
    FunSpec({
        val random = SecureRandom()

        test("the body is exactly 720 bytes for every object size and kind") {
            for (type in DirectoryObjectType.entries) {
                for (size in listOf(1, 100, 248, 653, 717)) {
                    DirectoryPublishBody.encode(type, ByteArray(size) { 5 }, random).size shouldBe 720
                }
            }
            DirectoryPublishBody.BODY_SIZE shouldBe 720
            DirectoryPublishBody.MAX_OBJECT_SIZE shouldBe 717
        }

        test("encode and decode round-trip, the padding is random and never interpreted") {
            val obj = ByteArray(248) { it.toByte() }
            val a = DirectoryPublishBody.encode(DirectoryObjectType.ANONYMOUS_PEER_RECORD, obj, random)
            val b = DirectoryPublishBody.encode(DirectoryObjectType.ANONYMOUS_PEER_RECORD, obj, random)
            a.contentEquals(b) shouldBe false // random padding
            DirectoryPublishBody.decode(a).objectBytes.contentEquals(obj) shouldBe true
            DirectoryPublishBody.decode(a).type shouldBe DirectoryObjectType.ANONYMOUS_PEER_RECORD
            DirectoryPublishBody.decode(a).toString().contains("length=248") shouldBe true
        }

        test("an object that does not fit, or is empty, is refused at encoding") {
            shouldThrow<IllegalArgumentException> {
                DirectoryPublishBody.encode(DirectoryObjectType.PREKEY_BUNDLE, ByteArray(718), random)
            }
            shouldThrow<IllegalArgumentException> {
                DirectoryPublishBody.encode(DirectoryObjectType.PREKEY_BUNDLE, ByteArray(0), random)
            }
        }

        test("the exact length is checked first; an unknown type and an overflowing length field are protocol errors") {
            val good = DirectoryPublishBody.encode(DirectoryObjectType.ONION_SERVICE_DESCRIPTOR, ByteArray(100), random)
            shouldThrow<CellFormatException> { DirectoryPublishBody.decode(good.copyOf(719)) }
            shouldThrow<CellFormatException> { DirectoryPublishBody.decode(good + 0) }
            shouldThrow<CellFormatException> { DirectoryPublishBody.decode(good.copyOf().also { it[0] = 9 }) }
            // 0x7F__ is far above 717
            shouldThrow<CellFormatException> { DirectoryPublishBody.decode(good.copyOf().also { it[1] = 0x7F }) }
            shouldThrow<CellFormatException> {
                DirectoryPublishBody.decode(
                    good.copyOf().also {
                        it[1] = 0
                        it[2] = 0
                    },
                )
            }
            shouldThrow<CellFormatException> {
                DirectoryPublishBody.decode(
                    good.copyOf().also {
                        it[1] = 0x02
                        it[2] = 0xCE.toByte()
                    },
                ) // 718
            }
        }

        test("720 bytes fit a relay message at the maximum number of hops and every smaller one") {
            for (hops in 1..OnionConstants.MAX_HOPS) {
                (RelayMessageCodec.maxData(hops) >= DirectoryPublishBody.BODY_SIZE) shouldBe true
            }
            val msg = RelayMessage(RelayCommand.DIRECTORY_PUBLISH, 0, ByteArray(720))
            RelayMessageCodec.encode(msg, RelayMessageCodec.capacity(OnionConstants.MAX_HOPS), random).size shouldBe
                RelayMessageCodec.capacity(OnionConstants.MAX_HOPS)
            RelayMessageCodec
                .decode(
                    RelayMessageCodec.encode(msg, RelayMessageCodec.capacity(OnionConstants.MAX_HOPS), random),
                ).command shouldBe RelayCommand.DIRECTORY_PUBLISH
        }

        test("the new relay commands have stable codes") {
            RelayCommand.DIRECTORY_PUBLISH.code shouldBe 16.toByte()
            RelayCommand.DIRECTORY_PUBLISHED.code shouldBe 17.toByte()
            RelayCommand.fromCode(16) shouldBe RelayCommand.DIRECTORY_PUBLISH
        }

        test("an end-to-end circuit carries 720 bytes through the relay layers to the last hop") {
            val clock = FixedClock()
            val relay = newTestRelay(clock = clock)
            val net = InMemoryOnionNetwork(listOf(relay))
            val probe = Probe(net, clock)
            val obj = ByteArray(300) { (it * 3).toByte() }
            probe.send(
                RelayCommand.DIRECTORY_PUBLISH,
                DirectoryPublishBody.encode(DirectoryObjectType.PREKEY_BUNDLE, obj, random),
            )
            net.publishes.size shouldBe 1
            net.publishes
                .single()
                .objectBytes
                .contentEquals(obj) shouldBe true
            net.publishes.single().type shouldBe DirectoryObjectType.PREKEY_BUNDLE
        }
    })
