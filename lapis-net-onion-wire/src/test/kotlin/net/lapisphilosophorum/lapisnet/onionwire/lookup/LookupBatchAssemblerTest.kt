package net.lapisphilosophorum.lapisnet.onionwire.lookup

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import net.lapisphilosophorum.lapisnet.onion.LookupBatchResponseBody
import net.lapisphilosophorum.lapisnet.onion.LookupResponseBody
import net.lapisphilosophorum.lapisnet.onion.LookupStatus
import net.lapisphilosophorum.lapisnet.onion.RelayCommand
import net.lapisphilosophorum.lapisnet.onion.RelayMessage
import java.security.SecureRandom

class LookupBatchAssemblerTest :
    FunSpec({
        val random = SecureRandom()

        fun msg(body: ByteArray) = RelayMessage(RelayCommand.LOOKUP_RESPONSE, 0, body)

        fun feed(
            a: BatchAssembler,
            frags: List<ByteArray>,
        ): BatchAssembler.Result? {
            var last: BatchAssembler.Result? = null
            for (f in frags) last = a.accept(msg(f))
            return last
        }

        fun batch(
            id: Int,
            vararg answers: Pair<Byte, ByteArray>,
        ) = LookupBatchResponseBody.encodeBatch(id, answers.toList(), random)

        test("a complete batch is returned in request order with its content") {
            val c0 = ByteArray(300) { 1 }
            val c2 = ByteArray(9000) { 2 }
            val frags =
                batch(
                    4,
                    LookupStatus.FOUND to c0,
                    LookupStatus.NOT_FOUND to ByteArray(0),
                    LookupStatus.FOUND to c2,
                )
            val a = BatchAssembler(4, 3)
            val r = feed(a, frags).shouldBeInstanceOf<BatchAssembler.Result.Complete>()
            r.items.map { it.status } shouldBe listOf(LookupStatus.FOUND, LookupStatus.NOT_FOUND, LookupStatus.FOUND)
            r.items[0].content.contentEquals(c0) shouldBe true
            r.items[1].content.size shouldBe 0
            r.items[2].content.contentEquals(c2) shouldBe true
        }

        test("the result is only returned with the very last fragment") {
            val frags = batch(1, LookupStatus.NOT_FOUND to ByteArray(0), LookupStatus.NOT_FOUND to ByteArray(0))
            val a = BatchAssembler(1, 2)
            for (i in 0 until frags.size - 1) a.accept(msg(frags[i])) shouldBe null
            a.accept(msg(frags.last())).shouldBeInstanceOf<BatchAssembler.Result.Complete>()
        }

        test("a skipped item, a repeated item and an interleaved fragment are manipulations") {
            val frags = batch(1, LookupStatus.NOT_FOUND to ByteArray(0), LookupStatus.NOT_FOUND to ByteArray(0))
            // item 1 first
            BatchAssembler(1, 2).accept(msg(frags[3])) shouldBe BatchAssembler.Result.Broken
            // item 0 twice
            BatchAssembler(1, 2)
                .also {
                    for (i in 0 until 3) it.accept(msg(frags[i]))
                }.accept(msg(frags[0])) shouldBe BatchAssembler.Result.Broken
            // a fragment of the next item inside the current one
            BatchAssembler(1, 2)
                .also {
                    it.accept(msg(frags[0]))
                }.accept(msg(frags[3])) shouldBe BatchAssembler.Result.Broken
            // a fragment skipped inside an item
            BatchAssembler(1, 2)
                .also {
                    it.accept(msg(frags[0]))
                }.accept(msg(frags[2])) shouldBe BatchAssembler.Result.Broken
        }

        test("a wrong request id, a wrong command and a wrong length are manipulations") {
            val frags = batch(1, LookupStatus.NOT_FOUND to ByteArray(0))
            BatchAssembler(2, 1).accept(msg(frags[0])) shouldBe BatchAssembler.Result.Broken
            BatchAssembler(1, 1).accept(RelayMessage(RelayCommand.LOOKUP_REQUEST, 0, frags[0])) shouldBe
                BatchAssembler.Result.Broken
            BatchAssembler(1, 1).accept(msg(frags[0].copyOf(100))) shouldBe BatchAssembler.Result.Broken
        }

        test(
            "a fragment count that does not fit the class, an unknown status and a status with content are manipulations",
        ) {
            val frags = batch(1, LookupStatus.NOT_FOUND to ByteArray(0))
            // class index 1 in the first fragment of a 3-fragment item
            BatchAssembler(1, 1).accept(msg(frags[0].copyOf().also { it[8] = 1 })) shouldBe BatchAssembler.Result.Broken
            BatchAssembler(1, 1).accept(msg(frags[0].copyOf().also { it[7] = 99 })) shouldBe
                BatchAssembler.Result.Broken
            BatchAssembler(1, 1).accept(msg(frags[0].copyOf().also { it[10] = 1 })) shouldBe
                BatchAssembler.Result.Broken
            // fragCount that is no class count
            BatchAssembler(1, 1).accept(msg(frags[0].copyOf().also { it[6] = 4 })) shouldBe BatchAssembler.Result.Broken
        }

        test("fragments after a result are ignored") {
            val frags = batch(1, LookupStatus.NOT_FOUND to ByteArray(0))
            val a = BatchAssembler(1, 1)
            feed(a, frags).shouldBeInstanceOf<BatchAssembler.Result.Complete>()
            a.accept(msg(frags[0])) shouldBe null
        }

        test(
            "a version-1 UNSUPPORTED_VERSION answer as the first message is a version-1-only relay; all three fragments are consumed",
        ) {
            val v1 = LookupResponseBody.encodeAnswer(9, LookupStatus.UNSUPPORTED_VERSION, ByteArray(0), random)
            val a = BatchAssembler(9, 4)
            a.accept(msg(v1[0])) shouldBe null
            a.accept(msg(v1[1])) shouldBe null
            a.accept(msg(v1[2])) shouldBe BatchAssembler.Result.V1Only
            a.started shouldBe true
        }

        test("a version-1 RATE_LIMITED answer is a refusal of the whole batch") {
            val v1 = LookupResponseBody.encodeAnswer(9, LookupStatus.RATE_LIMITED, ByteArray(0), random)
            val a = BatchAssembler(9, 2)
            feed(a, v1) shouldBe BatchAssembler.Result.WholeRefused
        }

        test("any other version-1 answer to a batch is a manipulation") {
            for (status in listOf(
                LookupStatus.NOT_FOUND,
                LookupStatus.DISABLED,
                LookupStatus.MALFORMED,
                LookupStatus.TIMEOUT,
            )) {
                val v1 = LookupResponseBody.encodeAnswer(3, status, ByteArray(0), random)
                BatchAssembler(3, 2).accept(msg(v1[0])) shouldBe BatchAssembler.Result.Broken
            }
            val found = LookupResponseBody.encodeAnswer(3, LookupStatus.FOUND, ByteArray(10), random)
            BatchAssembler(3, 2).accept(msg(found[0])) shouldBe BatchAssembler.Result.Broken
        }

        test("a version-1 answer with a wrong request id, a bigger class or a wrong fragment order is a manipulation") {
            val v1 = LookupResponseBody.encodeAnswer(3, LookupStatus.UNSUPPORTED_VERSION, ByteArray(0), random)
            BatchAssembler(4, 2).accept(msg(v1[0])) shouldBe BatchAssembler.Result.Broken
            BatchAssembler(3, 2).accept(msg(v1[1])) shouldBe BatchAssembler.Result.Broken
            val big = LookupResponseBody.encodeAnswer(3, LookupStatus.FOUND, ByteArray(5000), random)
            BatchAssembler(3, 2).accept(msg(big[0])) shouldBe BatchAssembler.Result.Broken
            BatchAssembler(3, 2).also { it.accept(msg(v1[0])) }.accept(msg(v1[2])) shouldBe BatchAssembler.Result.Broken
        }

        test(
            "a version-1 fragment after the first item began, and a version-2 fragment inside a version-1 refusal, are manipulations",
        ) {
            val frags = batch(3, LookupStatus.NOT_FOUND to ByteArray(0), LookupStatus.NOT_FOUND to ByteArray(0))
            val v1 = LookupResponseBody.encodeAnswer(3, LookupStatus.UNSUPPORTED_VERSION, ByteArray(0), random)
            BatchAssembler(3, 2).also { it.accept(msg(frags[0])) }.accept(msg(v1[0])) shouldBe
                BatchAssembler.Result.Broken
            BatchAssembler(3, 2).also { it.accept(msg(v1[0])) }.accept(msg(frags[1])) shouldBe
                BatchAssembler.Result.Broken
        }

        test("the largest class of every item is reassembled and nothing is allocated before the header is checked") {
            val big = ByteArray(131_066) { (it % 251).toByte() }
            val frags = batch(2, LookupStatus.FOUND to big, LookupStatus.FOUND to big)
            val a = BatchAssembler(2, 2)
            // a broken first fragment (class does not match) allocates nothing and ends the assembly
            BatchAssembler(2, 2).accept(msg(frags[0].copyOf().also { it[8] = 0 })) shouldBe BatchAssembler.Result.Broken
            val r = feed(a, frags).shouldBeInstanceOf<BatchAssembler.Result.Complete>()
            r.items.all { it.content.contentEquals(big) } shouldBe true
        }
    })
