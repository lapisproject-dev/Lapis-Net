package net.lapisphilosophorum.lapisnet.mail

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.directory.SealedMailboxBox

class AnonymousMailSizingTest :
    FunSpec({
        fun tooLarge(block: () -> Unit) {
            shouldThrow<MailAnonymousDeliveryException> { block() }.failure shouldBe
                MailAnonymousFailure.MAIL_TOO_LARGE_ANONYMOUS
        }

        test("the inline limit equals the sealed item capacity") {
            AnonymousMailSizing.MAX_INLINE_FRAME_BYTES shouldBe SealedMailboxBox.MAX_PAYLOAD_BYTES
        }

        test("a frame up to the item capacity without attachments is INLINE, one byte more is CIRCUIT") {
            AnonymousMailSizing.classify(1, emptyList()) shouldBe AnonymousMailSizeClass.INLINE
            AnonymousMailSizing.classify(AnonymousMailSizing.MAX_INLINE_FRAME_BYTES, emptyList()) shouldBe
                AnonymousMailSizeClass.INLINE
            AnonymousMailSizing.classify(AnonymousMailSizing.MAX_INLINE_FRAME_BYTES + 1, emptyList()) shouldBe
                AnonymousMailSizeClass.CIRCUIT
        }

        test("any attachment forces CIRCUIT, even a tiny frame") {
            AnonymousMailSizing.classify(100, listOf(10)) shouldBe AnonymousMailSizeClass.CIRCUIT
            AnonymousMailSizing.classify(100, listOf(0)) shouldBe AnonymousMailSizeClass.CIRCUIT
        }

        test("the bundle limit is 1 MiB over frame plus all blobs") {
            val limit = AnonymousMailSizing.MAX_CIRCUIT_BUNDLE_BYTES
            // header overhead for one blob: version(1) + frameLen(4) + count(1) + blobLen(4) = 10 bytes
            AnonymousMailSizing.classify(1000, listOf(limit - 1000 - 10)) shouldBe AnonymousMailSizeClass.CIRCUIT
            tooLarge { AnonymousMailSizing.classify(1000, listOf(limit - 1000 - 9)) }
            // the old window: payload sum exactly 1 MiB, but the encoded bundle would exceed it
            tooLarge { AnonymousMailSizing.classify(1000, listOf(limit - 1000)) }
            tooLarge { AnonymousMailSizing.classify(limit + 1, emptyList()) }
            tooLarge { AnonymousMailSizing.classify(10, listOf(limit / 2, limit / 2)) }
        }

        test("sizes beyond Int range in sum cannot overflow the check") {
            tooLarge { AnonymousMailSizing.classify(Int.MAX_VALUE, listOf(Int.MAX_VALUE, Int.MAX_VALUE)) }
        }

        test("17 attachments are refused, 16 are fine") {
            AnonymousMailSizing.classify(100, List(16) { 10 }) shouldBe AnonymousMailSizeClass.CIRCUIT
            tooLarge { AnonymousMailSizing.classify(100, List(17) { 1 }) }
        }

        test("an empty frame or a negative blob size is refused") {
            tooLarge { AnonymousMailSizing.classify(0, emptyList()) }
            tooLarge { AnonymousMailSizing.classify(10, listOf(-1)) }
        }

        test("the exception message is the stable wire code and names nothing else") {
            MailAnonymousDeliveryException(MailAnonymousFailure.RECIPIENT_NOT_REACHABLE_ANONYMOUSLY).message shouldBe
                "recipient-not-reachable-anonymously"
            MailAnonymousFailure.entries
                .map { it.wire }
                .toSet()
                .size shouldBe MailAnonymousFailure.entries.size
        }
    })
