package net.lapisphilosophorum.lapisnet.policy

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair

class AcceptanceGateEvaluatorTest :
    FunSpec({
        val sender = Secp256k1KeyPair.generate().publicKey

        test("empty gate list is accepted (null reason)") {
            val reason =
                AcceptanceGateEvaluator.firstPassOrFailureReason(
                    sender,
                    AcceptanceGateEvaluator.ACCEPT_ALL,
                    hasVeritasPath = { false },
                    karmaScoreOf = KarmaScoreLookup { 0.0 },
                )
            reason shouldBe null
        }

        test("VeritasPath alone: passes when hasVeritasPath is true") {
            val reason =
                AcceptanceGateEvaluator.firstPassOrFailureReason(
                    sender,
                    listOf(AcceptanceGate.VeritasPath),
                    hasVeritasPath = { true },
                    karmaScoreOf = KarmaScoreLookup { 0.0 },
                )
            reason shouldBe null
        }

        test("VeritasPath alone: fails when hasVeritasPath is false") {
            val reason =
                AcceptanceGateEvaluator.firstPassOrFailureReason(
                    sender,
                    listOf(AcceptanceGate.VeritasPath),
                    hasVeritasPath = { false },
                    karmaScoreOf = KarmaScoreLookup { 0.0 },
                )
            reason shouldBe "no Veritas path from local identity to sender"
        }

        test("KarmaThreshold alone: passes at or above the threshold") {
            val reason =
                AcceptanceGateEvaluator.firstPassOrFailureReason(
                    sender,
                    listOf(AcceptanceGate.KarmaThreshold(5.0)),
                    hasVeritasPath = { false },
                    karmaScoreOf = KarmaScoreLookup { 5.0 },
                )
            reason shouldBe null
        }

        test("KarmaThreshold alone: fails below the threshold") {
            val reason =
                AcceptanceGateEvaluator.firstPassOrFailureReason(
                    sender,
                    listOf(AcceptanceGate.KarmaThreshold(5.0)),
                    hasVeritasPath = { false },
                    karmaScoreOf = KarmaScoreLookup { 4.9 },
                )
            reason shouldBe "karma below threshold 5.0"
        }

        test("both gates configured, OR semantics: one passing is enough") {
            val reason =
                AcceptanceGateEvaluator.firstPassOrFailureReason(
                    sender,
                    listOf(AcceptanceGate.VeritasPath, AcceptanceGate.KarmaThreshold(5.0)),
                    hasVeritasPath = { false },
                    karmaScoreOf = KarmaScoreLookup { 10.0 },
                )
            reason shouldBe null
        }

        test("both gates fail: composite reason lists every failed gate, never sender-controlled text") {
            val reason =
                AcceptanceGateEvaluator.firstPassOrFailureReason(
                    sender,
                    listOf(AcceptanceGate.VeritasPath, AcceptanceGate.KarmaThreshold(5.0)),
                    hasVeritasPath = { false },
                    karmaScoreOf = KarmaScoreLookup { 0.0 },
                )
            reason shouldBe "no Veritas path from local identity to sender; karma below threshold 5.0"
        }
    })
