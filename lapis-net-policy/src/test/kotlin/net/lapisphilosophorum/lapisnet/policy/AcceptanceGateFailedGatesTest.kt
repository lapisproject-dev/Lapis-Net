package net.lapisphilosophorum.lapisnet.policy

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair

/** V0.9.15 - [AcceptanceGateEvaluator.failedGates] is the structured twin of `firstPassOrFailureReason`. */
class AcceptanceGateFailedGatesTest :
    FunSpec({
        val sender = Secp256k1KeyPair.generate().publicKey
        val noKarma = KarmaScoreLookup { 0.0 }

        test("null when accepted: no gates, or at least one gate passes (OR semantics)") {
            AcceptanceGateEvaluator.failedGates(sender, emptyList(), { false }, noKarma) shouldBe null
            AcceptanceGateEvaluator.failedGates(
                sender,
                listOf(AcceptanceGate.VeritasPath, AcceptanceGate.KarmaThreshold(3.0)),
                { false },
                KarmaScoreLookup { 3.0 },
            ) shouldBe null
        }

        test("the failed gates, in configuration order, when none passes") {
            val gates = listOf(AcceptanceGate.KarmaThreshold(3.0), AcceptanceGate.VeritasPath)
            AcceptanceGateEvaluator.failedGates(sender, gates, { false }, noKarma) shouldBe gates
            AcceptanceGateEvaluator.failedGates(sender, listOf(AcceptanceGate.VeritasPath), { false }, noKarma) shouldBe
                listOf(AcceptanceGate.VeritasPath)
        }

        test("firstPassOrFailureReason keeps its exact string format (delegation is byte-identical)") {
            val gates = listOf(AcceptanceGate.VeritasPath, AcceptanceGate.KarmaThreshold(2.5))
            AcceptanceGateEvaluator.firstPassOrFailureReason(sender, gates, { false }, noKarma) shouldBe
                "no Veritas path from local identity to sender; karma below threshold 2.5"
            AcceptanceGateEvaluator.firstPassOrFailureReason(sender, gates, { true }, noKarma) shouldBe null
        }
    })
