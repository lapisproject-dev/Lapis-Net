package net.lapisphilosophorum.lapisnet.networking.relay

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.protocol.circuit.pb.Circuit

class RelayExceptionStatusTest :
    FunSpec({
        test("only target-side refusals are not the relay's fault") {
            RelayException("x", relayStatus = Circuit.Status.NO_RESERVATION).isTargetSideFailure shouldBe true
            RelayException("x", relayStatus = Circuit.Status.CONNECTION_FAILED).isTargetSideFailure shouldBe false
            RelayException("x", relayStatus = Circuit.Status.RESOURCE_LIMIT_EXCEEDED).isTargetSideFailure shouldBe false
            RelayException("x", relayStatus = Circuit.Status.PERMISSION_DENIED).isTargetSideFailure shouldBe false
            RelayException("x").isTargetSideFailure shouldBe false
        }
    })
