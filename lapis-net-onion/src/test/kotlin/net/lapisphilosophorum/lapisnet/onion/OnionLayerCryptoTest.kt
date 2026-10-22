package net.lapisphilosophorum.lapisnet.onion

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.onion.OnionConstants.BODY_SIZE
import net.lapisphilosophorum.lapisnet.onion.OnionConstants.LAYER_OVERHEAD
import net.lapisphilosophorum.lapisnet.onion.fake.DeterministicSecureRandom
import java.security.SecureRandom
import java.util.Random

/** A client circuit plus the matching [RelayHopState]s, with keys supplied by [rng]. */
private class Rig(
    val hops: Int,
    keyRng: SecureRandom = SecureRandom(),
) {
    val client = ClientCircuit()
    val relays = ArrayList<RelayHopState>()

    init {
        for (i in 1..hops) {
            val f = ByteArray(32).also(keyRng::nextBytes)
            val b = ByteArray(32).also(keyRng::nextBytes)
            client.addHop(CircuitHopKeys(f, b))
            relays += RelayHopState(i, CircuitHopKeys(f, b))
        }
    }

    /** Walks [body] through relays 1..k (exclusive of [from]); returns the final result. */
    fun forward(
        body: ByteArray,
        upTo: Int,
        from: Int = 1,
        rng: SecureRandom = SecureRandom(),
    ): ForwardResult {
        var cur = body
        var result: ForwardResult? = null
        for (i in from..upTo) {
            val r = relays[i - 1].unwrapForward(cur, rng)
            result = r
            if (r is ForwardResult.Forward) {
                r.body.size shouldBe BODY_SIZE
                cur = r.body
            }
        }
        return result!!
    }

    fun backward(
        origin: Int,
        msg: RelayMessage,
        rng: SecureRandom = SecureRandom(),
    ): ByteArray {
        var cur = relays[origin - 1].originateBackward(msg, rng)
        cur.size shouldBe BODY_SIZE
        for (i in origin - 1 downTo 1) {
            cur = relays[i - 1].wrapBackward(cur, rng)
            cur.size shouldBe BODY_SIZE
        }
        return cur
    }
}

private fun msg(
    size: Int,
    cmd: RelayCommand = RelayCommand.DATA,
) = RelayMessage(cmd, 7, ByteArray(size) { (it * 31 + 5).toByte() })

class OnionLayerCryptoTest :
    FunSpec({
        test("layer sizes shrink by one overhead per hop") {
            for (i in 1..5) layerSize(i) shouldBe BODY_SIZE - (i - 1) * LAYER_OVERHEAD
        }

        test("forward roundtrip for every hop count and every target hop") {
            for (n in 1..5) {
                for (k in 1..n) {
                    val rig = Rig(n)
                    val m = msg(RelayMessageCodec.maxData(k))
                    val body = rig.client.wrapForward(m, k)
                    body.size shouldBe BODY_SIZE
                    val r = rig.forward(body, k)
                    (r is ForwardResult.Local) shouldBe true
                    val local = (r as ForwardResult.Local).message
                    local.command shouldBe RelayCommand.DATA
                    local.data.contentEquals(m.data) shouldBe true
                }
            }
        }

        test("many cells in sequence keep every counter in sync, including mixed targets") {
            val rig = Rig(3)
            repeat(50) { i ->
                val k = 1 + i % 3
                val r = rig.forward(rig.client.wrapForward(msg(10 + i), k), k)
                (r as ForwardResult.Local).message.data.size shouldBe 10 + i
            }
        }

        test("backward roundtrip for every hop count and every origin") {
            for (n in 1..5) {
                for (k in 1..n) {
                    val rig = Rig(n)
                    val m = msg(RelayMessageCodec.maxData(k), RelayCommand.DATA)
                    val (origin, got) = rig.client.unwrapBackward(rig.backward(k, m))
                    origin shouldBe k
                    got.data.contentEquals(m.data) shouldBe true
                }
            }
        }

        test("too-large payloads are refused") {
            val rig = Rig(3)
            shouldThrow<IllegalArgumentException> { rig.client.wrapForward(msg(RelayMessageCodec.maxData(3) + 1), 3) }
            shouldThrow<IllegalArgumentException> { rig.client.wrapForward(msg(1), 4) }
        }

        test("tamper in the forward direction: every sampled bit at every hop") {
            val sample = mutableListOf<Int>()
            sample += 0 until 64
            sample += (BODY_SIZE - 64) until BODY_SIZE
            val r = Random(7)
            repeat(150) { sample += r.nextInt(BODY_SIZE) }
            var checked = 0
            for (h in 1..3) {
                for (p in sample.distinct()) {
                    val rig = Rig(3)
                    val m = msg(30)
                    var body = rig.client.wrapForward(m, 3)
                    if (h > 1) body = (rig.forward(body, h - 1) as ForwardResult.Forward).body
                    body[p] = (body[p].toInt() xor (1 shl (p % 8))).toByte()
                    if (p < layerSize(h)) {
                        // authenticated region: the next honest hop aborts
                        shouldThrow<OnionIntegrityException> { rig.relays[h - 1].unwrapForward(body) }
                    } else {
                        // unauthenticated tail: discarded and regenerated, message still intact
                        val res = rig.forward(body, 3, from = h)
                        (res as ForwardResult.Local).message.data.contentEquals(m.data) shouldBe true
                    }
                    checked++
                }
            }
            (checked > 400) shouldBe true
        }

        test("tamper in the backward direction is detected by the client") {
            val sample =
                (0 until 64).toList() + ((BODY_SIZE - 64) until BODY_SIZE).toList() +
                    List(100) { Random(it.toLong()).nextInt(BODY_SIZE) }
            for (p in sample.distinct()) {
                val rig = Rig(3)
                val m = msg(30)
                // origin 3, wrapped by relay 2, then the body on the 2 -> 1 link is flipped
                val atRelay1 = rig.relays[2].originateBackward(m).let { rig.relays[1].wrapBackward(it) }
                atRelay1[p] = (atRelay1[p].toInt() xor (1 shl (p % 8))).toByte()
                val toClient = rig.relays[0].wrapBackward(atRelay1)
                // relay 1 only consumes the first BODY - 17 bytes: the final 17 bytes are discarded filler
                if (p < BODY_SIZE - LAYER_OVERHEAD) {
                    shouldThrow<OnionIntegrityException> { rig.client.unwrapBackward(toClient) }
                } else {
                    rig.client
                        .unwrapBackward(toClient)
                        .second.data
                        .contentEquals(m.data) shouldBe true
                }
            }
        }

        test("a flip in the final client-side body is always detected") {
            for (p in listOf(0, 1, 500, BODY_SIZE - 1)) {
                val rig = Rig(3)
                val b = rig.backward(3, msg(10))
                b[p] = (b[p].toInt() xor 1).toByte()
                shouldThrow<OnionIntegrityException> { rig.client.unwrapBackward(b) }
            }
        }

        test("no tagging channel: output does not depend on the bytes an honest hop must discard") {
            fun rig() = Rig(3, DeterministicSecureRandom("keys"))
            val a = rig()
            val b = rig()
            val bodyA = a.client.wrapForward(msg(40), 3, DeterministicSecureRandom("client"))
            val bodyB = b.client.wrapForward(msg(40), 3, DeterministicSecureRandom("client"))
            bodyA.contentEquals(bodyB) shouldBe true
            val outA = (a.relays[0].unwrapForward(bodyA, DeterministicSecureRandom("g")) as ForwardResult.Forward).body
            val outB = (b.relays[0].unwrapForward(bodyB, DeterministicSecureRandom("g")) as ForwardResult.Forward).body
            // a colluding guard writes a marker into the unauthenticated tail destined for relay 2
            for (i in layerSize(2) until BODY_SIZE) outB[i] = 0xAA.toByte()
            val midA = (a.relays[1].unwrapForward(outA, DeterministicSecureRandom("m")) as ForwardResult.Forward).body
            val midB = (b.relays[1].unwrapForward(outB, DeterministicSecureRandom("m")) as ForwardResult.Forward).body
            midA.contentEquals(midB) shouldBe true
        }

        test("a random run: the guard's marker is gone after the middle hop") {
            val rig = Rig(3)
            val out1 = (rig.relays[0].unwrapForward(rig.client.wrapForward(msg(40), 3)) as ForwardResult.Forward).body
            for (i in layerSize(2) until BODY_SIZE) out1[i] = 0xAA.toByte()
            val out2 = (rig.relays[1].unwrapForward(out1) as ForwardResult.Forward).body
            (out2.drop(layerSize(3)).count { it == 0xAA.toByte() } < 8) shouldBe true
        }

        test("truncated, oversized and replayed bodies fail") {
            val rig = Rig(2)
            val body = rig.client.wrapForward(msg(5), 2)
            shouldThrow<OnionIntegrityException> { rig.relays[0].unwrapForward(body.copyOf(BODY_SIZE - 1)) }
            val rig2 = Rig(2)
            val b2 = rig2.client.wrapForward(msg(5), 2)
            rig2.relays[0].unwrapForward(b2)
            shouldThrow<OnionIntegrityException> { rig2.relays[0].unwrapForward(b2) }
            shouldThrow<OnionIntegrityException> { Rig(1).client.unwrapBackward(ByteArray(10)) }
        }

        test("cross-circuit bodies do not open") {
            val a = Rig(3)
            val b = Rig(3)
            shouldThrow<OnionIntegrityException> { b.relays[0].unwrapForward(a.client.wrapForward(msg(5), 3)) }
        }

        test("closing zeroises every hop key; further use fails") {
            val rig = Rig(3)
            rig.client.close()
            rig.relays.forEach { it.close() }
            rig.client.zeroizedForTest() shouldBe true
            rig.relays.all { it.zeroizedForTest() } shouldBe true
            shouldThrow<IllegalStateException> { rig.client.wrapForward(msg(1), 1) }
        }
    })
