package net.lapisphilosophorum.lapisnet.onion

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.onion.fake.newTestRelay

/**
 * Honest limit, stated here as in docs/anonymity.adoc: these tests prove that the arrays THIS code
 * owns are overwritten with zeros. The JVM may have made copies the code cannot reach (GC moving
 * objects, BouncyCastle copying the key into its per-cell cipher state, `ByteArray.copyOf` in
 * accessors). Zeroisation narrows the window for a memory-dump attacker; it does not close it.
 */
class ZeroizationTest :
    FunSpec({
        fun zero(b: ByteArray) = b.all { it == 0.toByte() }

        test("CircuitHopKeys.close zeroises both keys and refuses further use") {
            val k = CircuitHopKeys(ByteArray(32) { 1 }, ByteArray(32) { 2 })
            zero(k.forwardRaw) shouldBe false
            k.close()
            zero(k.forwardRaw) shouldBe true
            zero(k.backwardRaw) shouldBe true
            shouldThrow<IllegalStateException> { k.forwardKeyCopy() }
            k.close() // idempotent
        }

        test("NtorClientState.close zeroises the ephemeral scalar") {
            val r = newTestRelay()
            val (state, _) = NtorHandshake.clientStart(r.binding, 1)
            zero(state.x.bytes) shouldBe false
            state.close()
            zero(state.x.bytes) shouldBe true
        }

        test("a ClientCircuit takes ownership of the hop keys it is given and zeroises them") {
            val keys = CircuitHopKeys(ByteArray(32) { 5 }, ByteArray(32) { 6 })
            val c = ClientCircuit()
            c.addHop(keys)
            zero(keys.forwardRaw) shouldBe true
            c.zeroizedForTest() shouldBe false
            c.close()
            c.zeroizedForTest() shouldBe true
        }

        test("a relay hop zeroises on close, and closing the relay drops every circuit") {
            val r = newTestRelay()
            val builder = ClientCircuitBuilder(listOf(r.binding))
            r.relay.onCell(LinkId(1), builder.start())
            r.relay.circuitCount shouldBe 1
            r.relay.close()
            r.relay.circuitCount shouldBe 0
            val hop = RelayHopState(1, CircuitHopKeys(ByteArray(32) { 1 }, ByteArray(32) { 2 }))
            hop.close()
            hop.zeroizedForTest() shouldBe true
        }

        test("every secret-bearing type prints REDACTED") {
            val r = newTestRelay()
            val (state, create) = NtorHandshake.clientStart(r.binding, 1)
            val server = NtorHandshake.serverRespond(create, r.onion.privateKey, r.binding)
            val keys = NtorHandshake.clientFinish(state, server.created)
            val circuit = ClientCircuit()
            val texts =
                listOf(
                    state.toString(),
                    server.toString(),
                    server.created.toString(),
                    keys.toString(),
                    circuit.toString(),
                    RelayHopState(1, CircuitHopKeys(ByteArray(32) { 1 }, ByteArray(32) { 2 })).toString(),
                    r.onion.privateKey.toString(),
                )
            texts.forEach { it shouldContain "REDACTED" }
            val keyHex = keys.forwardRaw.joinToString("") { "%02x".format(it) }
            texts.forEach { it shouldNotContain keyHex }
            X25519KeyPair.generate().privateKey.toString() shouldContain "REDACTED"
        }
    })
