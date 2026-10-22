package net.lapisphilosophorum.lapisnet.onion

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.onion.fake.FixedClock

private fun createCell(
    binding: OnionKeyBinding,
    clock: FixedClock,
): Cell = ClientCircuitBuilder(listOf(binding), clock = clock).start()

private fun answer(
    relay: OnionRelay,
    link: Long,
    cell: Cell,
): CellCommand = (relay.onCell(LinkId(link), cell).single() as RelayAction.SendCell).cell.command

class OnionRelayRotationTest :
    FunSpec({
        test("CREATE with old and new key both succeed in the overlap; the old one fails after retirement") {
            val clock = FixedClock()
            val now = clock.millis() / 1000
            val identity = Secp256k1KeyPair.generate()
            val ring = OnionKeyRing(identity.publicKey)
            val k1 = X25519KeyPair.generate()
            val b1 = OnionKeyBinding.create(identity, k1.publicKey, now + 1000)
            val k2 = X25519KeyPair.generate()
            val b2 = OnionKeyBinding.create(identity, k2.publicKey, now + 5000)
            ring.install(b1, k1.privateKey, now)
            ring.install(b2, k2.privateKey, now)
            val relay = OnionRelay(ring, clock = clock)
            answer(relay, 1, createCell(b1, clock)) shouldBe CellCommand.CREATED
            answer(relay, 2, createCell(b2, clock)) shouldBe CellCommand.CREATED
            clock.advanceMillis(1_100_000)
            ring.retireExpired(clock.millis() / 1000) shouldBe 1
            // the old binding no longer verifies on the client side, so craft the cell with the old fingerprint directly
            val (_, create) = NtorHandshake.clientStart(b1, 1)
            val stale = Cell(77, CellCommand.CREATE, create.encode())
            answer(relay, 3, stale) shouldBe CellCommand.DESTROY
            relay.circuitCount shouldBe 2
            relay.close()
            ring.close()
        }
    })
