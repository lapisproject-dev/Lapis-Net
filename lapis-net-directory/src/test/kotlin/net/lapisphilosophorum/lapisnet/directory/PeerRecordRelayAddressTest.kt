package net.lapisphilosophorum.lapisnet.directory

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.multiformats.Multiaddr
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import java.time.Instant

private const val RELAY_PEER = "12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp"

/**
 * The directory half of the NAT-traversal wave: a peer behind NAT publishes its relayed
 * reachability through the existing, already-signed `addresses` list, and a peer willing to relay
 * for others says so through the new [PeerCapability.RELAY] bit.
 *
 * The point of this suite is that both are genuinely *additive*: a relay address survives a full
 * encode/decode round trip through the unchanged `LNPR` v1 layout, and the new capability bit rides
 * the reserved-bits forward-compatibility path [PeerCapability]'s own doc comment always described.
 */
class PeerRecordRelayAddressTest :
    FunSpec({
        val directAddress = Multiaddr("/ip4/127.0.0.1/tcp/4001")
        val relayAddress = Multiaddr("/ip4/198.51.100.7/tcp/4001/p2p/$RELAY_PEER/p2p-circuit")

        fun record(
            identity: DualKeyIdentity = DualKeyIdentity.generate(),
            addresses: List<Multiaddr> = listOf(directAddress, relayAddress),
            capabilities: Set<PeerCapability> = setOf(PeerCapability.DM),
        ): PeerRecord =
            PeerRecord.create(
                identity,
                addresses,
                capabilities,
                sequenceNumber = 0,
                notValidAfterEpochSecond = Instant.now().epochSecond + 3600,
            )

        test("a /p2p-circuit address survives an encode/decode round trip unchanged") {
            val original = record()
            val decoded = PeerRecordCodec.decode(PeerRecordCodec.encode(original))

            decoded.addresses shouldBe original.addresses
            // The outer signature still verifies, so the relay address is covered by it exactly
            // like every direct address - a relay cannot strip or rewrite it undetected.
            PeerRecord.verify(decoded) shouldBe true
            decoded.verifyBinding() shouldBe true
            decoded.verifyPossession() shouldBe true
        }

        test("relayAddresses and directAddresses partition the address list") {
            val subject = record()

            subject.relayAddresses shouldBe listOf(relayAddress)
            subject.directAddresses shouldBe listOf(directAddress)
            (subject.directAddresses + subject.relayAddresses).toSet() shouldBe subject.addresses.toSet()
        }

        test("a record with no relay address reports none") {
            val subject = record(addresses = listOf(directAddress))

            subject.relayAddresses shouldBe emptyList()
            subject.directAddresses shouldBe listOf(directAddress)
        }

        test("the RELAY capability bit round-trips and does not disturb the other bits") {
            val subject =
                record(capabilities = setOf(PeerCapability.DM, PeerCapability.RELAY))
            val decoded = PeerRecordCodec.decode(PeerRecordCodec.encode(subject))

            decoded.capabilities shouldBe setOf(PeerCapability.DM, PeerCapability.RELAY)
            PeerCapability.bitsFrom(setOf(PeerCapability.RELAY)) shouldBe 0x08
            PeerCapability.setFromBits(0x0F) shouldBe PeerCapability.entries.toSet()
            // Every bit the codec accepts is a known bit and vice versa - the invariant
            // PeerRecordCodec.decode's reserved-bits check depends on.
            PeerCapability.bitsFrom(PeerCapability.entries.toSet()) shouldBe PeerCapability.KNOWN_BITS_MASK
        }
    })
