package net.lapisphilosophorum.lapisnet.directory

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerId
import io.libp2p.core.multiformats.Multiaddr
import io.libp2p.crypto.keys.unmarshalEd25519PublicKey
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.IdentityBinding
import java.time.Instant

private fun testAddress(port: Int): Multiaddr = Multiaddr("/ip4/127.0.0.1/tcp/$port")

/** [notValidAfterEpochSecond] defaults to a near-future (not far-future) value - since
 * [PeerRecord.create]'s round-4 [PeerRecord.MAX_TTL_WINDOW_SECONDS] cap rejects anything claiming
 * validity more than 24h beyond "now", the old `9_999_999_999L` (year 2286) placeholder this file
 * used before that fix would now throw at construction time. */
private fun freshRecord(
    identity: DualKeyIdentity = DualKeyIdentity.generate(),
    addresses: List<Multiaddr> = listOf(testAddress(4001)),
    capabilities: Set<PeerCapability> = setOf(PeerCapability.DM),
    sequenceNumber: Long = 0,
    notValidAfterEpochSecond: Long = Instant.now().epochSecond + 3600,
): PeerRecord = PeerRecord.create(identity, addresses, capabilities, sequenceNumber, notValidAfterEpochSecond)

class PeerRecordTest :
    FunSpec({
        test("constructor rejects a signature that isn't exactly 64 bytes") {
            val identity = DualKeyIdentity.generate()
            shouldThrow<IllegalArgumentException> {
                PeerRecord.fromDecoded(
                    identity = identity.secp256k1KeyPair.publicKey,
                    binding = identity.binding,
                    addresses = emptyList(),
                    capabilities = emptySet(),
                    sequenceNumber = 0,
                    notValidAfterEpochSecond = 0,
                    signature = ByteArray(63),
                )
            }
        }

        test("constructor rejects a negative sequenceNumber") {
            val identity = DualKeyIdentity.generate()
            shouldThrow<IllegalArgumentException> {
                PeerRecord.fromDecoded(
                    identity = identity.secp256k1KeyPair.publicKey,
                    binding = identity.binding,
                    addresses = emptyList(),
                    capabilities = emptySet(),
                    sequenceNumber = -1,
                    notValidAfterEpochSecond = 0,
                    signature = ByteArray(64),
                )
            }
        }

        test("constructor rejects more addresses than PeerRecordCodec.MAX_ADDRESSES") {
            val identity = DualKeyIdentity.generate()
            val tooMany = (1..(PeerRecordCodec.MAX_ADDRESSES + 1)).map { testAddress(4000 + it) }
            shouldThrow<IllegalArgumentException> {
                PeerRecord.fromDecoded(
                    identity = identity.secp256k1KeyPair.publicKey,
                    binding = identity.binding,
                    addresses = tooMany,
                    capabilities = emptySet(),
                    sequenceNumber = 0,
                    notValidAfterEpochSecond = 0,
                    signature = ByteArray(64),
                )
            }
        }

        test("create() then verify() round-trips true for a real DualKeyIdentity") {
            val record = freshRecord()
            PeerRecord.verify(record) shouldBe true
        }

        test("create() reuses identity.binding verbatim") {
            val identity = DualKeyIdentity.generate()
            val record = freshRecord(identity)
            record.binding shouldBe identity.binding
        }

        test("verify() returns false, not throw, for a record whose signature was flipped by one bit") {
            val record = freshRecord()
            val tampered =
                PeerRecord.fromDecoded(
                    identity = record.identity,
                    binding = record.binding,
                    addresses = record.addresses,
                    capabilities = record.capabilities,
                    sequenceNumber = record.sequenceNumber,
                    notValidAfterEpochSecond = record.notValidAfterEpochSecond,
                    signature = record.signature.also { it[0] = (it[0] + 1).toByte() },
                )
            PeerRecord.verify(tampered) shouldBe false
        }

        test("verify(expectedIdentity, record) is false when expectedIdentity does not match record.identity") {
            val record = freshRecord()
            val other = DualKeyIdentity.generate()
            PeerRecord.verify(record.identity, record) shouldBe true
            PeerRecord.verify(other.secp256k1KeyPair.publicKey, record) shouldBe false
        }

        test("verifyBinding() is true for a real PeerRecord.create() result") {
            val record = freshRecord()
            record.verifyBinding() shouldBe true
        }

        test("verifyBinding() is false for a hand-built record with a mismatched identity/binding pair") {
            val identityA = DualKeyIdentity.generate()
            val identityB = DualKeyIdentity.generate()
            // Structurally decoded fields only, never through create() (which would refuse this
            // combination via its own require(identity.verifyBinding()) guard) - this is exactly
            // the unit-level companion to PeerRecordSpoofingTest's case (a).
            val mismatched =
                PeerRecord.fromDecoded(
                    identity = identityA.secp256k1KeyPair.publicKey,
                    binding = identityB.binding,
                    addresses = emptyList(),
                    capabilities = emptySet(),
                    sequenceNumber = 0,
                    notValidAfterEpochSecond = 0,
                    signature = ByteArray(64),
                )
            mismatched.verifyBinding() shouldBe false
        }

        test("peerId round-trips to the same PeerId a real node would derive from the same identity") {
            val identity = DualKeyIdentity.generate()
            val record = freshRecord(identity)
            val expected = PeerId.fromPubKey(unmarshalEd25519PublicKey(identity.ed25519KeyPair.publicKey.bytes))
            record.peerId shouldBe expected
        }

        test("contentId is deterministic and changes when any one field changes") {
            val identity = DualKeyIdentity.generate()
            val base = freshRecord(identity, sequenceNumber = 0)

            base.contentId().toList() shouldBe base.contentId().toList()

            val differentAddresses = freshRecord(identity, addresses = listOf(testAddress(5000)), sequenceNumber = 0)
            val differentCapabilities =
                freshRecord(identity, capabilities = setOf(PeerCapability.CALL), sequenceNumber = 0)
            val differentSequence = freshRecord(identity, sequenceNumber = 1)
            val differentTtl = freshRecord(identity, sequenceNumber = 0, notValidAfterEpochSecond = 12_345L)

            val ids =
                listOf(base, differentAddresses, differentCapabilities, differentSequence, differentTtl)
                    .map { it.contentId().toList() }
            ids.toSet().size shouldBe 5
        }

        test("equals/hashCode: two independently-decoded copies of the same bytes are equal") {
            val record = freshRecord()
            val decodedA = PeerRecordCodec.decode(PeerRecordCodec.encode(record))
            val decodedB = PeerRecordCodec.decode(PeerRecordCodec.encode(record))

            decodedA shouldBe decodedB
            decodedA.hashCode() shouldBe decodedB.hashCode()
        }

        test("equals: records differing only in capabilities are not equal") {
            val identity = DualKeyIdentity.generate()
            val a = freshRecord(identity, capabilities = setOf(PeerCapability.DM))
            val b = freshRecord(identity, capabilities = setOf(PeerCapability.CALL))

            (a == b) shouldBe false
        }

        test("toString never contains the raw signature bytes or the binding signature bytes") {
            val record = freshRecord()
            val text = record.toString()
            val signatureHex = record.signature.joinToString("") { "%02x".format(it) }
            val bindingSignatureHex = record.binding.signature.joinToString("") { "%02x".format(it) }

            text.contains(signatureHex) shouldBe false
            text.contains(bindingSignatureHex) shouldBe false
        }

        test("create() throws when identity's own IdentityBinding does not verify") {
            val identityA = DualKeyIdentity.generate()
            val identityB = DualKeyIdentity.generate()
            // Construct a DualKeyIdentity whose binding does not actually match its own secp256k1
            // key - identityA's secp256k1 key paired with identityB's Ed25519 binding.
            val broken = DualKeyIdentity(identityA.secp256k1KeyPair, identityB.ed25519KeyPair, identityB.binding)
            broken.verifyBinding() shouldBe false

            shouldThrow<IllegalArgumentException> {
                PeerRecord.create(broken, emptyList(), emptySet(), 0, 0)
            }
        }

        // Security regression (V0.8.1 sub-wave audit round 4, major finding 2): create() must
        // refuse to sign a record whose claimed TTL reaches unreasonably far into the future - see
        // create()'s own doc comment for the "one-time compromised key poisons the directory
        // forever" scenario this closes for the honest-signing path.
        test("create() throws when notValidAfterEpochSecond claims validity beyond MAX_TTL_WINDOW_SECONDS") {
            val identity = DualKeyIdentity.generate()
            val now = 1_000_000L

            shouldThrow<IllegalArgumentException> {
                PeerRecord.create(
                    identity,
                    emptyList(),
                    emptySet(),
                    sequenceNumber = 0,
                    notValidAfterEpochSecond = now + PeerRecord.MAX_TTL_WINDOW_SECONDS + 1,
                    nowEpochSecond = now,
                )
            }
        }

        test("create() accepts notValidAfterEpochSecond exactly at the MAX_TTL_WINDOW_SECONDS boundary") {
            val identity = DualKeyIdentity.generate()
            val now = 1_000_000L

            val record =
                PeerRecord.create(
                    identity,
                    emptyList(),
                    emptySet(),
                    sequenceNumber = 0,
                    notValidAfterEpochSecond = now + PeerRecord.MAX_TTL_WINDOW_SECONDS,
                    nowEpochSecond = now,
                )
            record.notValidAfterEpochSecond shouldBe now + PeerRecord.MAX_TTL_WINDOW_SECONDS
        }

        test(
            "create()'s far-future TTL rejection is a real, effective cap - the historical " +
                "placeholder value used to be legal",
        ) {
            val identity = DualKeyIdentity.generate()
            val now = Instant.now().epochSecond

            // 9_999_999_999L (year ~2286) is the far-future placeholder every test file in this
            // module used before this fix - proving it is now rejected demonstrates the cap has
            // real teeth against exactly the shape of value this finding was about, not just the
            // synthetic boundary above.
            shouldThrow<IllegalArgumentException> {
                PeerRecord.create(identity, emptyList(), emptySet(), 0, 9_999_999_999L, nowEpochSecond = now)
            }
        }

        test("a binding constructed independently for the same identity is bindable and verifiable") {
            // Sanity check that IdentityBinding.verify itself behaves as PeerRecord relies on.
            val identity = DualKeyIdentity.generate()
            IdentityBinding.verify(identity.secp256k1KeyPair.publicKey, identity.binding) shouldBe true
        }
    })
