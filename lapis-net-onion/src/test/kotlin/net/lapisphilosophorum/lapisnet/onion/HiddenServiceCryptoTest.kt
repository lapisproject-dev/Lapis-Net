package net.lapisphilosophorum.lapisnet.onion

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.onion.fake.DeterministicSecureRandom
import net.lapisphilosophorum.lapisnet.onion.fake.FixedClock
import net.lapisphilosophorum.lapisnet.onion.fake.hex

private val NOW = FixedClock.START_MILLIS / 1000

private fun binding(nva: Long = NOW + 86_400) =
    OnionKeyBinding.create(Secp256k1KeyPair.generate(), X25519KeyPair.generate().publicKey, nva)

private fun descriptor(
    count: Int = 3,
    nva: Long = NOW + 3600,
): Pair<OnionServiceDescriptor, Ed25519KeyPair> {
    val key = Ed25519KeyPair.generate()
    val entries = List(count) { IntroPointEntry(binding(), Ed25519KeyPair.generate().publicKey) }
    return OnionServiceDescriptor.create(key, X25519KeyPair.generate().publicKey, entries, 7, nva, NOW) to key
}

class HiddenServiceCryptoTest :
    FunSpec({
        // ---- address -----------------------------------------------------------------------------
        test("an onion address round-trips and is 56 lowercase characters") {
            val addr = OnionServiceAddress(Ed25519KeyPair.generate().publicKey)
            val text = addr.encode()
            text.length shouldBe 56
            (text == text.lowercase()) shouldBe true
            OnionServiceAddress.parse(text) shouldBe addr
            addr.toString().contains(text) shouldBe false
        }

        test("a wrong checksum, version, length, case or alphabet is rejected without echoing the input") {
            val text = OnionServiceAddress(Ed25519KeyPair.generate().publicKey).encode()
            val bad =
                listOf(
                    text.dropLast(1),
                    text + "a",
                    text.uppercase(),
                    text.replaceRange(10, 11, if (text[10] == 'a') "b" else "a"),
                    text.replaceRange(55, 56, if (text[55] == 'a') "q" else "a"),
                    text.replaceRange(0, 1, "1"),
                    "",
                )
            bad.forEach {
                val e = shouldThrow<IllegalArgumentException> { OnionServiceAddress.parse(it) }
                (e.message ?: "").contains(it.take(8)) shouldBe (it.isEmpty())
            }
        }

        // ---- messages ----------------------------------------------------------------------------
        test("every body codec enforces its exact length") {
            val auth = Ed25519KeyPair.generate()
            val est = EstablishIntroBody.create(auth, ByteArray(32) { 1 }, NOW + 60, 3).encode()
            est.size shouldBe HsConstants.ESTABLISH_INTRO_SIZE
            EstablishIntroBody.decode(est).establishSeq shouldBe 3
            shouldThrow<CellFormatException> { EstablishIntroBody.decode(est.copyOf(est.size - 1)) }
            shouldThrow<CellFormatException> { EstablishIntroBody.decode(est + 0) }

            val intro = IntroduceBody(ByteArray(32) { 1 }, ByteArray(32) { 2 }, ByteArray(208) { 3 }).encode()
            intro.size shouldBe HsConstants.INTRODUCE_SIZE
            IntroduceBody.decode(intro).hpkeCiphertext.size shouldBe 208
            shouldThrow<CellFormatException> { IntroduceBody.decode(intro.copyOf(intro.size - 1)) }
            shouldThrow<CellFormatException> { IntroduceBody.decode(intro + 0) }

            val r1 = Rendezvous1Body(ByteArray(20), ByteArray(32), ByteArray(32)).encode()
            r1.size shouldBe HsConstants.RENDEZVOUS1_SIZE
            shouldThrow<CellFormatException> { Rendezvous1Body.decode(r1.copyOf(83)) }
            shouldThrow<CellFormatException> { CookieBody.decode(ByteArray(21)) }
            shouldThrow<CellFormatException> { StatusBody.decode(ByteArray(2)) }
            shouldThrow<CellFormatException> { IntroducePlaintext.decode(ByteArray(191)) }
        }

        test("a tampered ESTABLISH_INTRO does not verify and the signature binds the relay") {
            val auth = Ed25519KeyPair.generate()
            val relayId = ByteArray(32) { 5 }
            val body = EstablishIntroBody.create(auth, relayId, NOW + 60, 1)
            body.verify(relayId) shouldBe true
            body.verify(ByteArray(32) { 6 }) shouldBe false
            val raw = body.encode()
            for (i in 1 until raw.size) {
                val flipped = raw.copyOf().also { it[i] = (it[i].toInt() xor 1).toByte() }
                val ok = runCatching { EstablishIntroBody.decode(flipped).verify(relayId) }.getOrDefault(false)
                ok shouldBe false
            }
        }

        test("messages and bodies are redacted in toString") {
            listOf(
                IntroduceBody(ByteArray(32) { 1 }, ByteArray(32) { 2 }, ByteArray(208) { 3 }),
                Rendezvous1Body(ByteArray(20), ByteArray(32), ByteArray(32)),
                EstablishIntroBody.create(Ed25519KeyPair.generate(), ByteArray(32), NOW + 1, 1),
            ).forEach { it.toString().contains("REDACTED") shouldBe true }
        }

        // ---- descriptor --------------------------------------------------------------------------
        test("a valid descriptor verifies and round-trips with 1, 2 and 3 introduction points") {
            for (n in 1..3) {
                val (d, key) = descriptor(n)
                OnionServiceDescriptor.verify(d, NOW) shouldBe true
                val bytes = OnionServiceDescriptorCodec.encode(d)
                bytes.size shouldBe OnionServiceDescriptorCodec.encodedSize(n)
                (bytes.size <= OnionServiceDescriptorCodec.MAX_ENCODED_SIZE) shouldBe true
                OnionServiceDescriptorCodec.decode(bytes) shouldBe d
                d.address().serviceKey shouldBe key.publicKey
            }
        }

        test("an expired, over-long, duplicated or foreign-signed descriptor does not verify") {
            val (d, _) = descriptor()
            OnionServiceDescriptor.verify(d, NOW + 3601) shouldBe false
            shouldThrow<IllegalArgumentException> { descriptor(nva = NOW + 7 * 3600) }
            // outliving a binding
            val key = Ed25519KeyPair.generate()
            shouldThrow<IllegalArgumentException> {
                OnionServiceDescriptor.create(
                    key,
                    X25519KeyPair.generate().publicKey,
                    listOf(IntroPointEntry(binding(NOW + 100), Ed25519KeyPair.generate().publicKey)),
                    1,
                    NOW + 3600,
                    NOW,
                )
            }
            // duplicate relay and duplicate auth key
            val b = binding()
            shouldThrow<IllegalArgumentException> {
                OnionServiceDescriptor.create(
                    key,
                    X25519KeyPair.generate().publicKey,
                    listOf(
                        IntroPointEntry(b, Ed25519KeyPair.generate().publicKey),
                        IntroPointEntry(b, Ed25519KeyPair.generate().publicKey),
                    ),
                    1,
                    NOW + 60,
                    NOW,
                )
            }
            val auth = Ed25519KeyPair.generate().publicKey
            shouldThrow<IllegalArgumentException> {
                OnionServiceDescriptor.create(
                    key,
                    X25519KeyPair.generate().publicKey,
                    listOf(IntroPointEntry(binding(), auth), IntroPointEntry(binding(), auth)),
                    1,
                    NOW + 60,
                    NOW,
                )
            }
            shouldThrow<IllegalArgumentException> {
                OnionServiceDescriptor.create(key, X25519KeyPair.generate().publicKey, emptyList(), 1, NOW + 60, NOW)
            }
            shouldThrow<IllegalArgumentException> {
                OnionServiceDescriptor.create(
                    key,
                    X25519KeyPair.generate().publicKey,
                    List(4) { IntroPointEntry(binding(), Ed25519KeyPair.generate().publicKey) },
                    1,
                    NOW + 60,
                    NOW,
                )
            }
        }

        test("flipping any single byte of an encoded descriptor makes it undecodable or invalid") {
            val (d, _) = descriptor(2)
            val bytes = OnionServiceDescriptorCodec.encode(d)
            for (i in bytes.indices) {
                val flipped = bytes.copyOf().also { it[i] = (it[i].toInt() xor 0x01).toByte() }
                val ok =
                    try {
                        OnionServiceDescriptor.verify(OnionServiceDescriptorCodec.decode(flipped), NOW)
                    } catch (e: CellFormatException) {
                        false
                    }
                ok shouldBe false
            }
        }

        test("decode throws only CellFormatException on arbitrary input") {
            val rnd = DeterministicSecureRandom("descriptor-fuzz")
            for (len in listOf(0, 1, 145, 146, 314, 315, 483, 484, 653, 654, 700)) {
                val bytes = ByteArray(len).also { rnd.nextBytes(it) }
                try {
                    OnionServiceDescriptorCodec.decode(bytes)
                } catch (e: CellFormatException) {
                    // expected
                }
            }
        }

        // ---- INTRODUCE crypto --------------------------------------------------------------------
        test("INTRODUCE encryption round-trips and fails for a wrong key, auth key, service or tampering") {
            val enc = X25519KeyPair.generate()
            val auth = Ed25519KeyPair.generate().publicKey
            val id = ByteArray(32) { 4 }
            val plain = ByteArray(HsConstants.INTRODUCE_PLAINTEXT_SIZE) { it.toByte() }
            val (e, ct) = IntroduceCrypto.seal(id, enc.publicKey, auth, plain)
            e.size shouldBe 32
            ct.size shouldBe HsConstants.INTRODUCE_PLAINTEXT_SIZE + 16
            IntroduceCrypto.open(id, enc.privateKey, enc.publicKey, auth, e, ct).contentEquals(plain) shouldBe true

            val other = X25519KeyPair.generate()
            shouldThrow<OnionHandshakeException> {
                IntroduceCrypto.open(
                    id,
                    other.privateKey,
                    other.publicKey,
                    auth,
                    e,
                    ct,
                )
            }
            shouldThrow<OnionHandshakeException> {
                IntroduceCrypto.open(id, enc.privateKey, enc.publicKey, Ed25519KeyPair.generate().publicKey, e, ct)
            }
            shouldThrow<OnionHandshakeException> {
                IntroduceCrypto.open(ByteArray(32), enc.privateKey, enc.publicKey, auth, e, ct)
            }
            for (i in listOf(0, 17, ct.size - 1)) {
                val bad = ct.copyOf().also { it[i] = (it[i].toInt() xor 1).toByte() }
                shouldThrow<OnionHandshakeException> {
                    IntroduceCrypto.open(
                        id,
                        enc.privateKey,
                        enc.publicKey,
                        auth,
                        e,
                        bad,
                    )
                }
            }
            val badEnc = e.copyOf().also { it[3] = (it[3].toInt() xor 1).toByte() }
            shouldThrow<OnionHandshakeException> {
                IntroduceCrypto.open(
                    id,
                    enc.privateKey,
                    enc.publicKey,
                    auth,
                    badEnc,
                    ct,
                )
            }
        }

        test("a low-order encapsulated key is rejected") {
            val enc = X25519KeyPair.generate()
            val auth = Ed25519KeyPair.generate().publicKey
            val id = ByteArray(32)
            val lowOrder =
                listOf(
                    ByteArray(32),
                    ByteArray(32).also { it[0] = 1 },
                    net.lapisphilosophorum.lapisnet.onion.fake
                        .unhex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
                )
            lowOrder.forEach {
                shouldThrow<OnionHandshakeException> {
                    IntroduceCrypto.open(id, enc.privateKey, enc.publicKey, auth, it, ByteArray(208))
                }
            }
        }

        // ---- end-to-end handshake and layer ------------------------------------------------------
        test("the end-to-end handshake yields matching directions and 910 bytes of payload per blob") {
            val service = Ed25519KeyPair.generate()
            val address = OnionServiceAddress(service.publicKey)
            val enc = X25519KeyPair.generate()
            val state = RendezvousHandshake.senderStart(address, enc.publicKey)
            val (reply, receiver) =
                RendezvousHandshake.receiverRespond(
                    address.serviceIdDigest(),
                    enc.privateKey,
                    enc.publicKey,
                    state.clientEphemeral,
                )
            val sender = RendezvousHandshake.senderFinish(state, reply.serverEphemeral + reply.auth)
            sender.maxPayload shouldBe 910
            val msg = ByteArray(910) { (it * 3).toByte() }
            val blob = sender.seal(E2eType.DATA, msg)
            blob.size shouldBe HsConstants.E2E_BLOB_SIZE
            val (t, got) = receiver.open(blob)
            t shouldBe E2eType.DATA
            got.contentEquals(msg) shouldBe true
            val back = receiver.seal(E2eType.END, ByteArray(0))
            back.size shouldBe HsConstants.E2E_BLOB_SIZE
            sender.open(back).first shouldBe E2eType.END
            shouldThrow<IllegalArgumentException> { sender.seal(E2eType.DATA, ByteArray(911)) }
            sender.close()
            receiver.close()
            sender.zeroizedForTest() shouldBe true
            receiver.zeroizedForTest() shouldBe true
        }

        test("a wrong AUTH, a foreign service id or a replayed, reordered or tampered blob fails") {
            val address = OnionServiceAddress(Ed25519KeyPair.generate().publicKey)
            val enc = X25519KeyPair.generate()
            val state = RendezvousHandshake.senderStart(address, enc.publicKey)
            val (reply, receiver) =
                RendezvousHandshake.receiverRespond(
                    address.serviceIdDigest(),
                    enc.privateKey,
                    enc.publicKey,
                    state.clientEphemeral,
                )
            val badAuth = reply.auth.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
            val s2 = RendezvousHandshake.senderStart(address, enc.publicKey)
            val (r2, _) =
                RendezvousHandshake.receiverRespond(
                    address.serviceIdDigest(),
                    enc.privateKey,
                    enc.publicKey,
                    s2.clientEphemeral,
                )
            shouldThrow<OnionHandshakeException> {
                RendezvousHandshake.senderFinish(s2, r2.serverEphemeral + badAuth)
            }
            shouldThrow<OnionHandshakeException> {
                RendezvousHandshake.senderFinish(RendezvousHandshake.senderStart(address, enc.publicKey), ByteArray(10))
            }

            // a different service id: the AUTH cannot match
            val s3 = RendezvousHandshake.senderStart(address, enc.publicKey)
            val (r3, _) =
                RendezvousHandshake.receiverRespond(
                    ByteArray(32) { 1 },
                    enc.privateKey,
                    enc.publicKey,
                    s3.clientEphemeral,
                )
            shouldThrow<OnionHandshakeException> { RendezvousHandshake.senderFinish(s3, r3.serverEphemeral + r3.auth) }

            val sender = RendezvousHandshake.senderFinish(state, reply.serverEphemeral + reply.auth)
            val b1 = sender.seal(E2eType.DATA, byteArrayOf(1))
            val b2 = sender.seal(E2eType.DATA, byteArrayOf(2))
            // out of order -> integrity failure, then poisoned
            shouldThrow<OnionIntegrityException> { receiver.open(b2) }
            shouldThrow<IllegalStateException> { receiver.open(b1) }
        }

        test("replayed and tampered end-to-end blobs are rejected") {
            val address = OnionServiceAddress(Ed25519KeyPair.generate().publicKey)
            val enc = X25519KeyPair.generate()

            fun pair(): Pair<RendezvousEndToEnd, RendezvousEndToEnd> {
                val st = RendezvousHandshake.senderStart(address, enc.publicKey)
                val (r, rx) =
                    RendezvousHandshake.receiverRespond(
                        address.serviceIdDigest(),
                        enc.privateKey,
                        enc.publicKey,
                        st.clientEphemeral,
                    )
                return RendezvousHandshake.senderFinish(st, r.serverEphemeral + r.auth) to rx
            }
            val (s, r) = pair()
            val blob = s.seal(E2eType.DATA, byteArrayOf(9))
            r.open(blob)
            shouldThrow<OnionIntegrityException> { r.open(blob) } // duplicate
            val (s2, r2) = pair()
            val b = s2.seal(E2eType.DATA, byteArrayOf(9))
            shouldThrow<OnionIntegrityException> {
                r2.open(
                    b.copyOf().also { it[100] = (it[100].toInt() xor 1).toByte() },
                )
            }
            val (_, r3) = pair()
            shouldThrow<OnionIntegrityException> { r3.open(ByteArray(10)) }
            // a blob sealed by the receiver cannot be opened by the receiver (direction separation)
            val (s4, r4) = pair()
            val own = r4.seal(E2eType.DATA, byteArrayOf(1))
            shouldThrow<OnionIntegrityException> { r4.open(own) }
            s4.close()
        }

        test("relay and hidden-service labels derive different keys from identical inputs") {
            val rnd = DeterministicSecureRandom("labels")
            val id = ByteArray(32) { 2 }
            val b = X25519KeyPair.generate(DeterministicSecureRandom("b"))

            fun run(labels: NtorLabels): Pair<String, String> {
                val r1 = DeterministicSecureRandom("x")
                val r2 = DeterministicSecureRandom("y")
                val (st, x) = NtorHandshake.clientStartRaw(id, b.publicKey, r1)
                val res = NtorHandshake.serverRespondRaw(id, b.publicKey, b.privateKey, x, labels, r2)
                val fin = NtorHandshake.clientFinishRaw(st, res.created, labels)
                return hex(fin.forwardKeyCopy()) to hex(res.created.auth)
            }
            val relay = run(NtorLabels.RELAY)
            val hs = run(NtorLabels.HS)
            relay.first shouldNotBe hs.first
            relay.second shouldNotBe hs.second
            rnd.nextInt() // keep the generator referenced
        }

        test("a hop cipher with another AAD label cannot open the default label's ciphertext") {
            val key = ByteArray(32) { 7 }
            val a = HopCipher(key.copyOf(), Direction.FORWARD, 1)
            val b = HopCipher(key.copyOf(), Direction.FORWARD, 1, aadLabel = "other")
            val c = HopCipher(key.copyOf(), Direction.FORWARD, 1)
            val ct = a.seal(ByteArray(20))
            shouldThrow<OnionIntegrityException> { b.open(ct) }
            c.open(ct).size shouldBe 20
        }

        test(
            "forward secrecy: with the service and encryption keys but not the ephemerals, session keys are not recoverable",
        ) {
            val address = OnionServiceAddress(Ed25519KeyPair.generate().publicKey)
            val enc = X25519KeyPair.generate()
            val st = RendezvousHandshake.senderStart(address, enc.publicKey)
            val (reply, receiver) =
                RendezvousHandshake.receiverRespond(
                    address.serviceIdDigest(),
                    enc.privateKey,
                    enc.publicKey,
                    st.clientEphemeral,
                )
            val sender = RendezvousHandshake.senderFinish(st, reply.serverEphemeral + reply.auth)
            val blob = sender.seal(E2eType.DATA, "secret".toByteArray())
            // The ephemeral scalars were destroyed during the handshake; the long-term key alone cannot rebuild the session:
            // a fresh session keyed with a new ephemeral cannot open this blob although it uses the same long-term keys.
            val st2 = RendezvousHandshake.senderStart(address, enc.publicKey)
            val (r2, receiver2) =
                RendezvousHandshake.receiverRespond(
                    address.serviceIdDigest(),
                    enc.privateKey,
                    enc.publicKey,
                    st2.clientEphemeral,
                )
            RendezvousHandshake.senderFinish(st2, r2.serverEphemeral + r2.auth)
            shouldThrow<OnionIntegrityException> { receiver2.open(blob) }
            receiver.open(blob).second.decodeToString() shouldBe "secret"
            st.ntor.x.bytes
                .all { it == 0.toByte() } shouldBe true
        }
    })
