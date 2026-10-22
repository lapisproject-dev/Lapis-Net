@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onion

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.onion.fake.FixedClock
import net.lapisphilosophorum.lapisnet.onion.fake.InMemoryOnionNetwork
import net.lapisphilosophorum.lapisnet.onion.fake.Probe
import net.lapisphilosophorum.lapisnet.onion.fake.newTestRelay
import java.security.SecureRandom
import kotlin.time.Duration.Companion.seconds

private class Fixture(
    limits: OnionRelayLimits = OnionRelayLimits(),
) {
    val clock = FixedClock()
    val relay = newTestRelay(clock = clock, limits = limits)
    val net = InMemoryOnionNetwork(listOf(relay))
    val rnd = SecureRandom()

    fun probe() = Probe(net, clock)

    fun establishBody(
        auth: Ed25519KeyPair = Ed25519KeyPair.generate(),
        seq: Long = 1,
        nvaOffset: Long = 600,
        forRelay: ByteArray = relay.binding.relayIdDigest(),
    ) = EstablishIntroBody.create(auth, forRelay, clock.millis() / 1000 + nvaOffset, seq).encode()

    fun introduceBody(auth: Ed25519KeyPair): ByteArray {
        val b = ByteArray(HsConstants.INTRODUCE_SIZE)
        rnd.nextBytes(b)
        b[0] = HsConstants.VERSION
        auth.publicKey.bytes.copyInto(b, 1)
        return b
    }

    fun cookie() = ByteArray(HsConstants.COOKIE_SIZE).also { rnd.nextBytes(it) }

    fun establishIntro(auth: Ed25519KeyPair = Ed25519KeyPair.generate()): Pair<Probe, Ed25519KeyPair> {
        val p = probe()
        val r = p.send(RelayCommand.ESTABLISH_INTRO, establishBody(auth))
        r.single().command shouldBe RelayCommand.INTRO_ESTABLISHED
        return p to auth
    }

    fun establishRdv(cookie: ByteArray = cookie()): Pair<Probe, ByteArray> {
        val p = probe()
        p.send(RelayCommand.ESTABLISH_RENDEZVOUS, cookie).single().command shouldBe RelayCommand.RENDEZVOUS_ESTABLISHED
        return p to cookie
    }

    fun rdv1(cookie: ByteArray) = cookie + ByteArray(64) { it.toByte() }

    fun blob(seed: Int) = ByteArray(HsConstants.E2E_BLOB_SIZE) { (it * seed).toByte() }

    fun allZero() {
        relay.relay.circuitCount shouldBe 0
        relay.relay.introPointCount shouldBe 0
        relay.relay.pendingRendezvousCount shouldBe 0
        relay.relay.splicedPairCount shouldBe 0
    }
}

class OnionRelayRolesTest :
    FunSpec({
        test("a valid ESTABLISH_INTRO registers the introduction point and is acknowledged") {
            val f = Fixture()
            val (p, _) = f.establishIntro()
            f.relay.relay.introPointCount shouldBe 1
            p.close()
            f.allZero()
        }

        test("ESTABLISH_INTRO with a wrong relay digest, a bad signature or an expired time destroys the circuit") {
            val f = Fixture()
            val other = ByteArray(32) { 9 }
            f.probe().also {
                it.send(RelayCommand.ESTABLISH_INTRO, f.establishBody(forRelay = other))
                it.destroyed shouldBe true
            }
            f.probe().also {
                it.send(RelayCommand.ESTABLISH_INTRO, f.establishBody(nvaOffset = -5))
                it.destroyed shouldBe true
            }
            f.probe().also {
                it.send(RelayCommand.ESTABLISH_INTRO, f.establishBody(nvaOffset = 100_000))
                it.destroyed shouldBe true
            }
            f.probe().also {
                val body = f.establishBody()
                body[body.size - 1] = (body.last().toInt() xor 1).toByte()
                it.send(RelayCommand.ESTABLISH_INTRO, body)
                it.destroyed shouldBe true
            }
            f.probe().also {
                it.send(RelayCommand.ESTABLISH_INTRO, ByteArray(HsConstants.ESTABLISH_INTRO_SIZE - 1))
                it.destroyed shouldBe true
            }
            f.allZero()
        }

        test("an equal or smaller establishSeq is refused, a larger one replaces and closes the old circuit") {
            val f = Fixture()
            val auth = Ed25519KeyPair.generate()
            val old = f.probe()
            old.send(RelayCommand.ESTABLISH_INTRO, f.establishBody(auth, seq = 5)).single().command shouldBe
                RelayCommand.INTRO_ESTABLISHED
            f.probe().also {
                it.send(RelayCommand.ESTABLISH_INTRO, f.establishBody(auth, seq = 5))
                it.destroyed shouldBe true
            }
            f.probe().also {
                it.send(RelayCommand.ESTABLISH_INTRO, f.establishBody(auth, seq = 4))
                it.destroyed shouldBe true
            }
            f.relay.relay.introPointCount shouldBe 1
            old.destroyed shouldBe false
            val fresh = f.probe()
            fresh.send(RelayCommand.ESTABLISH_INTRO, f.establishBody(auth, seq = 6)).single().command shouldBe
                RelayCommand.INTRO_ESTABLISHED
            old.drain()
            old.destroyed shouldBe true
            f.relay.relay.introPointCount shouldBe 1
            fresh.close()
            f.allZero()
        }

        test("a second role, EXTEND or DATA on a role circuit destroys it") {
            val f = Fixture()
            val (p1, _) = f.establishIntro()
            p1.send(RelayCommand.ESTABLISH_INTRO, f.establishBody())
            p1.destroyed shouldBe true
            val (p2, _) = f.establishIntro()
            p2.send(RelayCommand.EXTEND, ByteArray(10))
            p2.destroyed shouldBe true
            val (p3, _) = f.establishIntro()
            p3.send(RelayCommand.DATA, ByteArray(10))
            p3.destroyed shouldBe true
            val (p4, _) = f.establishRdv()
            p4.send(RelayCommand.DATA, ByteArray(10))
            p4.destroyed shouldBe true
            f.allZero()
        }

        test("role messages are refused at a hop that is not the last one") {
            val clock = FixedClock()
            val net = InMemoryOnionNetwork(List(2) { newTestRelay(clock = clock) })
            val client = net.newClient(0)
            val circuit = net.buildCircuitFor(client, listOf(0, 1), SecureRandom(), clock)
            val body =
                EstablishIntroBody
                    .create(
                        Ed25519KeyPair.generate(),
                        net.relays[0].binding.relayIdDigest(),
                        clock.millis() / 1000 + 600,
                        1,
                    ).encode()
            net.clientSend(
                0,
                client.link,
                Cell(
                    client.circuitId,
                    CellCommand.RELAY,
                    circuit.wrapForward(RelayMessage(RelayCommand.ESTABLISH_INTRO, 0, body), 1),
                ),
            )
            net.relays[0].relay.introPointCount shouldBe 0
            net.relays[0].relay.circuitCount shouldBe 0
            net.relays[1].relay.circuitCount shouldBe 0
        }

        test("replies and forwarded commands that can never arrive at a relay destroy the circuit") {
            val f = Fixture()
            listOf(
                RelayCommand.INTRO_ESTABLISHED,
                RelayCommand.INTRODUCE2,
                RelayCommand.INTRODUCE_ACK,
                RelayCommand.RENDEZVOUS_ESTABLISHED,
                RelayCommand.RENDEZVOUS2,
            ).forEach {
                val p = f.probe()
                p.send(it, ByteArray(4))
                p.destroyed shouldBe true
            }
            f.allZero()
        }

        test(
            "INTRODUCE1 is forwarded as INTRODUCE2 and acknowledged; replays, unknown keys and malformed bodies are not",
        ) {
            val f = Fixture()
            val (ip, auth) = f.establishIntro()
            val sender = f.probe()
            val body = f.introduceBody(auth)
            val ack = sender.send(RelayCommand.INTRODUCE1, body).single()
            ack.command shouldBe RelayCommand.INTRODUCE_ACK
            ack.data[0] shouldBe IntroduceStatus.FORWARDED
            val forwarded = ip.drain().single()
            forwarded.command shouldBe RelayCommand.INTRODUCE2
            forwarded.data.contentEquals(body) shouldBe true

            // replay of the same bytes on a fresh circuit
            val replay = f.probe().send(RelayCommand.INTRODUCE1, body).single()
            replay.data[0] shouldBe IntroduceStatus.UNKNOWN
            ip.drain().isEmpty() shouldBe true

            // unknown auth key
            f
                .probe()
                .send(
                    RelayCommand.INTRODUCE1,
                    f.introduceBody(Ed25519KeyPair.generate()),
                ).single()
                .data[0] shouldBe
                IntroduceStatus.UNKNOWN
            // malformed
            f
                .probe()
                .send(RelayCommand.INTRODUCE1, ByteArray(50))
                .single()
                .data[0] shouldBe IntroduceStatus.MALFORMED

            // a second INTRODUCE1 on the same circuit
            sender.send(RelayCommand.INTRODUCE1, f.introduceBody(auth))
            sender.destroyed shouldBe true
        }

        test("INTRODUCE1 is rate limited per introduction point before any other work") {
            val f = Fixture(OnionRelayLimits(introduce1PerSecondPerIntroPoint = 2))
            val (ip, auth) = f.establishIntro()
            val statuses =
                List(5) {
                    f
                        .probe()
                        .send(RelayCommand.INTRODUCE1, f.introduceBody(auth))
                        .single()
                        .data[0]
                }
            statuses.count { it == IntroduceStatus.FORWARDED } shouldBe 2
            statuses.count { it == IntroduceStatus.RATE_LIMITED } shouldBe 3
            ip.drain().size shouldBe 2
        }

        test("rendezvous splice carries end-to-end blobs in both directions and RENDEZVOUS2 to the waiting side") {
            val f = Fixture()
            val seen = mutableListOf<ByteArray>()
            f.relay.relay.rendezvousDataObserver = { seen += it }
            val (a, cookie) = f.establishRdv()
            f.relay.relay.pendingRendezvousCount shouldBe 1
            val b = f.probe()
            b.send(RelayCommand.RENDEZVOUS1, f.rdv1(cookie)).isEmpty() shouldBe true
            val r2 = a.drain().single()
            r2.command shouldBe RelayCommand.RENDEZVOUS2
            r2.data.size shouldBe 64
            f.relay.relay.pendingRendezvousCount shouldBe 0
            f.relay.relay.splicedPairCount shouldBe 1

            val blobAB = f.blob(3)
            a.send(RelayCommand.RENDEZVOUS_DATA, blobAB).isEmpty() shouldBe true
            val gotB = b.drain().single()
            gotB.command shouldBe RelayCommand.RENDEZVOUS_DATA
            gotB.data.contentEquals(blobAB) shouldBe true
            val blobBA = f.blob(5)
            b.send(RelayCommand.RENDEZVOUS_DATA, blobBA)
            a
                .drain()
                .single()
                .data
                .contentEquals(blobBA) shouldBe true
            seen.size shouldBe 2

            // teardown of one half takes the other with it
            a.close()
            b.drain()
            b.destroyed shouldBe true
            f.allZero()
        }

        test("cookie is single use, unknown cookies, duplicates and self-splice destroy the circuit") {
            val f = Fixture()
            val (a, cookie) = f.establishRdv()
            f.probe().also {
                it.send(RelayCommand.RENDEZVOUS1, f.rdv1(f.cookie()))
                it.destroyed shouldBe true
            }
            f.relay.relay.splicedPairCount shouldBe 0
            f.probe().also {
                it.send(RelayCommand.ESTABLISH_RENDEZVOUS, cookie)
                it.destroyed shouldBe true
            }
            // self splice: RENDEZVOUS1 on the waiting circuit
            a.send(RelayCommand.RENDEZVOUS1, f.rdv1(cookie))
            a.destroyed shouldBe true
            f.allZero()

            val (a2, c2) = f.establishRdv()
            val b = f.probe()
            b.send(RelayCommand.RENDEZVOUS1, f.rdv1(c2))
            a2.drain()
            // the cookie is gone now
            f.probe().also {
                it.send(RelayCommand.RENDEZVOUS1, f.rdv1(c2))
                it.destroyed shouldBe true
            }
            f.relay.relay.splicedPairCount shouldBe 1
            a2.close()
            f.allZero()
        }

        test("a wrong-sized blob destroys both halves, RENDEZVOUS_DATA without a splice is refused") {
            val f = Fixture()
            val (a, cookie) = f.establishRdv()
            val b = f.probe()
            b.send(RelayCommand.RENDEZVOUS1, f.rdv1(cookie))
            a.drain()
            a.send(RelayCommand.RENDEZVOUS_DATA, ByteArray(HsConstants.E2E_BLOB_SIZE - 1))
            a.destroyed shouldBe true
            b.drain()
            b.destroyed shouldBe true
            f.allZero()
            f.probe().also {
                it.send(RelayCommand.RENDEZVOUS_DATA, f.blob(1))
                it.destroyed shouldBe true
            }
            val (w, _) = f.establishRdv()
            w.send(RelayCommand.RENDEZVOUS_DATA, f.blob(1))
            w.destroyed shouldBe true
            f.allZero()
        }

        test("a waiting rendezvous circuit is swept after the wait timeout") {
            val f = Fixture(OnionRelayLimits(rendezvousWaitTimeout = 30.seconds))
            val (a, _) = f.establishRdv()
            f.clock.advanceMillis(31_000)
            f.net.apply(0, f.relay.relay.sweepExpired())
            a.drain()
            a.destroyed shouldBe true
            f.allZero()
        }

        test("capacity limits answer with RESOURCE_LIMIT and leak nothing") {
            val f =
                Fixture(
                    OnionRelayLimits(
                        maxIntroPointsTotal = 1,
                        maxIntroPointsPerLink = 1,
                        maxPendingRendezvousTotal = 2,
                        maxPendingRendezvousPerLink = 2,
                        maxSplicedPairsTotal = 1,
                    ),
                )
            f.establishIntro()
            f.probe().also {
                it.send(RelayCommand.ESTABLISH_INTRO, f.establishBody())
                it.destroyed shouldBe true
                it.destroyReason shouldBe DestroyReason.RESOURCE_LIMIT
            }
            val (a1, c1) = f.establishRdv()
            val (a2, c2) = f.establishRdv()
            f.probe().also {
                it.send(RelayCommand.ESTABLISH_RENDEZVOUS, f.cookie())
                it.destroyed shouldBe true
                it.destroyReason shouldBe DestroyReason.RESOURCE_LIMIT
            }
            f.probe().send(RelayCommand.RENDEZVOUS1, f.rdv1(c1))
            a1.drain()
            f.relay.relay.splicedPairCount shouldBe 1
            f.probe().also {
                it.send(RelayCommand.RENDEZVOUS1, f.rdv1(c2))
                it.destroyed shouldBe true
                it.destroyReason shouldBe DestroyReason.RESOURCE_LIMIT
            }
            f.relay.relay.splicedPairCount shouldBe 1
            a2.close()
            a1.close()
        }

        test("hidden-service limits are validated") {
            listOf(
                { OnionRelayLimits(maxIntroPointsTotal = 0) },
                { OnionRelayLimits(maxIntroPointsPerLink = 300) },
                { OnionRelayLimits(maxPendingRendezvousPerLink = 1000) },
                { OnionRelayLimits(rendezvousWaitTimeout = 11.seconds * 100) },
                { OnionRelayLimits(introduce1PerSecondPerIntroPoint = -1) },
            ).forEach {
                var threw = false
                try {
                    it()
                } catch (e: IllegalArgumentException) {
                    threw = true
                }
                threw shouldBe true
            }
        }
    })
