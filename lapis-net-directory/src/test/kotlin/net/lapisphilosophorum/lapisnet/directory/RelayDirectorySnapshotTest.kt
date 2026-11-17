package net.lapisphilosophorum.lapisnet.directory

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerId
import io.libp2p.core.multiformats.Multiaddr
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import java.security.SecureRandom
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.atomic.AtomicLong

/** A clock tests move by hand. */
internal class MovableClock(
    start: Long = System.currentTimeMillis(),
) : Clock() {
    val millis = AtomicLong(start)

    override fun getZone(): ZoneOffset = ZoneOffset.UTC

    override fun withZone(zone: java.time.ZoneId?): Clock = this

    override fun instant(): Instant = Instant.ofEpochMilli(millis.get())

    override fun millis(): Long = millis.get()

    fun advanceSeconds(s: Long) {
        millis.addAndGet(s * 1000)
    }
}

/** A relay with a descriptor and a matching peer record. */
private class SnapshotRelay {
    val relay = OnionRelayPublisher()
    val identity: DualKeyIdentity get() = relay.identity
    val now = Instant.now().epochSecond
    val descriptor: OnionRelayDescriptor = relay.descriptor(sequence = 1)

    fun record(
        owner: DualKeyIdentity = identity,
        addresses: List<Multiaddr> = listOf(Multiaddr("/ip4/127.0.0.1/tcp/4001")),
        notValidAfter: Long = now + 3600,
    ): PeerRecord = PeerRecord.create(owner, addresses, emptySet(), 1, notValidAfter, now)

    fun entry(record: PeerRecord? = record()): Pair<OnionRelayDescriptor, ByteArray?> =
        descriptor to record?.let { PeerRecordCodec.encode(it) }
}

private fun snapshotOf(vararg entries: Pair<OnionRelayDescriptor, ByteArray?>): RelayDirectorySnapshot =
    OnionRelayDirectoryCodec.decodeResponse(OnionRelayDirectoryCodec.encodeResponse(entries.toList()))

private class RecordSink {
    val taken = ArrayList<PeerRecord>()
    val sink: (PeerRecord, ByteArray) -> Boolean = { r, _ ->
        taken += r
        true
    }
}

class RelayDirectorySnapshotTest :
    FunSpec({
        context("codec") {
            test("round trip with and without records, and the request is exactly five bytes") {
                val a = SnapshotRelay()
                val b = SnapshotRelay()
                val decoded = snapshotOf(a.entry(), b.entry(record = null))
                decoded.entries.size shouldBe 2
                decoded.entries[0].descriptor shouldBe a.descriptor
                PeerRecordCodec.decode(decoded.entries[0].recordBytes!!).identity shouldBe a.descriptor.identity
                decoded.entries[1].recordBytes shouldBe null
                OnionRelayDirectoryCodec.encodeRequest().size shouldBe 5
                OnionRelayDirectoryCodec.isValidRequest(OnionRelayDirectoryCodec.encodeRequest()) shouldBe true
                OnionRelayDirectoryCodec.isValidRequest(OnionRelayDirectoryCodec.encodeRequest() + 0) shouldBe false
                OnionRelayDirectoryCodec.isValidRequest(byteArrayOf(76, 78, 82, 68, 2)) shouldBe false
            }

            test("truncated, trailing, wrong magic or version, too many entries and oversized records are rejected") {
                val a = SnapshotRelay()
                val bytes = OnionRelayDirectoryCodec.encodeResponse(listOf(a.entry()))
                shouldThrow<MalformedRelayDirectorySnapshotException> {
                    OnionRelayDirectoryCodec.decodeResponse(bytes.copyOf(bytes.size - 1))
                }
                shouldThrow<MalformedRelayDirectorySnapshotException> {
                    OnionRelayDirectoryCodec.decodeResponse(
                        bytes + 0,
                    )
                }
                shouldThrow<MalformedRelayDirectorySnapshotException> {
                    OnionRelayDirectoryCodec.decodeResponse(bytes.copyOf().also { it[0] = 'X'.code.toByte() })
                }
                shouldThrow<MalformedRelayDirectorySnapshotException> {
                    OnionRelayDirectoryCodec.decodeResponse(bytes.copyOf().also { it[4] = 9 })
                }
                // count 257 in the header: refused from the header alone, before anything is allocated
                val tooMany =
                    bytes.copyOf(OnionRelayDirectoryCodec.HEADER_SIZE).also {
                        it[5] = 0x01
                        it[6] = 0x01
                    }
                shouldThrow<MalformedRelayDirectorySnapshotException> {
                    OnionRelayDirectoryCodec.expectedResponseLength(tooMany, tooMany.size)
                }
                // recordLen 1025
                val big = bytes.copyOf()
                val at = OnionRelayDirectoryCodec.HEADER_SIZE + OnionRelayDescriptorCodec.ENCODED_SIZE
                big[at] = 0x04
                big[at + 1] = 0x01
                shouldThrow<MalformedRelayDirectorySnapshotException> { OnionRelayDirectoryCodec.decodeResponse(big) }
                shouldThrow<MalformedRelayDirectorySnapshotException> {
                    OnionRelayDirectoryCodec.decodeResponse(
                        ByteArray(
                            OnionRelayDirectoryCodec.MAX_SNAPSHOT_RESPONSE_BYTES + 1,
                        ),
                    )
                }
                // a structurally broken descriptor rejects the whole response
                val broken = bytes.copyOf().also { it[OnionRelayDirectoryCodec.HEADER_SIZE] = 7 }
                shouldThrow<MalformedRelayDirectorySnapshotException> {
                    OnionRelayDirectoryCodec.decodeResponse(
                        broken,
                    )
                }
                // the encoder refuses what the decoder would refuse
                shouldThrow<IllegalArgumentException> {
                    OnionRelayDirectoryCodec.encodeResponse(listOf(a.descriptor to ByteArray(1025)))
                }
            }
        }

        context("server") {
            test("the snapshot is cached for 30 s, omits a record of another peer id and picks at most 256 at random") {
                val clock = MovableClock()
                val index = OnionRelayDescriptorIndex()
                val good = SnapshotRelay()
                val foreign = SnapshotRelay()
                val now = clock.millis() / 1000
                index.add(good.descriptor, now)
                index.add(foreign.descriptor, now)
                // the record looked up for `foreign` belongs to someone else: it must be left out
                val stranger = SnapshotRelay()
                val records =
                    mapOf(good.descriptor.identity to good.record(), foreign.descriptor.identity to stranger.record())
                val server = OnionRelayDirectoryServer(index, { id, _ -> records[id] }, clock)
                val snap = OnionRelayDirectoryCodec.decodeResponse(server.snapshotBytes())
                snap.entries.size shouldBe 2
                PeerRecordCodec
                    .decode(
                        snap.entries
                            .first {
                                it.descriptor.identity == good.descriptor.identity
                            }.recordBytes!!,
                    ).identity shouldBe
                    good.descriptor.identity
                snap.entries.first { it.descriptor.identity == foreign.descriptor.identity }.recordBytes shouldBe null
                server.snapshotBytes()
                server.rebuildCount shouldBe 1
                clock.advanceSeconds(31)
                server.snapshotBytes()
                server.rebuildCount shouldBe 2
            }

            test("more than 256 descriptors: 256 are served, and the choice varies") {
                val clock = MovableClock()
                val index = OnionRelayDescriptorIndex()
                val now = clock.millis() / 1000
                repeat(300) { index.add(SnapshotRelay().descriptor, now) }
                val server = OnionRelayDirectoryServer(index, { _, _ -> null }, clock, SecureRandom())
                val first =
                    OnionRelayDirectoryCodec
                        .decodeResponse(server.snapshotBytes())
                        .entries
                        .map {
                            it.descriptor.identity
                        }.toSet()
                first.size shouldBe 256
                clock.advanceSeconds(31)
                val second =
                    OnionRelayDirectoryCodec
                        .decodeResponse(server.snapshotBytes())
                        .entries
                        .map {
                            it.descriptor.identity
                        }.toSet()
                (first == second) shouldBe false
            }

            test("rate limits: 2 per peer per 10 min, 30 per minute in total, 4 at once") {
                val clock = MovableClock()
                val limiter = RelayDirectoryServeLimiter(RelayDirectoryServeLimits(), clock)
                val p = PeerId.random()
                limiter.tryAcquire(p) shouldBe true
                limiter.release()
                limiter.tryAcquire(p) shouldBe true
                limiter.release()
                limiter.tryAcquire(p) shouldBe false
                clock.advanceSeconds(301)
                limiter.tryAcquire(p) shouldBe true
                limiter.release()
                // concurrency: four held, the fifth refused, one released, admitted again
                val held = List(4) { PeerId.random() }
                held.forEach { limiter.tryAcquire(it) shouldBe true }
                limiter.tryAcquire(PeerId.random()) shouldBe false
                limiter.release()
                limiter.tryAcquire(PeerId.random()) shouldBe true
                repeat(4) { limiter.release() }
                limiter.inFlight() shouldBe 0
                // global: 30 per minute (6 used so far within this minute)
                var admitted = 0
                repeat(40) {
                    if (limiter.tryAcquire(PeerId.random())) {
                        admitted++
                        limiter.release()
                    }
                }
                (admitted <= 30 - 6 + 1) shouldBe true
            }

            test("per address: at most 2 streams at once whatever the peer ids, released per address") {
                val clock = MovableClock()
                val limiter = RelayDirectoryServeLimiter(RelayDirectoryServeLimits(), clock)
                val attacker = "ip4:203.0.113.7"
                // fresh peer ids from one address do not get more than two slots
                limiter.tryAcquire(PeerId.random(), attacker) shouldBe true
                limiter.tryAcquire(PeerId.random(), attacker) shouldBe true
                limiter.tryAcquire(PeerId.random(), attacker) shouldBe false
                // the remaining two global slots stay open for other addresses
                limiter.tryAcquire(PeerId.random(), "ip4:198.51.100.1") shouldBe true
                limiter.tryAcquire(PeerId.random(), "ip4:198.51.100.2") shouldBe true
                limiter.inFlight() shouldBe 4
                limiter.release(attacker)
                limiter.tryAcquire(PeerId.random(), attacker) shouldBe true
                limiter.release(attacker)
                limiter.release(attacker)
                limiter.release("ip4:198.51.100.1")
                limiter.release("ip4:198.51.100.2")
                limiter.inFlight() shouldBe 0
            }

            test("a refused request takes no token: neither per peer nor globally") {
                val clock = MovableClock()
                val limiter =
                    RelayDirectoryServeLimiter(
                        RelayDirectoryServeLimits(perPeerRequests = 1, globalPerMinute = 2),
                        clock,
                    )
                val honest = PeerId.random()
                // the global bucket is empty: the honest peer is refused, but keeps its own token
                limiter.tryAcquire(PeerId.random()) shouldBe true
                limiter.release()
                limiter.tryAcquire(PeerId.random()) shouldBe true
                limiter.release()
                limiter.tryAcquire(honest) shouldBe false
                clock.advanceSeconds(31)
                limiter.tryAcquire(honest) shouldBe true
                limiter.release()
                // the honest peer's own bucket is now empty: refused without taking the global token that came back
                clock.advanceSeconds(31)
                limiter.tryAcquire(honest) shouldBe false
                limiter.tryAcquire(PeerId.random()) shouldBe true
                limiter.release()
            }

            test("address key: IPv4 address, IPv6 /64, unknown without an ip component") {
                remoteAddressKey(Multiaddr("/ip4/203.0.113.7/tcp/4001")) shouldBe "ip4:203.0.113.7"
                remoteAddressKey(Multiaddr("/ip6/2001:db8:1:2::1/tcp/4001")) shouldBe
                    remoteAddressKey(Multiaddr("/ip6/2001:db8:1:2:ffff::9/tcp/4001"))
                (
                    remoteAddressKey(Multiaddr("/ip6/2001:db8:1:2::1/tcp/4001")) ==
                        remoteAddressKey(Multiaddr("/ip6/2001:db8:1:3::1/tcp/4001"))
                ) shouldBe false
                remoteAddressKey(Multiaddr("/dns4/example.org/tcp/4001")) shouldBe "unknown"
                remoteAddressKey(null) shouldBe "unknown"
            }
        }

        context("ingest") {
            val clock = MovableClock()

            test("a valid entry lands in both indexes and nothing is published") {
                val index = OnionRelayDescriptorIndex()
                val sink = RecordSink()
                val ingest = RelayDirectorySnapshotIngest(index, sink.sink, clock)
                val r = SnapshotRelay()
                val report = ingest.ingest(PeerId.random(), snapshotOf(r.entry()))
                report.accepted shouldBe 1
                report.recordsAccepted shouldBe 1
                index.current(r.descriptor.identity, clock.millis() / 1000) shouldBe r.descriptor
                sink.taken.single().identity shouldBe r.descriptor.identity
            }

            test("a tampered signature, a record of another identity, an expired or stale entry is not taken") {
                val index = OnionRelayDescriptorIndex()
                val sink = RecordSink()
                val ingest = RelayDirectorySnapshotIngest(index, sink.sink, clock)
                val r = SnapshotRelay()
                val bytes = OnionRelayDescriptorCodec.encode(r.descriptor)
                bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 1).toByte()
                val tampered = OnionRelayDescriptorCodec.decode(bytes)
                val other = SnapshotRelay()
                val report =
                    ingest.ingest(
                        PeerId.random(),
                        RelayDirectorySnapshot(
                            listOf(
                                RelayDirectorySnapshotEntry(tampered, null),
                                RelayDirectorySnapshotEntry(
                                    other.descriptor,
                                    PeerRecordCodec.encode(SnapshotRelay().record()),
                                ),
                            ) + List(9) { RelayDirectorySnapshotEntry(SnapshotRelay().descriptor, null) },
                        ),
                    )
                report.invalid shouldBe 2
                index.current(r.descriptor.identity, clock.millis() / 1000) shouldBe null
                sink.taken.size shouldBe 0
                // an older version after a newer one changes nothing
                val newer = r.relay.descriptor(sequence = 5)
                index.add(newer, clock.millis() / 1000)
                ingest
                    .ingest(
                        PeerId.random(),
                        snapshotOf(r.relay.descriptor(sequence = 2) to null),
                    ).staleOrReplayed shouldBe
                    1
                index.current(r.descriptor.identity, clock.millis() / 1000) shouldBe newer
            }

            test("an expired descriptor is skipped") {
                val c = MovableClock()
                val index = OnionRelayDescriptorIndex()
                val ingest = RelayDirectorySnapshotIngest(index, RecordSink().sink, c)
                val d = SnapshotRelay().relay.descriptor(expiresInSeconds = 100)
                c.advanceSeconds(200)
                ingest.ingest(PeerId.random(), snapshotOf(d to null)).expired shouldBe 1
                index.size() shouldBe 0
            }

            test("an expired record is skipped, the descriptor is still taken") {
                val index = OnionRelayDescriptorIndex()
                val sink = RecordSink()
                val ingest = RelayDirectorySnapshotIngest(index, sink.sink, clock)
                val r = SnapshotRelay()
                val stale = r.record(notValidAfter = r.now - 5)
                val report = ingest.ingest(PeerId.random(), snapshotOf(r.entry(stale)))
                report.accepted shouldBe 1
                report.recordsSkipped shouldBe 1
                sink.taken.size shouldBe 0
            }

            test("more than a quarter invalid: the rest is discarded and the source blocked for an hour") {
                val c = MovableClock()
                val index = OnionRelayDescriptorIndex()
                val ingest = RelayDirectorySnapshotIngest(index, RecordSink().sink, c)
                val bad =
                    List(4) {
                        val b = OnionRelayDescriptorCodec.encode(SnapshotRelay().descriptor)
                        b[b.size - 1] = (b[b.size - 1].toInt() xor 1).toByte()
                        RelayDirectorySnapshotEntry(OnionRelayDescriptorCodec.decode(b), null)
                    }
                val good = List(8) { RelayDirectorySnapshotEntry(SnapshotRelay().descriptor, null) }
                val source = PeerId.random()
                val report = ingest.ingest(source, RelayDirectorySnapshot(bad + good))
                report.sourceBlocked shouldBe true
                index.size() shouldBe 0
                ingest.isBlocked(source) shouldBe true
                ingest.ingest(source, RelayDirectorySnapshot(good)).sourceBlocked shouldBe true
                c.advanceSeconds(3601)
                ingest.isBlocked(source) shouldBe false
            }

            test("budgets: at most 64 new identities per fetch and 512 from snapshots in total") {
                val index = OnionRelayDescriptorIndex()
                val ingest = RelayDirectorySnapshotIngest(index, RecordSink().sink, clock)
                val many = List(256) { SnapshotRelay().descriptor to null as ByteArray? }
                val r1 = ingest.ingest(PeerId.random(), snapshotOf(*many.toTypedArray()))
                r1.accepted shouldBe 64
                r1.overBudget shouldBe 192
                repeat(10) {
                    ingest.ingest(
                        PeerId.random(),
                        snapshotOf(
                            *List(256) {
                                SnapshotRelay().descriptor to
                                    null as ByteArray?
                            }.toTypedArray(),
                        ),
                    )
                }
                ingest.snapshotOwnedCount() shouldBe 512
                index.size() shouldBe 512
            }

            test("an entry left out for the budget still counts as provenance once another source delivers it") {
                val index = OnionRelayDescriptorIndex()
                val ingest =
                    RelayDirectorySnapshotIngest(
                        index,
                        RecordSink().sink,
                        clock,
                        maxNewIdentitiesPerFetch = 2,
                        maxSnapshotOwnedIdentities = 8,
                    )
                val flood = List(4) { SnapshotRelay() }
                val honest = SnapshotRelay()
                val first = PeerId.random()
                // the flood comes first and uses up the budget of this fetch; the honest relay is over budget
                ingest
                    .ingest(
                        first,
                        snapshotOf(*(flood.take(2) + honest).map { it.entry(null) }.toTypedArray()),
                    ).overBudget shouldBe
                    1
                index.current(honest.descriptor.identity, clock.millis() / 1000) shouldBe null
                ingest.ingest(PeerId.random(), snapshotOf(honest.entry(null))).accepted shouldBe 1
                ingest.sourcesFor(honest.descriptor.identity) shouldBe 2
            }

            test("provenance counts distinct sources of the current descriptor") {
                val index = OnionRelayDescriptorIndex()
                val ingest = RelayDirectorySnapshotIngest(index, RecordSink().sink, clock)
                val r = SnapshotRelay()
                val s1 = PeerId.random()
                val s2 = PeerId.random()
                ingest.ingest(s1, snapshotOf(r.entry(null)))
                ingest.ingest(s1, snapshotOf(r.entry(null)))
                ingest.sourcesFor(r.descriptor.identity) shouldBe 1
                ingest.ingest(s2, snapshotOf(r.entry(null))).confirmed shouldBe 1
                ingest.sourcesFor(r.descriptor.identity) shouldBe 2
            }
        }

        context("eclipse") {
            test(
                "(1) one source with 1000 valid own descriptors takes at most 64 slots, honest gossip is still accepted",
            ) {
                val clock = MovableClock()
                val index = OnionRelayDescriptorIndex()
                val ingest = RelayDirectorySnapshotIngest(index, RecordSink().sink, clock)
                val sybil = PeerId.random()
                // the codec caps a snapshot at 256; four snapshots stand for 1000 entries
                repeat(4) {
                    ingest.ingest(
                        sybil,
                        snapshotOf(*List(250) { SnapshotRelay().descriptor to null as ByteArray? }.toTypedArray()),
                    )
                }
                (index.size() <= 4 * 64) shouldBe true
                // the gossip validator still accepts an honest descriptor
                val validator = OnionRelayDescriptorGossip.Validator(index, clock, 6, 60)
                val honest = SnapshotRelay().descriptor
                validator.validate(OnionRelayDescriptorCodec.encode(honest), PeerId.random()) shouldBe
                    io.libp2p.core.pubsub.ValidationResult.Valid
            }

            test("(1b) the total snapshot share never exceeds half the index, so gossip always keeps room") {
                val clock = MovableClock()
                val index = OnionRelayDescriptorIndex(maxTracked = 1024)
                val ingest = RelayDirectorySnapshotIngest(index, RecordSink().sink, clock)
                repeat(20) {
                    ingest.ingest(
                        PeerId.random(),
                        snapshotOf(
                            *List(256) {
                                SnapshotRelay().descriptor to
                                    null as ByteArray?
                            }.toTypedArray(),
                        ),
                    )
                }
                index.size() shouldBe 512
                val validator = OnionRelayDescriptorGossip.Validator(index, clock, 1000, 1000)
                repeat(20) {
                    validator.validate(
                        OnionRelayDescriptorCodec.encode(SnapshotRelay().descriptor),
                        PeerId.random(),
                    ) shouldBe
                        io.libp2p.core.pubsub.ValidationResult.Valid
                }
            }

            test("(2) two sources, one omits a relay: the union is complete") {
                val clock = MovableClock()
                val index = OnionRelayDescriptorIndex()
                val ingest = RelayDirectorySnapshotIngest(index, RecordSink().sink, clock)
                val relays = List(5) { SnapshotRelay() }
                ingest.ingest(PeerId.random(), snapshotOf(*relays.drop(1).map { it.entry() }.toTypedArray()))
                ingest.ingest(PeerId.random(), snapshotOf(*relays.map { it.entry() }.toTypedArray()))
                relays.all { index.current(it.descriptor.identity, clock.millis() / 1000) != null } shouldBe true
                relays.drop(1).all { ingest.sourcesFor(it.descriptor.identity) == 2 } shouldBe true
                ingest.sourcesFor(relays[0].descriptor.identity) shouldBe 1
            }

            test("(4) a guard snapshot with older versions changes nothing") {
                val clock = MovableClock()
                val index = OnionRelayDescriptorIndex()
                val ingest = RelayDirectorySnapshotIngest(index, RecordSink().sink, clock)
                val r = SnapshotRelay()
                val newest = r.relay.descriptor(sequence = 9)
                index.add(newest, clock.millis() / 1000)
                val report = ingest.ingest(PeerId.random(), snapshotOf(r.relay.descriptor(sequence = 3) to null))
                report.staleOrReplayed shouldBe 1
                index.current(r.descriptor.identity, clock.millis() / 1000) shouldBe newest
                // a validly signed older version still counts as "this source knows the relay" (provenance only)
                ingest.sourcesFor(r.descriptor.identity) shouldBe 1
            }
        }
    })
