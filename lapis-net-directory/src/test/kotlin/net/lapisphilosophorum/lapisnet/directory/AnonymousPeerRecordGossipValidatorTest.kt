package net.lapisphilosophorum.lapisnet.directory

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.read.ListAppender
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerId
import io.libp2p.core.pubsub.ValidationResult
import org.slf4j.LoggerFactory
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset

private class AnonTestClock(
    var millis: Long = System.currentTimeMillis(),
) : Clock() {
    override fun getZone() = ZoneOffset.UTC

    override fun withZone(zone: java.time.ZoneId?) = this

    override fun instant(): Instant = Instant.ofEpochMilli(millis)

    override fun millis(): Long = millis
}

private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

class AnonymousPeerRecordGossipValidatorTest :
    FunSpec({
        val peer = PeerId.random()

        fun rig(
            perAuthor: Int = 100,
            perPeer: Int = 100,
            global: Int = 100,
            clock: AnonTestClock = AnonTestClock(),
        ): Triple<AnonymousPeerRecordGossip.Validator, AnonymousPeerRecordIndex, AnonTestClock> {
            val index = AnonymousPeerRecordIndex(PeerRecordIndex())
            return Triple(AnonymousPeerRecordGossip.Validator(index, clock, perAuthor, perPeer, global), index, clock)
        }

        fun enc(r: AnonymousPeerRecord) = AnonymousPeerRecordCodec.encode(r)

        test("a valid record is accepted and indexed, a replay is ignored") {
            val (v, index, clock) = rig()
            val p = AnonymousPublisher()
            val bytes = enc(p.record(5))
            v.validate(peer, bytes) shouldBe ValidationResult.Valid
            index.current(p.key, clock.millis() / 1000).shouldNotBeNull()
            v.validate(peer, bytes) shouldBe ValidationResult.Ignore
            v.validate(peer, enc(p.record(4))) shouldBe ValidationResult.Ignore
        }

        test("wrong size, garbage and forged records are rejected") {
            val (v, _, _) = rig()
            val p = AnonymousPublisher()
            val good = enc(p.record(5))
            v.validate(peer, good.copyOf(247)) shouldBe ValidationResult.Invalid
            v.validate(peer, good + 0) shouldBe ValidationResult.Invalid
            v.validate(peer, ByteArray(248)) shouldBe ValidationResult.Invalid
            val forged = good.copyOf().also { it[200] = (it[200].toInt() xor 1).toByte() } // inside the sequence number
            v.validate(peer, forged) shouldBe ValidationResult.Invalid
            val foreignProof =
                enc(resign(p.identity, p.record(5), serviceKey = AnonymousPublisher().serviceKey.publicKey))
            v.validate(peer, foreignProof) shouldBe ValidationResult.Invalid
        }

        test("the cheap pre-check comes first: replays are ignored without spending any rate budget") {
            val (v, _, _) = rig(perAuthor = 1, perPeer = 1, global = 1)
            val p = AnonymousPublisher()
            val bytes = enc(p.record(5))
            v.validate(peer, bytes) shouldBe ValidationResult.Valid // spends the only token of every bucket
            repeat(20) {
                v.validate(peer, bytes) shouldBe ValidationResult.Ignore
            } // a duplicate costs nothing and is never rejected
        }

        test("the per-author, per-peer and global rate limits answer IGNORE, never REJECT") {
            val author = AnonymousPublisher()
            val (v1, _, _) = rig(perAuthor = 2)
            v1.validate(peer, enc(author.record(1))) shouldBe ValidationResult.Valid
            v1.validate(peer, enc(author.record(2))) shouldBe ValidationResult.Valid
            v1.validate(peer, enc(author.record(3))) shouldBe ValidationResult.Ignore

            val (v2, _, _) = rig(perPeer = 2)
            v2.validate(peer, enc(AnonymousPublisher().record(1))) shouldBe ValidationResult.Valid
            v2.validate(peer, enc(AnonymousPublisher().record(1))) shouldBe ValidationResult.Valid
            v2.validate(peer, enc(AnonymousPublisher().record(1))) shouldBe ValidationResult.Ignore
            v2.validate(PeerId.random(), enc(AnonymousPublisher().record(1))) shouldBe ValidationResult.Valid

            val (v3, _, _) = rig(global = 1)
            v3.validate(peer, enc(AnonymousPublisher().record(1))) shouldBe ValidationResult.Valid
            v3.validate(PeerId.random(), enc(AnonymousPublisher().record(1))) shouldBe ValidationResult.Ignore
        }

        test("an invalid record still costs rate budget (the expensive check is guarded)") {
            val (v, _, _) = rig(perPeer = 1)
            val p = AnonymousPublisher()
            val forged = enc(p.record(5)).also { it[200] = (it[200].toInt() xor 1).toByte() }
            v.validate(peer, forged) shouldBe ValidationResult.Invalid
            v.validate(peer, enc(AnonymousPublisher().record(1))) shouldBe ValidationResult.Ignore
        }

        test("the rate budget refills with time") {
            val clock = AnonTestClock()
            val (v, _, _) = rig(perPeer = 1, clock = clock)
            v.validate(peer, enc(AnonymousPublisher().record(1))) shouldBe ValidationResult.Valid
            v.validate(peer, enc(AnonymousPublisher().record(1))) shouldBe ValidationResult.Ignore
            clock.millis += 61_000
            v.validate(peer, enc(AnonymousPublisher().record(1))) shouldBe ValidationResult.Valid
        }

        test("log lines at DEBUG carry no bytes, keys, identities or peer ids") {
            val root = LoggerFactory.getLogger("net.lapisphilosophorum") as Logger
            val appender = ListAppender<ILoggingEvent>().also { it.start() }
            val old = root.level
            root.level = Level.DEBUG
            root.addAppender(appender)
            try {
                val (v, _, _) = rig(perPeer = 1)
                val p = AnonymousPublisher()
                val good = enc(p.record(5))
                v.validate(peer, good)
                v.validate(peer, good)
                v.validate(peer, ByteArray(248))
                v.validate(peer, good.copyOf(10))
                v.validate(peer, enc(AnonymousPublisher().record(1))) // rate limited
                val forbidden =
                    listOf(
                        peer.toBase58(),
                        hex(p.key.bytes),
                        p.key.fingerprint(),
                        hex(p.serviceKey.publicKey.bytes),
                        hex(good.copyOfRange(0, 16)),
                    )
                val lines = appender.list.map { it.formattedMessage + (it.throwableProxy?.message ?: "") }
                lines.none { line -> forbidden.any { line.contains(it) } } shouldBe true
            } finally {
                root.detachAppender(appender)
                root.level = old
            }
        }
    })
