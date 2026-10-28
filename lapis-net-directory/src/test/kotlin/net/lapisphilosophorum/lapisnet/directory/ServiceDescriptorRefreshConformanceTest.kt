package net.lapisphilosophorum.lapisnet.directory

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerId
import io.libp2p.core.pubsub.ValidationResult
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.onion.IntroPointEntry
import net.lapisphilosophorum.lapisnet.onion.OnionKeyBinding
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptor
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptorCodec
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.Random

private class RefreshClock(
    var millis: Long = System.currentTimeMillis(),
) : Clock() {
    override fun getZone() = ZoneOffset.UTC

    override fun withZone(zone: java.time.ZoneId?) = this

    override fun instant(): Instant = Instant.ofEpochMilli(millis)

    override fun millis(): Long = millis
}

private class FixedFraction(
    private val value: Double,
) : Random() {
    override fun nextDouble(): Double = value
}

private class ServiceContent(
    private val key: Ed25519KeyPair,
    private val clock: RefreshClock,
) {
    private val encKey = X25519KeyPair.generate().publicKey
    private var intros = newIntros()

    private fun newIntros() =
        List(3) {
            IntroPointEntry(
                OnionKeyBinding.create(
                    Secp256k1KeyPair.generate(),
                    X25519KeyPair.generate().publicKey,
                    clock.millis / 1000 + 86_400,
                ),
                Ed25519KeyPair.generate().publicKey,
            )
        }

    /** A genuine change of the introduction points (new content). */
    fun changeIntros() {
        intros = newIntros()
    }

    /** The current content signed as version [sequence]: same keys and introduction points, new signature. */
    fun version(sequence: Long): OnionServiceDescriptor {
        val nowSec = clock.millis / 1000
        return OnionServiceDescriptor.create(key, encKey, intros, sequence, nowSec + 3600, nowSec)
    }
}

/**
 * Wave I: the fresh-version republication of service descriptors must stay below what real receivers accept. The
 * REAL [OnionServiceDescriptorGossip.Validator] runs with its default limits along the worst timelines: slots with the
 * lowest and the highest jitter, three failed first attempts, and a genuine change of the introduction points inside
 * the first minute. Also pins down the mechanism behind the old gap: a byte-identical repeat is ignored by a holder.
 */
class ServiceDescriptorRefreshConformanceTest :
    FunSpec({
        val relay = PeerId.random()

        fun validator(clock: RefreshClock) =
            OnionServiceDescriptorGossip.Validator(
                OnionServiceDescriptorIndex(),
                clock,
                OnionServiceDescriptorGossip.DEFAULT_PER_AUTHOR_PER_MINUTE,
                OnionServiceDescriptorGossip.DEFAULT_PER_PEER_PER_MINUTE,
                OnionServiceDescriptorGossip.DEFAULT_GLOBAL_PER_MINUTE,
            )

        fun runTimeline(
            jitter: Double,
            failedAttempts: List<Long>,
            firstSuccess: Long,
            introChangeAt: Long?,
        ) {
            val clock = RefreshClock()
            val start = clock.millis
            val receiver = validator(clock)
            val content = ServiceContent(Ed25519KeyPair.generate(), clock)
            val guard = PublicationRateGuard(4, 60_000L) { clock.millis }
            val slots =
                DirectoryRepublishSchedule(random = FixedFraction(jitter)).plan(start + firstSuccess).map {
                    it -
                        start
                }

            // (time, kind): FRESH = slot with a fresh version, GENUINE = essential new descriptor
            data class Event(
                val at: Long,
                val genuine: Boolean,
            )
            val events = ArrayList<Event>()
            (failedAttempts + firstSuccess).forEach { events += Event(it, true) }
            slots.forEach { events += Event(it, false) }
            if (introChangeAt != null) events += Event(introChangeAt, true)
            events.sortBy { it.at }

            var sequence = 1L
            var lastBytes: ByteArray? = null
            var firstDelivered = false
            val sentAt = ArrayList<Long>()
            for (e in events) {
                clock.millis = start + e.at
                if (e.genuine && e.at == introChangeAt) content.changeIntros()
                val bytes: ByteArray
                val fresh: Boolean
                if (e.genuine) {
                    guard.tryAcquire() // counts, never blocks
                    // a failed attempt is a retry of the same bytes; the first attempt and the change are new versions
                    val isRetry =
                        e.at in failedAttempts.drop(1) || (e.at == firstSuccess && failedAttempts.isNotEmpty())
                    if (isRetry && lastBytes != null) {
                        bytes = lastBytes
                        fresh = false
                    } else {
                        bytes = OnionServiceDescriptorCodec.encode(content.version(sequence++))
                        fresh = true
                    }
                } else if (guard.tryAcquire()) {
                    bytes = OnionServiceDescriptorCodec.encode(content.version(sequence++))
                    fresh = true
                } else {
                    bytes = lastBytes!! // fallback: identical repeat
                    fresh = false
                }
                lastBytes = bytes
                sentAt += clock.millis
                (sentAt.count { clock.millis - it < 60_000L } <= 4 || !fresh) shouldBe true
                val result = receiver.validate(bytes, relay)
                if (fresh) {
                    // never Ignore because of a rate limit
                    result shouldBe ValidationResult.Valid
                    firstDelivered = true
                } else if (firstDelivered) {
                    result shouldBe ValidationResult.Ignore // a holder ignores identical bytes without spending budget
                }
            }
        }

        test("worst timeline with the lowest jitter: every fresh version is Valid") {
            runTimeline(jitter = 0.0, failedAttempts = emptyList(), firstSuccess = 0L, introChangeAt = 20_000L)
        }

        test("worst timeline with the highest jitter and three failed first attempts: every fresh version is Valid") {
            runTimeline(
                jitter = 1.0,
                failedAttempts = listOf(0L, 5_000L, 20_000L),
                firstSuccess = 65_000L,
                introChangeAt = 70_000L,
            )
        }

        test("slots right behind the first send (lowest jitter) and an intro change in the first minute are Valid") {
            runTimeline(jitter = 0.0, failedAttempts = emptyList(), firstSuccess = 0L, introChangeAt = 6_000L)
        }

        test("a byte-identical repeat is Ignore at a holder (the mechanism behind the old multi-hop gap)") {
            val clock = RefreshClock()
            val receiver = validator(clock)
            val content = ServiceContent(Ed25519KeyPair.generate(), clock)
            val bytes = OnionServiceDescriptorCodec.encode(content.version(1))
            receiver.validate(bytes, relay) shouldBe ValidationResult.Valid
            repeat(10) { receiver.validate(bytes, relay) shouldBe ValidationResult.Ignore }
            // a fresh version of the same content passes the pre-check at that very holder
            receiver.validate(OnionServiceDescriptorCodec.encode(content.version(2)), relay) shouldBe
                ValidationResult.Valid
        }
    })
