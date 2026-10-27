package net.lapisphilosophorum.lapisnet.directory

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerId
import io.libp2p.core.pubsub.ValidationResult
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Ed25519KeyPair
import net.lapisphilosophorum.lapisnet.identity.EncryptionKeyBinding
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.onion.IntroPointEntry
import net.lapisphilosophorum.lapisnet.onion.OnionKeyBinding
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptor
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptorCodec
import net.lapisphilosophorum.lapisnet.ratchet.OneTimePrekey
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundle
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyBundleCodec
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.Random

private class StaffelClock(
    var millis: Long = System.currentTimeMillis(),
) : Clock() {
    override fun getZone() = ZoneOffset.UTC

    override fun withZone(zone: java.time.ZoneId?) = this

    override fun instant(): Instant = Instant.ofEpochMilli(millis)

    override fun millis(): Long = millis
}

private class LowestJitter : Random() {
    override fun nextDouble(): Double = 0.0
}

private fun bundle(
    identity: DualKeyIdentity,
    sequenceNumber: Long,
): PrekeyBundle =
    PrekeyBundle.create(
        identity = identity,
        encryptionBinding = EncryptionKeyBinding.create(identity.secp256k1KeyPair, X25519KeyPair.generate().publicKey),
        signedPrekeyId = 0,
        signedPrekey = X25519KeyPair.generate().publicKey,
        oneTimePrekeys = listOf(OneTimePrekey(0, X25519KeyPair.generate().publicKey)),
        sequenceNumber = sequenceNumber,
        notValidAfterEpochSecond = 500_000L,
        nowEpochSecond = 0,
    )

private fun descriptor(
    key: Ed25519KeyPair,
    sequence: Long,
    nowSec: Long,
): OnionServiceDescriptor =
    OnionServiceDescriptor.create(
        key,
        X25519KeyPair.generate().publicKey,
        List(2) {
            IntroPointEntry(
                OnionKeyBinding.create(
                    Secp256k1KeyPair.generate(),
                    X25519KeyPair.generate().publicKey,
                    nowSec + 86_400,
                ),
                Ed25519KeyPair.generate().publicKey,
            )
        },
        sequence,
        nowSec + 3600,
        nowSec,
    )

/**
 * The early republication schedule must stay below what real receivers accept: the real validators are driven along
 * the time axis of [DirectoryRepublishSchedule.DEFAULT_OFFSETS] plus the failure retries.
 */
class AnonymousDirectoryEarlyRepublishConformanceTest :
    FunSpec({
        val relay = PeerId.random()
        val limit = AnonymousPeerRecordGossip.DEFAULT_PER_AUTHOR_PER_MINUTE

        fun recordValidator(clock: StaffelClock) =
            AnonymousPeerRecordGossip.Validator(
                AnonymousPeerRecordIndex(PeerRecordIndex()),
                clock,
                limit,
                limit * 10,
                limit * 10,
            )

        test("every new record version of the worst-case timeline (lowest jitter, 3 failed retries) is Valid") {
            val clock = StaffelClock()
            val start = clock.millis
            val validator = recordValidator(clock)
            val publisher = AnonymousPublisher()
            val guard = PublicationRateGuard(4, 60_000L) { clock.millis }
            // 3 failed attempts (5 s, 15 s, 45 s backoff), then the first success, then the early slots
            val failedAttempts = listOf(0L, 5_000L, 20_000L)
            val firstSuccess = 65_000L
            val slots =
                DirectoryRepublishSchedule(random = LowestJitter()).plan(start + firstSuccess).map { it - start }
            val timeline = failedAttempts + firstSuccess + slots
            var sequence = 1L
            var maxInWindow = 0
            val published = ArrayList<Long>()
            for (t in timeline) {
                clock.millis = maxOf(clock.millis, start + t)
                // the publisher defers instead of exceeding its own rate
                while (!guard.tryAcquire()) clock.millis = guard.nextAllowedAtMillis()
                published += clock.millis
                maxInWindow = maxOf(maxInWindow, published.count { clock.millis - it < 60_000L })
                val record = publisher.record(sequence++, now = clock.millis / 1000)
                validator.validate(relay, AnonymousPeerRecordCodec.encode(record)) shouldBe ValidationResult.Valid
            }
            (maxInWindow <= 4) shouldBe true
            (maxInWindow < limit) shouldBe true
        }

        test("identical record and descriptor repetitions are Ignore and spend no rate budget") {
            val clock = StaffelClock()
            val validator = recordValidator(clock)
            val publisher = AnonymousPublisher()
            val first = AnonymousPeerRecordCodec.encode(publisher.record(1, now = clock.millis / 1000))
            validator.validate(relay, first) shouldBe ValidationResult.Valid
            repeat(30) { validator.validate(relay, first) shouldBe ValidationResult.Ignore }
            // the budget is untouched by the repetitions: further new versions still fit (limit - 1 more in a minute)
            for (seq in 2L..limit.toLong()) {
                validator
                    .validate(
                        relay,
                        AnonymousPeerRecordCodec.encode(publisher.record(seq, now = clock.millis / 1000)),
                    ) shouldBe
                    ValidationResult.Valid
            }
            validator
                .validate(
                    relay,
                    AnonymousPeerRecordCodec.encode(publisher.record(limit + 1L, now = clock.millis / 1000)),
                ) shouldBe ValidationResult.Ignore // now the rate limit does apply

            val descriptorIndex = OnionServiceDescriptorIndex()
            val descriptorValidator =
                OnionServiceDescriptorGossip.Validator(descriptorIndex, clock, limit, limit * 10, limit * 10)
            val key = Ed25519KeyPair.generate()
            val bytes = OnionServiceDescriptorCodec.encode(descriptor(key, 1, clock.millis / 1000))
            descriptorValidator.validate(bytes, relay) shouldBe ValidationResult.Valid
            repeat(30) { descriptorValidator.validate(bytes, relay) shouldBe ValidationResult.Ignore }
            for (seq in 2L..limit.toLong()) {
                descriptorValidator.validate(
                    OnionServiceDescriptorCodec.encode(descriptor(key, seq, clock.millis / 1000)),
                    relay,
                ) shouldBe ValidationResult.Valid
            }
        }

        test("new bundles with rising sequence are Valid, an identical bundle is Invalid (why it is never repeated)") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("early-republish-bundles"))
                val index = PrekeyBundleIndex()
                val from = PeerId.random()
                for (seq in 0L..5L) {
                    val bytes = PrekeyBundleCodec.encode(bundle(identity, seq))
                    PrekeyBundleGossip.onGossipMessage(bytes, from, storage, index) shouldBe ValidationResult.Valid
                }
                val repeated = PrekeyBundleCodec.encode(bundle(identity, 6))
                PrekeyBundleGossip.onGossipMessage(repeated, from, storage, index) shouldBe ValidationResult.Valid
                PrekeyBundleGossip.onGossipMessage(repeated, from, storage, index) shouldBe ValidationResult.Invalid
            } finally {
                node.stop()
            }
        }
    })
