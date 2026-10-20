package net.lapisphilosophorum.lapisnet.madli

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import net.lapisphilosophorum.lapisnet.trust.MAX_TRUST_MICROS
import net.lapisphilosophorum.lapisnet.trust.MIN_TRUST_MICROS
import net.lapisphilosophorum.lapisnet.trust.VeritasGossip
import net.lapisphilosophorum.lapisnet.trust.VeritasGrant
import java.nio.file.Files

class CachedVeritasObserverWeightTest :
    FunSpec({
        test("repeated weightOf calls on an unchanged index never re-resolve grants or re-fingerprint") {
            val local = Secp256k1KeyPair.generate()
            val observer = Secp256k1KeyPair.generate().publicKey
            val grants = listOf(VeritasGrant.create(local, observer, MAX_TRUST_MICROS))
            var version = 1L
            var resolveCalls = 0
            var fingerprintCalls = 0
            val weights =
                CachedVeritasObserverWeight(
                    version = { version },
                    grantsSource = {
                        resolveCalls++
                        grants
                    },
                    fingerprintOf = {
                        fingerprintCalls++
                        listOf(version.toByte())
                    },
                    localIdentity = local.publicKey,
                )
            repeat(1_000) { weights.weightOf(observer) shouldBe 1.0 }
            resolveCalls shouldBe 1
            fingerprintCalls shouldBe 1
            version = 2L
            repeat(1_000) { weights.weightOf(observer) shouldBe 1.0 }
            resolveCalls shouldBe 2
            fingerprintCalls shouldBe 2
        }

        test("a revoking grant for the same pair (same grant count) changes the observer weight") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity).also { it.start(bootstrapPeers = emptyList()) }
            val storage = NabuStorage.attach(node, Files.createTempDirectory("madli-weight-test"))
            val pubsub = GossipPubSub.attach(node)
            val veritas = VeritasGossip.attach(pubsub, storage)
            try {
                val local = identity.secp256k1KeyPair
                val observer = Secp256k1KeyPair.generate().publicKey
                val weights = CachedVeritasObserverWeight(veritas, local.publicKey)

                weights.weightOf(observer) shouldBe 0.0 // no grant yet
                val grant = VeritasGrant.create(local, observer, MAX_TRUST_MICROS)
                veritas.announce(grant)
                weights.weightOf(observer) shouldBe 1.0

                // revocation replaces the edge: the grant count stays 1, only the content changes
                veritas.announce(VeritasGrant.create(local, observer, MIN_TRUST_MICROS, previous = grant))
                veritas.currentGrants().size shouldBe 1
                weights.weightOf(observer) shouldBe 0.0
            } finally {
                runCatching { veritas.stop() }
                runCatching { pubsub.stop() }
                runCatching { storage.stop() }
                runCatching { node.stop() }
            }
        }
    })
