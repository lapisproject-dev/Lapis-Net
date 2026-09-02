package net.lapisphilosophorum.lapisnet.dm

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.policy.AcceptanceGate
import net.lapisphilosophorum.lapisnet.policy.KarmaScoreLookup
import net.lapisphilosophorum.lapisnet.trust.TrustGraph
import java.util.Collections

/**
 * THE CORE V0.8.6 SECURITY REGRESSION: proves [DmEnvelope.senderIdentity] is never a
 * [DmAcceptancePolicy] gate input by itself - only the AEAD-authenticated identity is. Two cases:
 *
 * (a) An attacker claims a Veritas-trusted identity in [DmEnvelope.senderIdentity] but the ratchet
 * bytes actually decrypt under the ATTACKER's own session - never delivered, never gate-passed as
 * the trusted peer (mirrors [DmStreamAbuseTest]'s case (e), retested here specifically through the
 * acceptance-policy lens).
 *
 * (b) The SAME attacker, this time with a genuinely-own, real X3DH-bootstrapped session (their own
 * real identity as the claimed sender) - IS delivered (the AEAD genuinely authenticates them), but
 * with `quarantined = true`: the gate never treats them as the trusted peer, and gates real content
 * as required.
 */
class DmPolicyAuthorityTest :
    FunSpec({
        test(
            "(a) claiming a trusted identity while encrypting under an unrelated session never " +
                "delivers, never gate-passes as the trusted peer",
        ) {
            val trusted = buildDmTestNode()
            val attacker = buildDmTestNode()
            val victim = buildDmTestNode()
            try {
                connectAndConverge(trusted, victim)
                connectAndConverge(attacker, victim)

                val identityTrusted = trusted.identity.secp256k1KeyPair.publicKey
                val identityVictim = victim.identity.secp256k1KeyPair.publicKey

                // victim's acceptance policy trusts `trusted`, gated by VeritasPath.
                val graph = TrustGraph.fromEdges(listOf(Triple(identityVictim, identityTrusted, 1_000_000)))
                val acceptance =
                    DmAcceptanceCheck(
                        gates =
                            listOf(
                                AcceptanceGate.VeritasPath,
                            ),
                        trustGraph = graph,
                        karmaScoreOf =
                            KarmaScoreLookup {
                                0.0
                            },
                    )
                victim.dmSessionManager.updateAcceptanceCheck(acceptance)

                val received = Collections.synchronizedList(mutableListOf<DmInboundMessage>())
                victim.dmSessionManager.addInboundListener { received.add(it) }

                // attacker's OWN live sending session to victim encrypts a message.
                sendAndAwaitReceived(attacker, victim, identityVictim, received, "hello from attacker")
                val beforeCount = received.size

                val attackerSession =
                    requireNotNull(attacker.dmSessionManager.liveSessionForTest(identityVictim))
                val ratchetMessage =
                    attackerSession.encrypt(DmContentCodec.encode(DmContent(body = "forged as trusted")))
                // Wrap it in an envelope claiming senderIdentity = trusted, not attacker.
                val forgedEnvelope = DmEnvelope(DmMessageType.TEXT, identityTrusted, null, ratchetMessage)
                val forgedBytes = DmEnvelopeCodec.encode(forgedEnvelope)

                victim.dmSessionManager.handleInboundEnvelope(attacker.node.peerId, forgedBytes)

                // Never delivered - the claimed field alone is never trusted (existing DM invariant),
                // so it never even reaches acceptance-policy classification as `trusted`.
                received.size shouldBe beforeCount
            } finally {
                trusted.stop()
                attacker.stop()
                victim.stop()
            }
        }

        test(
            "(b) a genuinely self-authenticated, untrusted attacker IS delivered but quarantined - " +
                "never silently accepted as if trusted",
        ) {
            val attacker = buildDmTestNode()
            val victim = buildDmTestNode()
            try {
                connectAndConverge(attacker, victim)
                val identityAttacker = attacker.identity.secp256k1KeyPair.publicKey
                val identityVictim = victim.identity.secp256k1KeyPair.publicKey

                // victim's acceptance policy has NO trust path to attacker at all.
                val graph = TrustGraph.fromEdges(emptyList())
                val acceptance =
                    DmAcceptanceCheck(
                        gates =
                            listOf(
                                AcceptanceGate.VeritasPath,
                            ),
                        trustGraph = graph,
                        karmaScoreOf =
                            KarmaScoreLookup {
                                0.0
                            },
                    )
                victim.dmSessionManager.updateAcceptanceCheck(acceptance)

                val received = Collections.synchronizedList(mutableListOf<DmInboundMessage>())
                victim.dmSessionManager.addInboundListener { received.add(it) }

                sendAndAwaitReceived(attacker, victim, identityVictim, received, "hello, genuinely from me")

                received.size shouldBe 1
                received[0].sender shouldBe identityAttacker
                received[0].content.body shouldBe "hello, genuinely from me"
                received[0].quarantined shouldBe true
            } finally {
                attacker.stop()
                victim.stop()
            }
        }

        test(
            "(c) once the local node replies to a quarantined stranger, DmAcceptedContacts makes " +
                "that stranger's FURTHER messages arrive unquarantined - the reachable escape path " +
                "DmAcceptancePolicy's own design depends on isAcceptedContact for",
        ) {
            val stranger = buildDmTestNode()
            val victimAcceptedContacts = DmAcceptedContacts()
            val victim =
                buildDmTestNode(
                    acceptance =
                        DmAcceptanceCheck(
                            gates = listOf(AcceptanceGate.VeritasPath),
                            trustGraph = TrustGraph.fromEdges(emptyList()),
                            karmaScoreOf = KarmaScoreLookup { 0.0 },
                            isAcceptedContact = victimAcceptedContacts::isAccepted,
                        ),
                    acceptedContacts = victimAcceptedContacts,
                )
            try {
                connectAndConverge(stranger, victim)
                val identityStranger = stranger.identity.secp256k1KeyPair.publicKey
                val identityVictim = victim.identity.secp256k1KeyPair.publicKey

                val received = Collections.synchronizedList(mutableListOf<DmInboundMessage>())
                victim.dmSessionManager.addInboundListener { received.add(it) }

                // First message from a stranger with no Veritas path: delivered, but quarantined -
                // isAcceptedContact(stranger) is still false at this point.
                sendAndAwaitReceived(stranger, victim, identityVictim, received, "hello, may I have your trust?")
                received[0].quarantined shouldBe true
                victimAcceptedContacts.isAccepted(identityStranger) shouldBe false

                // The local user (victim) decides to reply - DmSessionManager.send's own
                // prepareEnvelopeLocked marks the recipient accepted as a side effect (see
                // DmSessionManager.attach's `acceptedContacts` parameter doc comment).
                val sendDeadline = System.currentTimeMillis() + 20_000
                while (!victimAcceptedContacts.isAccepted(identityStranger) &&
                    System.currentTimeMillis() < sendDeadline
                ) {
                    runCatching { victim.dmSessionManager.send(identityStranger, DmContent(body = "sure, hi back")) }
                    Thread.sleep(500)
                }
                victimAcceptedContacts.isAccepted(identityStranger) shouldBe true

                // A SECOND message from the now-accepted stranger arrives unquarantined - the exact
                // escape path DmAcceptancePolicy.decide's own doc comment describes as the ONLY way
                // out of quarantine.
                sendAndAwaitReceived(stranger, victim, identityVictim, received, "thanks, here is more")
                received[1].quarantined shouldBe false
            } finally {
                stranger.stop()
                victim.stop()
            }
        }
    })

private fun sendAndAwaitReceived(
    from: DmTestNode,
    to: DmTestNode,
    recipientIdentity: net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey,
    received: MutableList<DmInboundMessage>,
    bodyText: String,
    timeoutSeconds: Long = 20,
) {
    val before = received.size
    val deadline = System.currentTimeMillis() + timeoutSeconds * 1000
    while (received.size <= before && System.currentTimeMillis() < deadline) {
        runCatching { from.dmSessionManager.send(recipientIdentity, DmContent(body = bodyText)) }
        Thread.sleep(1000)
    }
    if (received.size <= before) error("expected at least ${before + 1} inbound message(s), got ${received.size}")
}
