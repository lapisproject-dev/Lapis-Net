package net.lapisphilosophorum.lapisnet.dm

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair

class DmAcceptedContactsTest :
    FunSpec({
        test("a peer is not accepted until accept() is called") {
            val contacts = DmAcceptedContacts()
            val peer = Secp256k1KeyPair.generate().publicKey
            contacts.isAccepted(peer) shouldBe false
            contacts.accept(peer)
            contacts.isAccepted(peer) shouldBe true
        }

        test("accepting is idempotent") {
            val contacts = DmAcceptedContacts()
            val peer = Secp256k1KeyPair.generate().publicKey
            contacts.accept(peer)
            contacts.accept(peer)
            contacts.isAccepted(peer) shouldBe true
        }

        test("LRU bound: the least-recently-accepted peer is evicted once the cap is exceeded") {
            val contacts = DmAcceptedContacts(maxTracked = 3)
            val peers = List(4) { Secp256k1KeyPair.generate().publicKey }
            peers.forEach { contacts.accept(it) }

            contacts.isAccepted(peers[0]) shouldBe false
            contacts.isAccepted(peers[1]) shouldBe true
            contacts.isAccepted(peers[2]) shouldBe true
            contacts.isAccepted(peers[3]) shouldBe true
        }
    })
