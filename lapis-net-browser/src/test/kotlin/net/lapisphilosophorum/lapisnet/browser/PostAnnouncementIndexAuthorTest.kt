package net.lapisphilosophorum.lapisnet.browser

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair

class PostAnnouncementIndexAuthorTest :
    FunSpec({
        fun post(
            author: Secp256k1KeyPair,
            text: String,
        ): PostAnnouncement = PostAnnouncement.create(author, text.toByteArray(Charsets.UTF_8))

        test("postsBy returns only that author's posts and is empty for an unknown author") {
            val a = Secp256k1KeyPair.generate()
            val b = Secp256k1KeyPair.generate()
            val index = PostAnnouncementIndex()
            val pa = post(a, "one")
            val pb = post(b, "two")
            index.add(pa, deriveBodyCid(pa.bodyBytes)) shouldBe true
            index.add(pb, deriveBodyCid(pb.bodyBytes)) shouldBe true

            index.postsBy(a.publicKey).single().announcement shouldBe pa
            index.postsBy(b.publicKey) shouldHaveSize 1
            index.postsBy(Secp256k1KeyPair.generate().publicKey) shouldHaveSize 0
        }

        test("the author index follows FIFO eviction") {
            val a = Secp256k1KeyPair.generate()
            val index = PostAnnouncementIndex(maxTracked = 2, maxPersisted = 10, maxPersistedBodies = 10)
            val posts = (1..3).map { post(a, "p$it") }
            posts.forEach { index.add(it, deriveBodyCid(it.bodyBytes)) shouldBe true }

            index.all() shouldHaveSize 2
            index.postsBy(a.publicKey).map { it.announcement }.toSet() shouldBe posts.drop(1).toSet()
        }
    })
