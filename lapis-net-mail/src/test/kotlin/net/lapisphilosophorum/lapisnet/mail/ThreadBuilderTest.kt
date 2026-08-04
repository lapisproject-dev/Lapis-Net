package net.lapisphilosophorum.lapisnet.mail

import io.ipfs.cid.Cid
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import kotlin.time.Duration.Companion.seconds

private val sender = Secp256k1KeyPair.generate()
private val recipient = Secp256k1KeyPair.generate().publicKey

/** Builds a real, correctly-signed [InboxMessage] whose `contentCid` is a real
 * `MessageBodyCodec.cidFor` value - exactly the production path, no test-seam shortcuts (see
 * [ThreadBuilder]'s class doc comment on why cycles here are honestly constructible via the real
 * API, unlike the trust module's version chains). */
private fun message(
    subject: String,
    replyTo: Cid? = null,
    from: Secp256k1KeyPair = sender,
    to: Secp256k1PublicKey = recipient,
): InboxMessage {
    val body = MessageBody(subject = subject, body = "body of $subject")
    val bodyCid = MessageBodyCodec.cidFor(MessageBodyCodec.encode(body))
    val envelope = MessageEnvelope.create(from, listOf(to), bodyCid, replyTo = replyTo)
    return InboxMessage(envelope, body)
}

/** Structural equality helper - [ThreadNode] deliberately does not implement `equals`/`hashCode`
 * itself (mirroring `VeritasGrantResolver`'s tips not needing one either), so tests compare
 * (contentCid, depth, children) recursively instead. */
private fun structurallyEqual(
    a: List<ThreadNode>,
    b: List<ThreadNode>,
): Boolean {
    if (a.size != b.size) return false
    return a.zip(b).all { (x, y) ->
        x.contentCid == y.contentCid && x.depth == y.depth && structurallyEqual(x.children, y.children)
    }
}

class ThreadBuilderTest :
    FunSpec({
        test("linear reply chain of 3 builds correct depth/children") {
            val root = message("root")
            val reply1 = message("reply1", replyTo = root.envelope.contentCid)
            val reply2 = message("reply2", replyTo = reply1.envelope.contentCid)

            val forest = ThreadBuilder.build(listOf(root, reply1, reply2))

            forest.roots.size shouldBe 1
            val builtRoot = forest.roots.single()
            builtRoot.contentCid shouldBe root.envelope.contentCid
            builtRoot.depth shouldBe 0
            builtRoot.children.size shouldBe 1
            builtRoot.children.single().contentCid shouldBe reply1.envelope.contentCid
            builtRoot.children.single().depth shouldBe 1
            builtRoot.children
                .single()
                .children
                .single()
                .contentCid shouldBe reply2.envelope.contentCid
            builtRoot.children
                .single()
                .children
                .single()
                .depth shouldBe 2
        }

        test("forked replies - two messages replying to the same parent both appear, deterministically ordered") {
            val root = message("root")
            val childA = message("childA", replyTo = root.envelope.contentCid)
            val childB = message("childB", replyTo = root.envelope.contentCid)
            val known = listOf(root, childA, childB)

            val forward = ThreadBuilder.build(known)
            val shuffled = ThreadBuilder.build(known.shuffled())
            val reversed = ThreadBuilder.build(known.reversed())

            forward.roots
                .single()
                .children.size shouldBe 2
            val forwardOrder =
                forward.roots
                    .single()
                    .children
                    .map { it.contentCid }
            shuffled.roots
                .single()
                .children
                .map { it.contentCid } shouldBe forwardOrder
            reversed.roots
                .single()
                .children
                .map { it.contentCid } shouldBe forwardOrder
        }

        test("a reply whose parent is not locally known becomes its own root - no synthesized placeholder") {
            val orphanReplyTo = message("never-included").envelope.contentCid
            val orphan = message("orphan-reply", replyTo = orphanReplyTo)

            val forest = ThreadBuilder.build(listOf(orphan))

            forest.roots.size shouldBe 1
            forest.roots.single().contentCid shouldBe orphan.envelope.contentCid
            forest.roots
                .single()
                .children
                .shouldBeEmpty()
        }

        test(
            "a real, honestly-constructible 2-cycle (A replies to B, B replies to A) excludes both from roots",
        ).config(timeout = 10.seconds) {
            val bodyA = MessageBody(subject = "A", body = "bodyA")
            val bodyB = MessageBody(subject = "B", body = "bodyB")
            val cidA = MessageBodyCodec.cidFor(MessageBodyCodec.encode(bodyA))
            val cidB = MessageBodyCodec.cidFor(MessageBodyCodec.encode(bodyB))
            val envelopeA = MessageEnvelope.create(sender, listOf(recipient), cidA, replyTo = cidB)
            val envelopeB = MessageEnvelope.create(sender, listOf(recipient), cidB, replyTo = cidA)
            val msgA = InboxMessage(envelopeA, bodyA)
            val msgB = InboxMessage(envelopeB, bodyB)

            // A legitimate, unrelated thread present in the SAME known list must be unaffected.
            val legit = message("legit-unrelated")

            val forest = ThreadBuilder.build(listOf(msgA, msgB, legit))

            forest.roots.map { it.contentCid } shouldBe listOf(legit.envelope.contentCid)
            forest.threadContaining(cidA).shouldBeNull()
            forest.threadContaining(cidB).shouldBeNull()
            forest.threadContaining(legit.envelope.contentCid).shouldNotBeNull()
        }

        test("a self-reference (replyTo == own contentCid) is excluded from roots") {
            val body = MessageBody(subject = "self", body = "self-referential")
            val cid = MessageBodyCodec.cidFor(MessageBodyCodec.encode(body))
            val envelope = MessageEnvelope.create(sender, listOf(recipient), cid, replyTo = cid)
            val msg = InboxMessage(envelope, body)

            val forest = ThreadBuilder.build(listOf(msg))

            forest.roots.shouldBeEmpty()
            forest.threadContaining(cid).shouldBeNull()
        }

        test("cascading exclusion - a legitimate message replying to a cycle member is also absent from the forest") {
            val bodyA = MessageBody(subject = "A", body = "bodyA")
            val bodyB = MessageBody(subject = "B", body = "bodyB")
            val cidA = MessageBodyCodec.cidFor(MessageBodyCodec.encode(bodyA))
            val cidB = MessageBodyCodec.cidFor(MessageBodyCodec.encode(bodyB))
            val envelopeA = MessageEnvelope.create(sender, listOf(recipient), cidA, replyTo = cidB)
            val envelopeB = MessageEnvelope.create(sender, listOf(recipient), cidB, replyTo = cidA)
            val msgA = InboxMessage(envelopeA, bodyA)
            val msgB = InboxMessage(envelopeB, bodyB)
            // D replies to A (a cycle member) - D's replyTo IS present in byContentCid, so D never
            // qualifies as a root either, even though D itself is not part of the cycle.
            val msgD = message("D-replies-into-cycle", replyTo = cidA)

            val forest = ThreadBuilder.build(listOf(msgA, msgB, msgD))

            forest.roots.shouldBeEmpty()
            forest.threadContaining(msgD.envelope.contentCid).shouldBeNull()
        }

        test("depth cap forces a leaf at maxDepth, not at the chain's real end") {
            val smallMaxDepth = 5
            var previousCid: Cid? = null
            val chain =
                (0..smallMaxDepth + 3).map { i ->
                    val msg = message("depth-$i", replyTo = previousCid)
                    previousCid = msg.envelope.contentCid
                    msg
                }

            val forest = ThreadBuilder.build(chain, smallMaxDepth)

            forest.roots.size shouldBe 1
            var node = forest.roots.single()
            var depth = 0
            while (node.children.isNotEmpty()) {
                node = node.children.single()
                depth++
            }
            depth shouldBe smallMaxDepth
            node.contentCid shouldBe chain[smallMaxDepth].envelope.contentCid
        }

        test(
            "a thread-bomb self-reference and a deep chain at the depth cap do not cause unbounded work or a crash",
        ).config(timeout = 30.seconds) {
            val bombBody = MessageBody(subject = "bomb", body = "bomb")
            val bombCid = MessageBodyCodec.cidFor(MessageBodyCodec.encode(bombBody))
            val bomb =
                InboxMessage(MessageEnvelope.create(sender, listOf(recipient), bombCid, replyTo = bombCid), bombBody)

            var previousCid: Cid? = null
            val deepChain =
                (0..ThreadBuilder.MAX_THREAD_DEPTH + 50).map { i ->
                    val msg = message("deep-$i", replyTo = previousCid)
                    previousCid = msg.envelope.contentCid
                    msg
                }

            val forest = ThreadBuilder.build(listOf(bomb) + deepChain)

            forest.threadContaining(bombCid).shouldBeNull()
            forest.roots.size shouldBe 1
        }

        test(
            "receipt-order independence - the same known set in different arrival orders builds a structurally identical forest",
        ) {
            val root = message("root")
            val childA = message("childA", replyTo = root.envelope.contentCid)
            val childB = message("childB", replyTo = root.envelope.contentCid)
            val grandchild = message("grandchild", replyTo = childA.envelope.contentCid)
            val orphan = message("orphan", replyTo = message("missing-parent").envelope.contentCid)
            val known = listOf(root, childA, childB, grandchild, orphan)

            val baseline = ThreadBuilder.build(known)
            val shuffledOnce = ThreadBuilder.build(known.shuffled())
            val shuffledTwice = ThreadBuilder.build(known.shuffled())
            val reversedOrder = ThreadBuilder.build(known.reversed())

            structurallyEqual(baseline.roots, shuffledOnce.roots) shouldBe true
            structurallyEqual(baseline.roots, shuffledTwice.roots) shouldBe true
            structurallyEqual(baseline.roots, reversedOrder.roots) shouldBe true
        }

        test("two envelopes with byte-identical MessageBody content collide on contentCid") {
            val sharedBody = MessageBody(subject = "same", body = "same content")
            val cid = MessageBodyCodec.cidFor(MessageBodyCodec.encode(sharedBody))
            val first = InboxMessage(MessageEnvelope.create(sender, listOf(recipient), cid), sharedBody)
            val secondSender = Secp256k1KeyPair.generate()
            val second = InboxMessage(MessageEnvelope.create(secondSender, listOf(recipient), cid), sharedBody)

            val forest = ThreadBuilder.build(listOf(first, second))

            // Both share contentCid and both are roots (no replyTo) - the internal byContentCid map
            // (used for PARENT lookups) has documented "last one wins" semantics, but here BOTH are
            // roots, so a different mechanism decides which one is actually visible: the global
            // visited-cid set (defense-in-depth cycle guard) means only the FIRST root processed for
            // a given contentCid is ever built into a ThreadNode - the second is silently skipped as
            // "already visited". Exactly one node survives, never a crash or duplicate.
            forest.roots.size shouldBe 1
            forest.threadContaining(cid).shouldNotBeNull()
            forest
                .threadContaining(cid)!!
                .message.envelope.sender shouldBe first.envelope.sender
        }
    })
