package net.lapisphilosophorum.lapisnet.mail

import io.ipfs.cid.Cid

/**
 * One node in an assembled mail thread: [message] plus its [depth] (a root is depth `0`) and
 * already-built [children] - sorted deterministically by content-cid bytes (see [ThreadBuilder]'s
 * class doc comment on receipt-order independence), never by arrival/insertion order.
 */
class ThreadNode internal constructor(
    val message: InboxMessage,
    val depth: Int,
    children: List<ThreadNode>,
) {
    /** Immutable snapshot. */
    val children: List<ThreadNode> = children.toList()

    /** The [MessageEnvelope.contentCid] this node's [message] carries - the identity
     * [ThreadBuilder] threads on (see that object's class doc comment for why this, not
     * [MessageEnvelope.contentId], is the correct linking key). */
    val contentCid: Cid get() = message.envelope.contentCid
}

/**
 * The result of [ThreadBuilder.build]: every root [ThreadNode] found in the input set, plus an
 * O(1) lookup from any [Cid] that appears ANYWHERE in the forest (not just at a root) back to that
 * node's tree root.
 */
class ThreadForest internal constructor(
    val roots: List<ThreadNode>,
    private val rootByContentCid: Map<Cid, ThreadNode>,
) {
    /** The root of whichever tree contains a node whose [MessageEnvelope.contentCid] is [cid], or
     * `null` if [cid] is not part of any assembled thread - either because it was never in the
     * `known` set [ThreadBuilder.build] was given, or because it was excluded as part of a cycle
     * (see [ThreadBuilder]'s class doc comment, "cascading exclusion"). */
    fun threadContaining(cid: Cid): ThreadNode? = rootByContentCid[cid]
}

/**
 * Assembles a forest of [ThreadNode] trees out of a flat set of [InboxMessage]s, using
 * [MessageEnvelope.replyTo] as the single-valued parent pointer. Mirrors
 * `net.lapisphilosophorum.lapisnet.trust.VeritasGrantResolver`'s explicit-stack,
 * non-recursive-DFS, visited-set, hard-depth-cap traversal discipline - a mail thread is
 * structurally the same "forked DAG with a possible cycle" problem as that resolver's version-chain
 * walk, and this codebase already has a battle-tested solution for it.
 *
 * **Linking key: [MessageEnvelope.replyTo] compared against every known envelope's
 * [MessageEnvelope.contentCid] - NOT [MessageEnvelope.contentId].** `replyTo`/`contentCid` share
 * the exact same type (`io.ipfs.cid.Cid`) and reference the PARENT MESSAGE'S BODY-BLOB CID
 * ([MessageBodyCodec.cidFor]), not the parent envelope's own SHA-256 fingerprint
 * ([MessageEnvelope.contentId], a raw `ByteArray` used only internally by [InboxIndex]/
 * [MailContentId] for gossip dedup). A consequence, inherited from V0.9.1's field typing and not
 * fixable without a wire-breaking change: two different envelopes whose [MessageBody] bytes happen
 * to be byte-identical collide on the same threading key (see [build]'s "last one wins" note).
 *
 * **[MessageEnvelope.threadRoot] is NOT used for structural tree assembly in this wave.** It
 * remains carried-and-signed-but-structurally-unused, exactly as V0.9.1/V0.9.2 already documented
 * for both fields - V0.9.3 resolves that sentence only for `replyTo`.
 *
 * **Why a genuine cycle is honestly constructible here, unlike in the trust module.**
 * `VeritasGrantResolver`'s doc comment argues a hash-chain cycle is cryptographically infeasible
 * through the real API, because a successor's `previousGrantId` is fixed to an
 * ALREADY-COMPUTED predecessor content id at creation time. Mail has no such causality
 * constraint: `contentCid` is a pure function of [MessageBody] bytes alone, computable BEFORE any
 * envelope exists, independently for two unrelated bodies. A genuine 2-cycle (`envelope A` replies
 * to `envelope B` which replies to `envelope A`) - and even a length-1 self-reference
 * (`envelope.replyTo == envelope.contentCid`) - is therefore trivially constructible via the real
 * production API (two real, correctly signed [MessageEnvelope]s), not merely via a test-seam hack.
 *
 * **Cycle rejection happens at root selection, not mid-walk.** [replyTo] is a single-valued parent
 * pointer (each message has at most one parent), so any pure cycle consists entirely of members
 * whose `replyTo` points at another IN-SET cycle member - meaning every member of a cycle fails the
 * "is a root" test (step 4 in [build]) by construction. A cycle can therefore never be reached by a
 * downward walk starting from a legitimate root: reachability follows `replyTo`-defined child edges
 * strictly outward from a `replyTo == null`-or-missing root, and nothing in a cycle has such an
 * ancestor. Consequence, deliberately different from a literal "truncate mid-walk" reading, and
 * tested explicitly (`ThreadBuilderTest`'s "cascading exclusion" case): the entire cycle, AND
 * anything that transitively replies only into it, is silently absent from [ThreadForest.roots] and
 * [ThreadForest.threadContaining] - not a crash, not an infinite loop, bounded `O(known.size)`
 * work. The mid-walk `visited` guard in [walkOneTree] is kept anyway as defense-in-depth for a
 * future relaxation of the single-parent-pointer model, mirroring `VeritasGrantResolver`'s own
 * "belt-and-braces" cycle guard - under today's data model it is structurally unreachable, exactly
 * as it is for the trust module (there, for a different underlying reason: no cycle can exist at
 * all; here, cycles can exist but are structurally excluded before any walk starts).
 */
object ThreadBuilder {
    /** Mirrors `VeritasGrantResolver.MAX_CHAIN_DEPTH`'s exact rationale and magnitude - defense in
     * depth against a pathologically deep/forked reply chain, on top of
     * [InboxIndex.MAX_TRACKED_MESSAGES]/[SentFolder.MAX_TRACKED_SENT_MESSAGES]'s own bound on the
     * number of distinct tracked messages. */
    const val MAX_THREAD_DEPTH = 4_096

    fun build(known: List<InboxMessage>): ThreadForest = build(known, MAX_THREAD_DEPTH)

    /**
     * As [build], but with an explicit [maxDepth] - a test seam, mirroring
     * `VeritasGrantResolver.resolveLatest(candidates, maxDepth)`'s identical internal-overload
     * reasoning, so [MAX_THREAD_DEPTH]'s cap can be exercised without constructing thousands of
     * real signed envelopes.
     *
     * **Precondition on [known]**: if it contains two entries sharing a `contentCid` (possible -
     * see this object's class doc comment on the `contentCid` collision case), the LAST one
     * encountered in iteration order wins (a plain `associateBy` build-up). This is never reachable
     * via the real [InboxGossip.messages]/[SentFolder.latest] paths (those dedup upstream by
     * envelope content id, a strictly finer key than `contentCid`), but a caller invoking this
     * internal overload directly with unfiltered data must pre-dedup [known] itself if it cares
     * which duplicate wins.
     *
     * **A separate, second-order edge case**: if TWO entries sharing a `contentCid` are BOTH
     * roots (both have `replyTo == null`, or a `replyTo` pointing outside the known set), the
     * `byContentCid` "last one wins" rule above does not decide which one is actually visible -
     * both are walked as candidate roots, but the global `visited` set (step 5) means only the
     * FIRST one processed for that `contentCid` is ever built into a [ThreadNode]; the second is
     * silently skipped as "already visited", never a crash or a duplicate node.
     */
    internal fun build(
        known: List<InboxMessage>,
        maxDepth: Int,
    ): ThreadForest {
        // STEP 1 - index by contentCid.
        val byContentCid: Map<Cid, InboxMessage> = known.associateBy { it.envelope.contentCid }

        // STEP 2 - reverse adjacency, ONLY for replyTo targets present in byContentCid. A dangling
        // replyTo (parent not locally known) is "not a linkable node" - mirrors
        // VeritasGrantResolver's identical dangling-reference rule.
        val childrenOf = HashMap<Cid, MutableList<InboxMessage>>()
        known.forEach { msg ->
            val parent = msg.envelope.replyTo ?: return@forEach
            if (byContentCid.containsKey(parent)) {
                childrenOf.getOrPut(parent) { mutableListOf() }.add(msg)
            }
        }
        // STEP 3 - sort each parent's children ONCE, deterministically, by contentCid's unsigned
        // byte-lexicographic bytes (mirrors GrantContentIdBytesComparator's tie-break exactly).
        // THIS is what makes the whole build receipt-order independent: regardless of `known`'s
        // input order, the same (parent -> sorted children) map results.
        childrenOf.values.forEach { list ->
            list.sortWith(compareBy(CidBytesComparator) { it.envelope.contentCid.toBytes() })
        }

        // STEP 4 - roots: replyTo == null, OR replyTo not present in byContentCid (missing parent -
        // becomes its own top-level tree, never a synthesized placeholder node). A cycle member
        // NEVER qualifies here (its replyTo IS present in byContentCid, pointing at another in-set
        // member) - this is the actual cycle-rejection mechanism, see this object's class doc
        // comment.
        val roots =
            known
                .filter { msg ->
                    val parent = msg.envelope.replyTo
                    parent == null || !byContentCid.containsKey(parent)
                }.sortedWith(compareBy(CidBytesComparator) { it.envelope.contentCid.toBytes() })

        // STEP 5 - iterative, explicit-stack, two-phase (ENTER/LEAVE) post-order walk per root.
        // GLOBAL visited set across the WHOLE forest - defense-in-depth, structurally unreachable
        // given step 4's filter (see class doc comment), kept for the same belt-and-braces reason
        // VeritasGrantResolver keeps its own cycle guard.
        val globalVisited = HashSet<Cid>()
        val builtRoots = mutableListOf<ThreadNode>()
        val rootByContentCid = HashMap<Cid, ThreadNode>()

        for (root in roots) {
            if (root.envelope.contentCid in globalVisited) continue
            val builtRoot = walkOneTree(root, maxDepth, byContentCid, childrenOf, globalVisited)
            builtRoots += builtRoot
            tagDescendantsWithRoot(builtRoot, rootByContentCid)
        }
        return ThreadForest(builtRoots, rootByContentCid)
    }

    /**
     * Explicit-stack, two-phase (ENTER then LEAVE) DFS - children must be FULLY built before the
     * parent [ThreadNode] is assembled, so a plain single-phase stack (as `VeritasGrantResolver`
     * uses, which only ever needs to find leaf TIPS, never reconstruct a tree) is not enough here;
     * this is the one place this algorithm's shape diverges from that resolver's.
     */
    private fun walkOneTree(
        root: InboxMessage,
        maxDepth: Int,
        byContentCid: Map<Cid, InboxMessage>,
        childrenOf: Map<Cid, List<InboxMessage>>,
        globalVisited: MutableSet<Cid>,
    ): ThreadNode {
        val stack = ArrayDeque<Frame>()
        stack.addLast(Frame.Enter(root, 0))
        val built = HashMap<Cid, ThreadNode>()

        while (stack.isNotEmpty()) {
            when (val frame = stack.removeLast()) {
                is Frame.Enter -> {
                    val cid = frame.msg.envelope.contentCid
                    // Cycle hit (defense-in-depth, see class doc comment) - the whole frame is
                    // dropped, never built, never re-entered.
                    if (!globalVisited.add(cid)) continue
                    val kids = childrenOf[cid].orEmpty()
                    if (kids.isEmpty() || frame.depth >= maxDepth) {
                        built[cid] = ThreadNode(frame.msg, frame.depth, emptyList())
                        continue
                    }
                    stack.addLast(Frame.Leave(frame.msg, frame.depth))
                    // Push in reverse so children are visited (and therefore leave-processed) in
                    // ascending sorted order despite the stack's LIFO order.
                    kids.asReversed().forEach { stack.addLast(Frame.Enter(it, frame.depth + 1)) }
                }
                is Frame.Leave -> {
                    val cid = frame.msg.envelope.contentCid
                    val kids = childrenOf[cid].orEmpty()
                    // A child that hit the cycle guard above never appears in `built` - filtered
                    // out here via mapNotNull, never a null-pointer crash.
                    val builtKids = kids.mapNotNull { built[it.envelope.contentCid] }
                    built[cid] = ThreadNode(frame.msg, frame.depth, builtKids)
                }
            }
        }
        return built.getValue(root.envelope.contentCid)
    }

    /** Iterative (explicit-stack, not recursive - see this object's class doc comment for why
     * recursion is avoided throughout) fill of [out] with every node in [root]'s tree mapped back
     * to [root] itself. */
    private fun tagDescendantsWithRoot(
        root: ThreadNode,
        out: MutableMap<Cid, ThreadNode>,
    ) {
        val stack = ArrayDeque<ThreadNode>()
        stack.addLast(root)
        while (stack.isNotEmpty()) {
            val node = stack.removeLast()
            out[node.contentCid] = root
            node.children.forEach { stack.addLast(it) }
        }
    }

    private sealed class Frame {
        data class Enter(
            val msg: InboxMessage,
            val depth: Int,
        ) : Frame()

        data class Leave(
            val msg: InboxMessage,
            val depth: Int,
        ) : Frame()
    }
}

/** Unsigned lexicographic byte-order comparator over raw CID bytes - the tie-break [ThreadBuilder]
 * uses to keep sibling ordering (and therefore the whole assembled forest) receipt-order
 * independent. Mirrors `net.lapisphilosophorum.lapisnet.trust.GrantContentIdBytesComparator`'s
 * comparison style, applied directly to `ByteArray` instead of a wrapped content-id type. */
private object CidBytesComparator : Comparator<ByteArray> {
    override fun compare(
        a: ByteArray,
        b: ByteArray,
    ): Int {
        val minLength = minOf(a.size, b.size)
        for (i in 0 until minLength) {
            val diff = (a[i].toInt() and 0xFF) - (b[i].toInt() and 0xFF)
            if (diff != 0) return diff
        }
        return a.size - b.size
    }
}
