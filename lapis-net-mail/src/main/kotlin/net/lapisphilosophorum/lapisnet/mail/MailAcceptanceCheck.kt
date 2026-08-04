package net.lapisphilosophorum.lapisnet.mail

import net.lapisphilosophorum.lapisnet.trust.TrustGraph

/**
 * Bundles everything [InboxGossip.onGossipMessage] needs to run [MailAcceptancePolicy.shouldAccept]
 * as an optional, pluggable check - see that validator's own doc comment for the insertion point
 * and ordering guarantee. `null` (the default in [InboxGossip.attach]) means no check runs at all,
 * preserving every prior V0.9.x wave's "accept everything addressed to me" behavior exactly -
 * functionally identical to, but cheaper than, passing a non-null instance configured with
 * [MailAcceptancePolicy.ACCEPT_ALL].
 *
 * [trustGraph] is an already-built, already-locally-held [TrustGraph] snapshot - see
 * `net.lapisphilosophorum.lapisnet.trust.TrustGraph`'s own doc comment: building it is the
 * caller's job (typically from a `VeritasGrantIndex`'s resolved edges), never this validator's.
 * Re-supplying a fresh instance as the local node's trust state evolves is the caller's
 * responsibility - [InboxGossip.onGossipMessage] only ever reads whatever [trustGraph] the caller
 * handed it for that one gossip message, never fetches or refreshes it itself (the "zero
 * clock/network calls in the validator" rule this module's classes all share).
 *
 * [depositLookup] is a pure, local, no-I/O function from an already-decoded [MessageEnvelope] to
 * a [FirstContactDeposit] the caller already holds for it, or `null` if none is available. **The
 * deposit itself does NOT travel in-band over `MailFrameCodec`'s wire format this wave** - a
 * deliberate scope cut, consistent with this whole mechanism's "obtained out-of-band"/"manual,
 * application-layer decision" cuts (see [FirstContactDeposit]'s class doc comment): a real
 * deployment would populate a small local map (envelope content id -> deposit) once its
 * application layer observes an out-of-band Lightning payment settle, and this lambda is that
 * lookup. A future wave that extends `MailFrameCodec`/`MessageEnvelopeCodec` to carry a deposit
 * on the wire can supply this same lambda backed by the decoded frame instead, without
 * [MailAcceptancePolicy]/[InboxGossip] changing at all.
 */
class MailAcceptanceCheck(
    val gates: List<MailAcceptanceGate>,
    val trustGraph: TrustGraph,
    val karmaScoreOf: KarmaScoreLookup,
    val depositLookup: (MessageEnvelope) -> FirstContactDeposit? = { null },
)
