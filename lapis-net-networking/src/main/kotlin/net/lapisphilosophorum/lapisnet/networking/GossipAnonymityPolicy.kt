package net.lapisphilosophorum.lapisnet.networking

/**
 * The fixed set of GossipSub topics a node in anonymity mode may subscribe to (wave V0.10.0-J1a). One list for the CLI
 * and the browser, so that both subscribe to subsets of the same public, global topics; no identity-scoped topic
 * (inbox, direct mailbox) is on it. The strings repeat the topic constants of the modules above this one (this module
 * cannot depend on them); the first test of `BrowserAnonymityTransportHygieneTest` in `lapis-net-browser` checks that
 * they are identical.
 *
 * Note on fingerprinting: the CLI node does not attach the Virtus, Karma and post topics, the browser does, so the two
 * still subscribe to different subsets. Who can see that is limited to the node's direct gossip neighbours.
 */
val ANONYMITY_GOSSIP_ALLOWLIST: Set<String> =
    setOf(
        "LapisNet:anonymous-peer-record-gossip:v1",
        "LapisNet:onion-service-descriptor-gossip:v1",
        "LapisNet:onion-relay-descriptor-gossip:v1",
        "LapisNet:anonymous-mailbox:v1",
        "LapisNet:madli-daily-vector-gossip:v1",
        "LapisNet:peer-record-gossip:v1",
        "LapisNet:prekey-bundle-gossip:v1",
        "LapisNet:veritas-trust-edge-gossip:v1",
        "LapisNet:virtus-ltr-record-gossip:v1",
        "LapisNet:karma-vote-gossip:v1",
        "LapisNet:browser-post-announcement-gossip:v1",
    )

/**
 * Restrictions of [GossipPubSub] in anonymity mode (wave V0.10.0-J1a):
 *
 * - [GossipPubSub.subscribe] refuses every topic outside [allowedTopics] with [GossipAnonymityRefusedException];
 * - [GossipPubSub.publish] and [GossipPubSub.publishReporting] refuse EVERY own publication: an own gossip message is
 *   signed with the transport key and leaves from this node's address, so it would tie its content (often signed by
 *   the identity) to the address. Directory objects and mailbox items go through circuits instead.
 *
 * What stays allowed: receiving, validating and forwarding other nodes' messages (the router does that, it is no own
 * publication).
 */
class GossipAnonymityPolicy(
    val allowedTopics: Set<String> = ANONYMITY_GOSSIP_ALLOWLIST,
)

/**
 * Thrown by [GossipPubSub] under a [GossipAnonymityPolicy]. The message never names a topic or a peer. A
 * [GossipPubSubException], so callers that already treat a failed publication as "not delivered" keep working
 * (fail-closed: nothing left the node).
 */
class GossipAnonymityRefusedException(
    message: String,
) : GossipPubSubException(message)
