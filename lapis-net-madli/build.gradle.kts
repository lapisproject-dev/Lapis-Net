// lapis-net-madli: Madli (V0.5), the fourth and final scoring dimension - a machine-to-machine
// node-reputation system rating NODES AS INFRASTRUCTURE (Bitswap/DHT serving quality), never
// content or people. Its signed daily observation vector (MadliDailyVector) mirrors
// lapis-net-karma's KarmaVote / lapis-net-virtus's LtrRecord hardened codec/gossip/two-cap-index
// shape.
//
// DELIBERATE DEVIATION from the Karma/Virtus "no sibling trust dependency" rule: this module DOES
// depend on lapis-net-trust. Karma/Virtus defer Veritas-weighting to their application-layer
// consumer (lapis-net-browser's KarmaScoring); Madli is machine-to-machine infrastructure with no
// browser/application consumer in this wave, so its Veritas-weighted aggregation (the module's
// core deliverable, and the subject of the mandatory Sybil-resistance simulation) is hosted here.
// The aggregation CORE stays trust-free by taking an injected observerWeight: (Secp256k1PublicKey)
// -> Double (mirroring KarmaWeightCalculator's injected votesByVoter); only MadliAggregator's thin
// veritasObserverWeight adapter references TrustPathFinder/TrustGraph.
//
// api(lapis-net-trust) transitively re-exports lapis-net-storage (NabuStorage, in MadliGossip's
// public factory), lapis-net-networking (GossipPubSub/LapisNode/Host/PeerId), lapis-net-identity
// (Secp256k1PublicKey/KeyPair), and java-cid. They are also declared explicitly below (house style:
// a type appearing directly in this module's public API is declared directly, not relied on
// transitively). lapis-net-core stays implementation: domainSeparatedDigest is used internally only.
dependencies {
    implementation(project(":lapis-net-core"))
    api(project(":lapis-net-identity"))
    api(project(":lapis-net-storage"))
    api(project(":lapis-net-trust"))
    // RelayCandidateRanker / RelayReliabilityCounts / PeerInfo appear in the public API of
    // MadliRelayRanker and MadliRelayReliabilityPublisher.
    api(project(":lapis-net-networking"))
    api(rootProject.libs.java.cid)
}
