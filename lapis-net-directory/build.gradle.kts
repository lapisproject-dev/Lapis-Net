// lapis-net-directory: V0.8.1, the first sub-wave of the V0.8 (direct messages and calls) arc.
// A signed peer/presence directory record (PeerRecord) - identity, a proven libp2p transport-key
// binding (reusing lapis-net-identity's IdentityBinding verbatim, not a second binding scheme), a
// capped Multiaddr list, an advertised capability set, a monotonic per-identity sequence number,
// and a heartbeat TTL - propagated over a dedicated GossipSub topic (PeerDirectoryGossip),
// mirroring the codec + gossip + two-cap-index shape lapis-net-trust's VeritasGossip/
// VeritasGrantIndex (V0.1.7) established and lapis-net-mail's InboxGossip/InboxIndex (V0.9.1-
// V0.9.4) refined further. V0.8.2 (X3DH) and later V0.8 sub-waves resolve recipients' prekey
// bundles through this directory; V0.8.4 (online DM) resolves recipients' current network
// addresses through it.
//
// Kademlia.dialPeer is documented broken since V0.1.4 (see docs/architecture.adoc's Storage
// section) - like every V0.9 mail sub-wave, this module is gossip-only, no DHT publication.
//
// Dependency shape mirrors lapis-net-mail's stated house rule, not lapis-net-trust's older
// transitive-reliance-on-lapis-net-storage's-own-api-edge approach: lapis-net-identity is `api`
// because Secp256k1PublicKey/DualKeyIdentity/IdentityBinding appear directly in PeerRecord's
// public constructor/properties/create()/verify() signatures and in PeerDirectoryGossip's public
// signatures. lapis-net-storage is `api` because NabuStorage appears directly in
// PeerDirectoryGossip.attach()'s public signature. lapis-net-networking is `api`, declared
// EXPLICITLY rather than relied on transitively through lapis-net-storage's own `api` edge:
// GossipPubSub appears in PeerDirectoryGossip.attach()'s signature, and - unlike lapis-net-mail -
// Multiaddr/PeerId (jvm-libp2p types, re-exported `api` by lapis-net-networking) also appear
// directly in PeerRecord's OWN public constructor/properties (addresses: List<Multiaddr>,
// peerId: PeerId), making the explicit edge even more clearly warranted here than in mail.
// lapis-net-core stays `implementation`: domainSeparatedDigest is used internally only.
//
// Deliberately NO java-cid dependency, unlike lapis-net-trust/lapis-net-mail: PeerRecord carries
// no io.ipfs.cid.Cid field at all (see PeerRecordCodec's doc comment) - there is nothing here for
// lapis-net-core's CidBytesValidation to guard, so it is never invoked by this module.
//
// Deliberately NO dependency on lapis-net-trust: unlike lapis-net-mail's V0.9.4 addition, this
// wave's PeerRecord acceptance is purely structural (signature + identity-binding + sequence-
// number ordering), not policy-gated - no Veritas-distance concept is needed. A future wave MAY
// add an opt-in Veritas-distance admission filter mirroring MailAcceptancePolicy; V0.8.1 does not.
//
// V0.8.2 addition: PrekeyBundleGossip/PrekeyBundleIndex publish and index lapis-net-ratchet's
// PrekeyBundle over a dedicated GossipSub topic, reusing this module's established codec + gossip +
// two/three-cap-index machinery rather than duplicating it inside lapis-net-ratchet (which is
// deliberately network-free - see that module's own build.gradle.kts). `api` because PrekeyBundle
// appears directly in PrekeyBundleGossip.announce()/lookup()'s public signatures.
dependencies {
    implementation(project(":lapis-net-core"))
    api(project(":lapis-net-identity"))
    api(project(":lapis-net-ratchet"))
    api(project(":lapis-net-storage"))
    api(project(":lapis-net-networking"))
}
