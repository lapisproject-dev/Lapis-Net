// lapis-net-dm: V0.8.4, the fourth sub-wave of the V0.8 (direct messages and calls) arc, and the
// FIRST module in this codebase that carries a custom libp2p STREAM protocol binding rather than
// reusing GossipSub. Wires lapis-net-ratchet's already-reviewed X3DH/Double-Ratchet primitives
// (V0.8.2/V0.8.3, both deliberately network-free) into a live network path: DmProtocol (a custom
// "/lapis/dm/1.0.0" jvm-libp2p StrictProtocolBinding/ProtocolHandler, mirroring the bundled
// io.libp2p.protocol.Ping reference implementation's shape), DmEnvelope/DmEnvelopeCodec (the outer
// wire frame), and DmSessionManager (the state machine driving X3dh.initiate/respond and
// DoubleRatchetSession.encrypt/decrypt for real 1:1 conversations, with durable session persistence
// reusing DoubleRatchetSessionCodec.encodeWithKey/decodeWithKey).
//
// This is the FIRST place in the codebase parsing untrusted bytes off a raw libp2p stream with NO
// GossipSub message-size ceiling backstopping the parser - see DmProtocol's own class doc comment
// for the length-validated-before-allocation / slowloris-timeout / per-peer-stream-cap discipline
// this demands.
//
// implementation(lapis-net-core): domainSeparatedDigest (DmDedupKey) used internally only.
// api(lapis-net-identity): DualKeyIdentity/Secp256k1PublicKey/EncryptionKeyBinding appear directly
// in DmSessionManager's/DmEnvelope's public signatures.
// api(lapis-net-ratchet): DoubleRatchetSession/RatchetMessage/PrekeyStore/X3dh types appear directly
// in DmEnvelope's and DmSessionManager's public signatures.
// api(lapis-net-directory): PeerDirectoryGossip/PrekeyBundleGossip appear directly in
// DmSessionManager.attach()'s public signature.
// api(lapis-net-networking): LapisNode/Host/PeerId/Multiaddr (jvm-libp2p, re-exported api by
// lapis-net-networking) appear directly in DmProtocol's/DmSessionManager's public signatures -
// mirrors lapis-net-directory's own "explicit-not-transitive" house rule.
//
// Deliberately NO lapis-net-storage dependency: DM sessions persist via
// DoubleRatchetSessionCodec's own file-based encrypted-at-rest format (mirroring PrekeyStore's
// atomic-temp-file-then-move pattern), never via NabuStorage/CID - there is no content-addressed
// blob here to store, and DmStore (conversation history) is explicitly in-memory-only this wave
// (see that class's own doc comment for the documented scope cut).
//
// Netty codec classes (LengthFieldBasedFrameDecoder, LengthFieldPrepender, ReadTimeoutHandler) need
// no separate dependency declaration - verified against the resolved classpath: as of jvm-libp2p
// 1.3.5-RELEASE's transitive Netty 4.2.10.Final, both moved into netty-codec-base/netty-handler
// (already pulled in transitively via api(lapis-net-networking) -> api(jvm-libp2p) -> Netty), the
// same way GossipPubSub.kt's own Unpooled/ByteBufUtil usage arrives.
dependencies {
    implementation(project(":lapis-net-core"))
    api(project(":lapis-net-identity"))
    api(project(":lapis-net-ratchet"))
    api(project(":lapis-net-directory"))
    api(project(":lapis-net-networking"))
}
