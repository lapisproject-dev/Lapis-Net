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
// V0.8.5 REVERSAL of an earlier statement in this comment (kept here, corrected, rather than
// silently dropped - the original claimed the opposite of what is now true): this module used to
// have NO lapis-net-storage dependency, because DM sessions persist via
// DoubleRatchetSessionCodec's own file-based encrypted-at-rest format, and there was no content-
// addressed blob to store. V0.8.5's offline Nabu mailbox makes that statement false: a
// DmEnvelope deposited for offline pickup IS a content-addressed Nabu blob
// (DmSessionManager.sendOffline calls NabuStorage.put/get), and MailboxPointer carries an
// io.ipfs.cid.Cid field directly in its own public constructor/properties (see MailboxPointer.kt/
// MailboxPointerCodec.kt). `api`, not `implementation`, because NabuStorage/Cid appear directly in
// DmSessionManager.attach()'s and MailboxGossip.attach()'s public signatures and in MailboxPointer's
// own public API - the same "explicit-not-transitive" house rule already governing every other
// dependency edge in this module.
//
// V0.8.5 addition: GossipPubSub needs no NEW dependency edge (already reachable via
// api(lapis-net-networking)), but is now used directly in this module's own implementation
// (DmSessionManager.sendOffline, MailboxRedeliveryScheduler) and appears directly in
// DmSessionManager.attach()'s new `pubsub` parameter - satisfying the same house rule.
//
// Netty codec classes (LengthFieldBasedFrameDecoder, LengthFieldPrepender, ReadTimeoutHandler) need
// no separate dependency declaration - verified against the resolved classpath: as of jvm-libp2p
// 1.3.5-RELEASE's transitive Netty 4.2.10.Final, both moved into netty-codec-base/netty-handler
// (already pulled in transitively via api(lapis-net-networking) -> api(jvm-libp2p) -> Netty), the
// same way GossipPubSub.kt's own Unpooled/ByteBufUtil usage arrives.
//
// V0.8.6 additions:
// api(lapis-net-policy): AcceptanceGate/KarmaScoreLookup appear directly in DmAcceptancePolicy's/
// DmAcceptanceCheck's public signatures.
// implementation(lightning-kmp)/implementation(bitcoin-kmp): identical reasoning and identical
// bitcoin-kmp version-pinning note to lapis-net-mail/build.gradle.kts's own comment (lightning-kmp's
// published POM pins an older bitcoin-kmp-jvm than this project resolves elsewhere; the explicit
// bitcoin-kmp dependency here forces the same resolved version everywhere). Every fr.acinq.* type
// stays confined to DmFirstContactDepositVerifier.kt, mirroring FirstContactDepositVerifier's "sole
// consumer" discipline.
dependencies {
    implementation(project(":lapis-net-core"))
    api(project(":lapis-net-identity"))
    api(project(":lapis-net-ratchet"))
    api(project(":lapis-net-directory"))
    api(project(":lapis-net-networking"))
    api(project(":lapis-net-storage"))
    api(project(":lapis-net-policy"))
    implementation(rootProject.libs.lightning.kmp)
    implementation(rootProject.libs.bitcoin.kmp)
}
