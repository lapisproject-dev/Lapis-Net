// lapis-net-ratchet: V0.8.2, the second sub-wave of the V0.8 (direct messages and calls) arc.
// PURE CRYPTOGRAPHIC PRIMITIVES ONLY - the X3DH handshake (Signal's published specification,
// reimplemented from the spec because libsignal is AGPL-3.0 and this project is Apache-2.0), the
// PrekeyBundle it consumes, that bundle's canonical codec, and the local PrekeyStore holding the
// private halves with genuine one-time-prekey consumption semantics.
//
// DELIBERATELY ZERO network/libp2p/Nabu/java-cid dependencies, and this isolation is a security
// property, not a packaging preference: a reviewer auditing the handshake in this module never has
// to reason about untrusted network input and crypto correctness in the same file. Publication of
// PrekeyBundles over GossipSub lives in lapis-net-directory (PrekeyBundleGossip/PrekeyBundleIndex),
// which already owns this codebase's "signed record over its own gossip topic with a two-cap index"
// machinery and already documents (in its own build.gradle.kts and PeerRecord's doc comment) that
// V0.8.2's prekey bundles resolve through it. A later sub-wave's lapis-net-dm module is the one that
// will carry network dependencies and call into THIS module.
//
// lapis-net-identity is `api`: X25519PublicKey/X25519PrivateKey/X25519KeyPair/EncryptionKeyBinding/
// Secp256k1PublicKey/DualKeyIdentity/PassphraseProvider all appear directly in this module's public
// signatures (PrekeyBundle's properties, X3dh's parameters, PrekeyStore's factory functions) -
// following lapis-net-mail's/lapis-net-directory's stated "explicit-not-transitive" house rule.
// lapis-net-core stays `implementation`: domainSeparatedDigest is used internally only.
// BouncyCastle stays `implementation`, same reasoning as lapis-net-identity's and lapis-net-mail's
// own build.gradle.kts comments: HKDFBytesGenerator/HKDFParameters/SHA256Digest are used internally
// by X3dh's key derivation and never appear in any public signature of this module. The X25519 key
// agreement primitive itself is NOT reached from here directly - it lives in lapis-net-identity as
// the Lapis-value-typed `x25519SharedSecret(X25519PrivateKey, X25519PublicKey)` function, mirroring
// exactly how lapis-net-mail reaches secp256k1 ECDH through `ecdhSharedSecret` without ever
// depending on secp256k1-kmp itself.
//
// Deliberately NO java-cid dependency: no io.ipfs.cid.Cid field exists anywhere in this module's
// wire formats, so lapis-net-core's CidBytesValidation is never invoked here - stated explicitly so
// a reviewer does not go looking for a missing guard (mirroring PeerRecordCodec's own N/A note).
dependencies {
    implementation(project(":lapis-net-core"))
    api(project(":lapis-net-identity"))
    implementation(rootProject.libs.bouncycastle.provider)
}
