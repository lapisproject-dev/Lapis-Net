// lapis-net-mail: asynchronous messages (the e-mail replacement), V0.9.1 - the message format
// itself. MessageEnvelope is the signed, addressed wrapper; MessageBody is the payload blob its
// contentCid is bound to. Propagation is GossipSub-only, one topic per recipient identity
// (InboxTopics), mirroring the KarmaGossip/MadliGossip/LtrGossip codec + gossip + two-cap-index
// shape that lapis-net-trust's VeritasGossip/VeritasGrantIndex established in V0.1.7.
//
// Dependency shape mirrors lapis-net-virtus/lapis-net-karma (see those modules' build.gradle.kts
// comments) for the same reasons: lapis-net-identity is `api` because Secp256k1PublicKey/
// Secp256k1KeyPair appear in MessageEnvelope's public constructor/properties/create()/verify()
// signatures and in InboxTopics/InboxGossip/MailSender's public signatures; java-cid is `api`
// because io.ipfs.cid.Cid appears in MessageEnvelope's (contentCid/replyTo/threadRoot) and
// AttachmentRef's public API; lapis-net-storage is `api` because NabuStorage appears directly in
// InboxGossip.attach()'s and MailSender's public signatures. lapis-net-core stays
// `implementation`: domainSeparatedDigest is used internally only.
//
// DELIBERATE DIVERGENCE from the sibling modules: lapis-net-networking is declared EXPLICITLY here,
// not relied on transitively. lapis-net-trust/-virtus/-karma/-madli all expose GossipPubSub in a
// public attach() signature while depending on lapis-net-storage's `api` edge to re-export it
// (documented in lapis-net-trust/build.gradle.kts). That works, but it contradicts the house rule
// lapis-net-madli/build.gradle.kts states in its own comment - "a type appearing directly in this
// module's public API is declared directly, not relied on transitively". GossipPubSub appears in
// InboxGossip.attach() and MailSender's constructor, so this module follows the stated rule rather
// than the accidental practice. The edge is redundant, never conflicting: lapis-net-storage already
// re-exports the identical project dependency.
//
// Deliberately NOT a dependency on lapis-net-trust/-virtus/-karma/-madli: mail is a separate
// subsystem, not a scoring dimension, and shares only the identity keypair and the protocol core
// (see docs/roadmap.adoc's V0.9 entry and docs/architecture.adoc's Layering section). Nothing in
// MessageEnvelope's data model needs a VeritasGrant, LtrRecord, KarmaVote, or MadliDailyVector.
// V0.9.2 addition: BouncyCastle stays `implementation`, same reasoning as
// lapis-net-identity/build.gradle.kts's own comment about secp256k1-kmp/BouncyCastle - its
// HKDFBytesGenerator/HKDFParameters types (used internally by HybridEcies's key derivation) never
// appear in any public signature of this module. No secp256k1-kmp dependency is added here: the
// ECDH primitive (ecdhSharedSecret) lives in lapis-net-identity and reaches this module through the
// existing `api(project(":lapis-net-identity"))` edge above as a Lapis-value-typed function
// (Secp256k1PrivateKey, Secp256k1PublicKey in/out) - no third-party crypto type crosses the
// module boundary, upholding lapis-net-identity's own stated rule.
dependencies {
    implementation(project(":lapis-net-core"))
    api(project(":lapis-net-identity"))
    api(project(":lapis-net-storage"))
    api(project(":lapis-net-networking"))
    api(rootProject.libs.java.cid)
    implementation(rootProject.libs.bouncycastle.provider)
}
