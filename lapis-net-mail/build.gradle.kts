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
// V0.9.2 addition: BouncyCastle stays `implementation`, same reasoning as
// lapis-net-identity/build.gradle.kts's own comment about secp256k1-kmp/BouncyCastle - its
// HKDFBytesGenerator/HKDFParameters types (used internally by HybridEcies's key derivation) never
// appear in any public signature of this module. No secp256k1-kmp dependency is added here: the
// ECDH primitive (ecdhSharedSecret) lives in lapis-net-identity and reaches this module through the
// existing `api(project(":lapis-net-identity"))` edge above as a Lapis-value-typed function
// (Secp256k1PrivateKey, Secp256k1PublicKey in/out) - no third-party crypto type crosses the
// module boundary, upholding lapis-net-identity's own stated rule.
//
// V0.9.4 addition, REVISING the V0.9.1-V0.9.3 "deliberately NOT a dependency on lapis-net-trust/
// -virtus/-karma/-madli" stance: this module NOW depends on lapis-net-trust, mirroring
// lapis-net-madli's own precedent EXACTLY (see that module's build.gradle.kts comment - "DELIBERATE
// DEVIATION from the Karma/Virtus 'no sibling trust dependency' rule"). MailAcceptancePolicy's
// Veritas-distance spam filter needs TrustGraph/TrustPathFinder to answer "does the local identity
// have a positive trust path to this sender" - exactly the same shape of question Madli's
// veritasObserverWeight adapter answers for node reputation. `api` because TrustGraph appears
// directly in MailAcceptancePolicy.veritasPathCheck's public signature. The policy's CORE
// (MailAcceptancePolicy.shouldAccept) still takes trust as an injected `hasVeritasPath: (key) ->
// Boolean` lambda, mirroring MadliAggregator.aggregate's injected observerWeight lambda - only the
// thin veritasPathCheck adapter references TrustGraph/TrustPathFinder directly. Still NO dependency
// on lapis-net-karma: there is no existing per-identity Karma score in that module to call (Karma
// is computed per-CONTENT, see MailAcceptancePolicy's KarmaScoreLookup doc comment for the full
// reasoning) - the Karma gate takes an injected score lookup instead. Still NO dependency on
// lapis-net-virtus or lapis-net-madli: FirstContactDepositVerifier structurally mirrors
// lapis-net-virtus's LightningProofVerifier (V0.6) but is a deliberately separate, reimplemented
// object (see that class's doc comment for why it cannot simply call through), and nothing here
// needs a MadliDailyVector.
//
// lightning-kmp/bitcoin-kmp are `implementation` ONLY, never `api` - identical reasoning and the
// identical bitcoin-kmp version-pinning note to lapis-net-virtus/build.gradle.kts (lightning-kmp's
// own published POM pins an older bitcoin-kmp-jvm than this project resolves elsewhere; the
// explicit bitcoin-kmp dependency here forces the same 0.31.0 resolved everywhere else). Every
// fr.acinq.* type stays confined to FirstContactDepositVerifier.kt, mirroring LightningProofVerifier's
// "sole consumer" discipline.
//
// V0.8.6 addition: this module now depends on lapis-net-policy. MailAcceptanceGate/
// MailAcceptanceDecision/KarmaScoreLookup stay declared HERE (public API unchanged - see
// MailAcceptancePolicy.kt's own class doc comment for why), but MailAcceptancePolicy.shouldAccept
// and MailAcceptanceCheck.cachedVeritasPathCheck now delegate internally to
// lapis-net-policy's AcceptanceGateEvaluator/VeritasPathCache, extracted so lapis-net-dm's
// DmAcceptancePolicy (V0.8.6) can reuse the identical gate semantics without a lapis-net-dm ->
// lapis-net-mail dependency (siblings, not an ancestor relationship). `implementation`, not `api`:
// AcceptanceGate/VeritasPathCache never appear in this module's own public signatures, only inside
// MailAcceptancePolicy's/MailAcceptanceCheck's private mapping/delegation code.
dependencies {
    implementation(project(":lapis-net-core"))
    api(project(":lapis-net-identity"))
    api(project(":lapis-net-storage"))
    api(project(":lapis-net-networking"))
    api(project(":lapis-net-trust"))
    api(rootProject.libs.java.cid)
    implementation(project(":lapis-net-policy"))
    implementation(rootProject.libs.bouncycastle.provider)
    implementation(rootProject.libs.lightning.kmp)
    implementation(rootProject.libs.bitcoin.kmp)
}

// MailAttachmentCipherTest's "encrypt rejects plaintext above MAX_PLAINTEXT_BYTES" test allocates a
// single real ~1 GiB ByteArray to actually exercise MailAttachmentCipher.encrypt's size guard
// (rather than merely re-deriving the boundary constant) - the root project's default test-worker
// heap is too small for that one-off allocation. Scoped to this module only, not the root build,
// since no other module's tests need it.
tasks.test {
    maxHeapSize = "2g"
}
