// lapis-net-policy: V0.8.6 extraction. Holds the acceptance-gate vocabulary (VeritasPath /
// KarmaThreshold) and its evaluator, factored out of lapis-net-mail's MailAcceptancePolicy so a
// second caller - lapis-net-dm's DmAcceptancePolicy - can reuse the SAME gate semantics without
// depending on lapis-net-mail (which is DM's sibling, not an ancestor). MailAcceptancePolicy keeps
// its own public types (MailAcceptanceGate, MailAcceptanceDecision, KarmaScoreLookup) unchanged and
// now delegates internally - see lapis-net-mail/build.gradle.kts's own updated comment and
// MailAcceptancePolicy.kt's class doc comment for the full "gates shared, decision not shared"
// reasoning (docs/architecture.adoc has the long-form version).
//
// api(lapis-net-identity): Secp256k1PublicKey appears directly in AcceptanceGateEvaluator's and
// KarmaScoreLookup's public signatures.
// api(lapis-net-trust): TrustGraph appears directly in AcceptanceGateEvaluator.veritasPathCheck's
// and VeritasPathCache's public signatures.
//
// Deliberately NO dependency on lapis-net-karma: exactly like MailAcceptancePolicy before it, there
// is no existing per-identity Karma score to call (Karma is computed per-CONTENT) - the Karma gate
// takes an injected KarmaScoreLookup instead.
dependencies {
    api(project(":lapis-net-identity"))
    api(project(":lapis-net-trust"))
}
