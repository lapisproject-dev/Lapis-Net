// lapis-net-onion: V0.10.0-A (unreleased), the foundation of the traffic-anonymisation arc
// (see docs/anonymity.adoc). PURE CRYPTO + CELL STATE, ZERO network/libp2p/Nabu dependencies,
// NOT wired into LapisNode, the browser or the CLI. This isolation is a security property, not a
// packaging preference (same reasoning as lapis-net-ratchet): a reviewer auditing the handshake and
// the onion layering here never has to reason about untrusted network input and crypto correctness
// in the same file. The relay state machine (OnionRelay) consumes cells and RETURNS actions; it
// performs no I/O of its own.
//
// lapis-net-identity is `api`: X25519PublicKey/X25519PrivateKey/Secp256k1PublicKey/Secp256k1KeyPair
// appear in this module's public signatures (OnionKeyBinding, NtorHandshake, OnionRelay).
// lapis-net-core stays `implementation` (domainSeparatedDigest is used internally only).
// BouncyCastle stays `implementation`: HKDF/HMAC/ChaCha20Poly1305/constantTimeAreEqual are used
// internally and never appear in a public signature. No new third-party dependency was added.
dependencies {
    implementation(project(":lapis-net-core"))
    api(project(":lapis-net-identity"))
    implementation(rootProject.libs.bouncycastle.provider)

    // Test-only SLF4J backend, used exclusively by LoggingHygieneTest to capture log output.
    testImplementation(rootProject.libs.logback.classic)
}
