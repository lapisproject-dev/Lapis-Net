// lapis-net-networking: libp2p node bootstrap and GossipSub propagation.
//
// jvm-libp2p is `api`, not `implementation` - deliberately, unlike lapis-net-identity's
// treatment of secp256k1-kmp/Bouncy Castle. This module's public API (LapisNode.peerId,
// listenAddresses(), discovered/connected peer types) is built directly on jvm-libp2p's own
// PeerId/Multiaddr/Connection/PeerInfo types: they are small immutable domain values (not
// low-level crypto primitives needing encapsulation), and this module's entire purpose per
// docs/architecture.adoc is to *be* the libp2p integration layer. Wrapping them would add
// indirection with no safety benefit and would have to be unwound again once GossipSub
// (V0.1.7) lands in this same module and needs the real types anyway.
//
// lapis-net-identity is `api` for a different reason: DualKeyIdentity (this project's own
// domain type) appears directly in this module's public signatures (LapisNode.create(identity:
// DualKeyIdentity, ...)), so any module calling into lapis-net-networking's public API
// transitively needs lapis-net-identity on its own compile classpath too.

// jvm-libp2p's non-Maven-Central repositories are declared in the root build.gradle.kts
// (allprojects), not here, because this dependency is `api` - lapis-net-cli (and any future
// consumer of this module) needs to resolve it too, not just this module.

dependencies {
    implementation(project(":lapis-net-core"))
    api(project(":lapis-net-identity"))
    api(rootProject.libs.jvm.libp2p)
    // See the `netty` entry in gradle/libs.versions.toml: jvm-libp2p exposes these codecs only at
    // runtime scope, and relay/CircuitRelayProtocols.kt needs them at compile time.
    implementation(rootProject.libs.netty.codec.protobuf)

    // Test-only concrete SLF4J backend, so GossipPubSubConnectOrderTest can attach a Logback
    // ListAppender and assert on actual WARN-level log events (round-2 N1 regression test) - this
    // module otherwise stays backend-free at compile/runtime (see lapis-net-cli's build.gradle.kts
    // comment: it is the only module that ships a concrete backend for real usage).
    testImplementation(rootProject.libs.logback.classic)
}
