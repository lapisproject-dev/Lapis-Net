// lapis-net-onion-wire: V0.10.0-B (unreleased), part 2 of the traffic-anonymisation arc (see
// docs/anonymity.adoc). Wires the network-free onion foundation (lapis-net-onion) into the node: a
// libp2p stream protocol "/lapis/onion/1.0.0" carrying fixed 1024-byte cells (OnionLinkProtocol /
// OnionLinkManager), the relay host around the pure OnionRelay state machine (OnionRelayService),
// persistence and rotation of the relay's onion keys (OnionKeyStore), a purely local relay quality
// tracker, and a diagnostic-only circuit client. NO user traffic is routed over circuits in this
// wave, there is no path selection and nothing is anonymised; relay mode is opt-in (--onion-relay).
//
// Why a module of its own (decision recorded in docs/architecture.adoc): lapis-net-onion must stay free
// of network code (a security property), so the adapter cannot live there; lapis-net-networking cannot
// depend on lapis-net-onion/-directory without a cycle (directory -> networking). Pattern follows
// lapis-net-dm: the module owns a StrictProtocolBinding and attach() registers it on the host.
//
// api: OnionKeyBinding/OnionRelay types (onion), LapisNode/PeerId (networking), OnionRelayDescriptor*/
// PeerDirectoryGossip (directory) and DualKeyIdentity (identity) appear in public signatures.
// implementation(lapis-net-core): nothing from core is exposed. Netty codec/handler classes
// (ByteToMessageDecoder, ReadTimeoutHandler) arrive transitively through lapis-net-networking ->
// jvm-libp2p, exactly as for lapis-net-dm.

dependencies {
    implementation(project(":lapis-net-core"))
    api(project(":lapis-net-identity"))
    api(project(":lapis-net-onion"))
    api(project(":lapis-net-networking"))
    api(project(":lapis-net-directory"))
    implementation(rootProject.libs.bouncycastle.provider)

    // Test-only SLF4J backend: OnionWireLoggingHygieneTest captures log output.
    testImplementation(rootProject.libs.logback.classic)
}

// Wave I: the Sybil simulation has a small sample that runs in `check` and a full run (20,000 clients per cell, minutes)
// that produces the table in docs/anonymity.adoc. It is switched on with -PlapisSybilFull=true and never runs in `check`.
// providers.gradleProperty keeps the task configuration-cache compatible.
tasks.test {
    systemProperty("lapis.sybil.full", providers.gradleProperty("lapisSybilFull").getOrElse("false"))
}
