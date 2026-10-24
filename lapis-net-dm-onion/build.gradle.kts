// lapis-net-dm-onion: V0.10.0-F1, direct messages over circuits. The adapter between lapis-net-dm (which knows
// nothing about onion circuits, only the AnonymousDmTransport seam) and lapis-net-onion-wire (which knows nothing
// about direct messages). Neither of those two may depend on the other, hence this module: it implements the
// transport (rendezvous-stream framing with a constant acknowledgement, the sender's small stream cache), the
// re-announcement of sealed offline mailbox items and the subscriber that opens items from the shared topic.
//
// api(lapis-net-dm): AnonymousDmTransport / DmInboundSink appear in this module's public signatures.
// api(lapis-net-onion-wire): AnonymityRuntime / OnionServiceStreamRouter appear in the public signatures.
// directory, identity and ratchet types (DirectoryReachability, PrekeyBundle, keys) reach callers through those two.
// V0.10.0-F2: java-test-fixtures exposes DmOnionHarness / DmOnionTestSupport (relay hosts, the anonymity-mode node
// rig, fake channels and ports) to lapis-net-mail-onion's tests, which need the same real multi-node circuit setup.
plugins {
    id("java-test-fixtures")
}

dependencies {
    api(project(":lapis-net-dm"))
    api(project(":lapis-net-onion-wire"))
    api(project(":lapis-net-onion"))
    api(project(":lapis-net-directory"))
    api(project(":lapis-net-identity"))
    api(project(":lapis-net-ratchet"))
    api(project(":lapis-net-networking"))

    testImplementation(testFixtures(project(":lapis-net-dm")))
    testImplementation(project(":lapis-net-trust"))
    testImplementation(project(":lapis-net-policy"))
    testImplementation(project(":lapis-net-storage"))
    // Test-only SLF4J backend: the logging hygiene test captures log output.
    testImplementation(rootProject.libs.logback.classic)

    // The fixtures compile against the same types as the main sources plus the node rig's own collaborators; the
    // java-test-fixtures plugin does not inherit main's dependencies, so they are declared explicitly (see lapis-net-dm).
    testFixturesApi(project(":lapis-net-dm"))
    testFixturesApi(testFixtures(project(":lapis-net-dm")))
    testFixturesApi(project(":lapis-net-onion-wire"))
    testFixturesApi(project(":lapis-net-onion"))
    testFixturesApi(project(":lapis-net-directory"))
    testFixturesApi(project(":lapis-net-identity"))
    testFixturesApi(project(":lapis-net-ratchet"))
    testFixturesApi(project(":lapis-net-networking"))
    testFixturesApi(project(":lapis-net-storage"))
    testFixturesApi(project(":lapis-net-trust"))
    testFixturesApi(project(":lapis-net-policy"))
    testFixturesImplementation(rootProject.libs.logback.classic)
}
