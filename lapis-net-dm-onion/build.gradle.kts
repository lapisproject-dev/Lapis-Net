// lapis-net-dm-onion: V0.10.0-F1, direct messages over circuits. The adapter between lapis-net-dm (which knows
// nothing about onion circuits, only the AnonymousDmTransport seam) and lapis-net-onion-wire (which knows nothing
// about direct messages). Neither of those two may depend on the other, hence this module: it implements the
// transport (rendezvous-stream framing with a constant acknowledgement, the sender's small stream cache), the
// re-announcement of sealed offline mailbox items and the subscriber that opens items from the shared topic.
//
// api(lapis-net-dm): AnonymousDmTransport / DmInboundSink appear in this module's public signatures.
// api(lapis-net-onion-wire): AnonymityRuntime / OnionServiceStreamRouter appear in the public signatures.
// directory, identity and ratchet types (DirectoryReachability, PrekeyBundle, keys) reach callers through those two.
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
}
