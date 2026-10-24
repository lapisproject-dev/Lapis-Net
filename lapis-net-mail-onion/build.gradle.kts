// lapis-net-mail-onion: V0.10.0-F2, mail over circuits. The adapter between lapis-net-mail (which knows nothing about
// onion circuits, only the AnonymousMailTransport / AnonymousMailInboundSink seam) and lapis-net-onion-wire (which
// knows nothing about mail). Neither of those may depend on the other, hence this module, the same shape as
// lapis-net-dm-onion: rendezvous-stream bundles with a constant acknowledgement, the sender's bounded online retry
// queue for bundles that do not fit a sealed mailbox item, and the subscriber that opens MAIL items from the shared topic.
//
// api(lapis-net-mail): AnonymousMailTransport / AnonymousMailInboundSink appear in this module's public signatures.
// api(lapis-net-dm-onion): FrameChannel, StreamFrameChannel, DmFrameReader and AnonymousMailboxRedelivery are reused
// (one framing, one redelivery queue per node). api(lapis-net-onion-wire): AnonymityRuntime is in the port signature.
dependencies {
    api(project(":lapis-net-mail"))
    api(project(":lapis-net-dm-onion"))
    api(project(":lapis-net-onion-wire"))
    api(project(":lapis-net-onion"))
    api(project(":lapis-net-directory"))
    api(project(":lapis-net-identity"))
    api(project(":lapis-net-ratchet"))
    api(project(":lapis-net-networking"))
    api(project(":lapis-net-storage"))

    testImplementation(testFixtures(project(":lapis-net-dm-onion")))
    testImplementation(testFixtures(project(":lapis-net-dm")))
    testImplementation(project(":lapis-net-trust"))
    testImplementation(project(":lapis-net-policy"))
    // Test-only SLF4J backend: the logging hygiene test captures log output.
    testImplementation(rootProject.libs.logback.classic)
}
