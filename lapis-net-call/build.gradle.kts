// lapis-net-call: V0.8.7, 1:1 direct calls over WebRTC - the fifth sub-wave of the V0.8 (direct
// messages and calls) arc, and the FIRST module in this codebase to depend on real-time media
// (dev.onvoid.webrtc:webrtc-java, an Apache-2.0-licensed JNI binding over a bundled BSD-3 libwebrtc
// build - no AGPL exposure, unlike lapis-net-mail's own `libsignal` avoidance precedent, which does
// not apply here since this is a DIFFERENT third-party dependency with a DIFFERENT license).
//
// Depends on lapis-net-dm for signaling transport (DmSessionManager.sendCallSignal/
// addCallSignalListener - see DmCallSignalTransport.kt) and DTLS-fingerprint identity binding (the
// SDP travels inside the SAME Double Ratchet AEAD as a text DM - see docs/architecture.adoc's "1:1
// calls over WebRTC" section for the full argument for why this makes Insertable-Streams E2EE
// functionally unnecessary for a 1:1 call). The dependency edge runs lapis-net-call -> lapis-net-dm,
// never the other way: lapis-net-dm stays entirely WebRTC-free (see DmInboundCallSignal's own doc
// comment) - the 25 MB native webrtc-java library never lands on lapis-net-dm's, lapis-net-directory's,
// lapis-net-mail's, or lapis-net-cli's classpath merely by them depending on lapis-net-dm.
//
// api(lapis-net-dm): Secp256k1PublicKey/DmSessionManager/DmInboundCallSignal appear directly in
// DmCallSignalTransport's/CallManager.attach()'s public signatures.
// implementation(lapis-net-core): FixedWindowRateLimiter (CallManager's own invite-rate limiter) used
// internally only.
// implementation(webrtc-java): confined ENTIRELY to WebRtcCallMediaEngine.kt - the sole consumer of
// `dev.onvoid.webrtc.*` in this module, mirroring lapis-net-dm's own `fr.acinq.*`-confined-to-
// DmFirstContactDepositVerifier.kt "sole consumer" discipline. Every other file in this module only
// ever sees the CallMediaEngine/CallMediaSession/CallMediaObserver interfaces.
dependencies {
    api(project(":lapis-net-dm"))
    implementation(project(":lapis-net-core"))
    implementation(rootProject.libs.webrtc.java)
    runtimeOnly(variantOf(rootProject.libs.webrtc.java) { classifier(webrtcNativeClassifier()) })
    testRuntimeOnly(rootProject.libs.logback.classic)
    // testFixtures(lapis-net-dm): buildDmTestNode/connectAndConverge/DmTestNode -
    // TwoNodeCallIntegrationTest.kt's real two-node setup. Every type these helpers reference
    // (LapisNode, PeerDirectoryGossip, PrekeyStore, NabuStorage, GossipPubSub, DualKeyIdentity) is
    // already resolvable here via the api(lapis-net-dm) edge above (lapis-net-dm re-exports them as
    // api itself) - this edge only needs to bring the HELPER FUNCTIONS/CLASSES themselves.
    testImplementation(testFixtures(project(":lapis-net-dm")))
}

// Host-platform classifier detection for webrtc-java's native binary - NOT all five platform
// classifiers are declared, deliberately: doing so would pull ~125 MB of native libraries into every
// build regardless of host OS/arch. CI runs on ubuntu-latest/x86_64; developer machines in this
// project are Linux-x86_64 or macOS-aarch64 (see CLAUDE.md's OS-detection table) - this function
// covers exactly those, plus the remaining combinations webrtc-java itself publishes, so a build on
// any of the five published platforms resolves the RIGHT native jar rather than silently resolving
// none (which would fail at runtime, not at build time, with an unhelpful UnsatisfiedLinkError far
// from this comment).
fun webrtcNativeClassifier(): String {
    val os = System.getProperty("os.name").lowercase()
    val arch = System.getProperty("os.arch").lowercase()
    val osPart =
        when {
            os.contains("mac") || os.contains("darwin") -> "macos"
            os.contains("linux") -> "linux"
            os.contains("windows") -> "windows"
            else -> error("unsupported OS for webrtc-java natives: $os")
        }
    val archPart =
        when (arch) {
            "amd64", "x86_64" -> "x86_64"
            "aarch64", "arm64" -> "aarch64"
            else -> error("unsupported architecture for webrtc-java natives: $arch")
        }
    return "$osPart-$archPart"
}

tasks.withType<Test>().configureEach {
    // JDK 25: System.load (used internally by webrtc-java's native bootstrap) is a "restricted
    // method" - a warning today, a hard blockade in a future JDK. Verified 2026-09-02 on Temurin
    // 25.0.4 - see docs/architecture.adoc's "1:1 calls over WebRTC" section, "explicit, deliberate
    // scope cuts" subsection, for the full note.
    jvmArgs("--enable-native-access=ALL-UNNAMED")
}
