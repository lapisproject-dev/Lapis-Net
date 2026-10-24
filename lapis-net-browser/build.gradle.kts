// lapis-net-browser: V0.2.2 Minimal-Browser MVP. An embedded, loopback-only Ktor HTTP server
// running inside the same JVM process as a real LapisNode, serving a hand-written,
// framework-free HTML/CSS/vanilla-JS static page against JSON routes. No Compose Multiplatform,
// no KVision/Kilua, no JS build toolchain - just fetch() against the routes in BrowserApi.kt.

plugins {
    application
    alias(libs.plugins.kotlin.serialization)
}

application {
    mainClass.set("net.lapisphilosophorum.lapisnet.browser.BrowserMainKt")
    // V0.8.7b - webrtc-java loads a native library; JDK 25 warns (and will eventually block) native
    // access from the unnamed module without this flag.
    applicationDefaultJvmArgs = listOf("--enable-native-access=ALL-UNNAMED")
}

// V0.8.7b - every BrowserServer.start now probes WebRtcCallMediaEngine.isNativeAvailable(), so every
// test that starts a BrowserServer needs native access, not only the call tests.
tasks.withType<Test>().configureEach {
    jvmArgs("--enable-native-access=ALL-UNNAMED")
}

dependencies {
    implementation(project(":lapis-net-core"))
    implementation(project(":lapis-net-identity"))
    implementation(project(":lapis-net-networking"))
    implementation(project(":lapis-net-storage"))
    implementation(project(":lapis-net-trust"))
    implementation(project(":lapis-net-virtus"))
    implementation(project(":lapis-net-karma"))
    // V0.9.3 - new edge: mail was explicitly untouched by browser through V0.9.2.
    implementation(project(":lapis-net-mail"))
    // V0.8.6b - new edges: DM browser wiring needs the directory (PeerRecord/PrekeyBundle) and
    // ratchet (PrekeyStore) layers DmSessionManager.attach itself depends on, plus lapis-net-dm.
    implementation(project(":lapis-net-directory"))
    implementation(project(":lapis-net-ratchet"))
    implementation(project(":lapis-net-dm"))
    // V0.8.7b - browser call remote control. The webrtc-java natives arrive transitively through
    // lapis-net-call's runtimeOnly declaration.
    implementation(project(":lapis-net-call"))
    // V0.9.15 - wiring of the V0.9.x library features: Madli (relay ranking/publishing) and the shared
    // acceptance-gate vocabulary (also reachable transitively through lapis-net-dm, declared explicitly).
    implementation(project(":lapis-net-madli"))
    implementation(project(":lapis-net-policy"))
    // V0.10.0-E - `--anonymity=on`: path selection, guards and circuit-based directory publication. New edge:
    // onion-wire depends on core, identity, onion, networking and directory only, so no cycle.
    implementation(project(":lapis-net-onion-wire"))
    implementation(project(":lapis-net-onion"))
    // V0.10.0-F1 - direct messages over circuits (adapter between lapis-net-dm and lapis-net-onion-wire).
    implementation(project(":lapis-net-dm-onion"))

    implementation(rootProject.libs.ktor.server.core)
    implementation(rootProject.libs.ktor.server.netty)
    implementation(rootProject.libs.ktor.server.content.negotiation)
    implementation(rootProject.libs.ktor.server.status.pages)
    implementation(rootProject.libs.ktor.serialization.kotlinx.json)
    implementation(rootProject.libs.kotlinx.serialization.json)
    implementation(rootProject.libs.zxing.core)

    runtimeOnly(rootProject.libs.logback.classic)

    testImplementation(rootProject.libs.ktor.server.test.host)
    // V0.8.7b - CallManagerBrowserIntegrationTest reuses lapis-net-dm's real two-node harness.
    testImplementation(testFixtures(project(":lapis-net-dm")))
    // V0.8.7b - CallSessionTokenTest attaches a logback ListAppender to prove the token is never logged.
    testImplementation(rootProject.libs.logback.classic)
    // Test-only, deliberately NOT `implementation` - LightningLtrEndpointTest.kt needs to build a
    // real, in-process, cryptographically signed BOLT-11 invoice (via Bolt11Invoice.create) to
    // exercise POST /api/ltr/lightning end to end, exactly the way LightningProofVerifierTest does
    // in lapis-net-virtus. This is a test-classpath-only addition - production code in this module
    // (BrowserApi.kt) never depends on lightning-kmp/bitcoin-kmp; see LightningProofVerifier's
    // invoiceAmountMsatOrNull() helper, which is what the real route uses instead. bitcoin-kmp is
    // pinned to the same 0.31.0 used everywhere else in this project (see lapis-net-virtus's
    // build.gradle.kts version note) purely for consistency across test suites, not because this
    // module's test code interacts with lapis-net-virtus's compiled classes directly.
    testImplementation(rootProject.libs.lightning.kmp)
    testImplementation(rootProject.libs.bitcoin.kmp)
    // V0.9.3 - MailXssRenderingTest.kt needs a real, JS/DOM-executing headless browser to prove
    // mail.js's rendering function actually escapes an injected XSS payload, not just describe the
    // intent - see that test's own doc comment and gradle/libs.versions.toml's htmlunit note.
    testImplementation(rootProject.libs.htmlunit)
}
