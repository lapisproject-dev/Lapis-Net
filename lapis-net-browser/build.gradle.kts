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

    implementation(rootProject.libs.ktor.server.core)
    implementation(rootProject.libs.ktor.server.netty)
    implementation(rootProject.libs.ktor.server.content.negotiation)
    implementation(rootProject.libs.ktor.server.status.pages)
    implementation(rootProject.libs.ktor.serialization.kotlinx.json)
    implementation(rootProject.libs.kotlinx.serialization.json)
    implementation(rootProject.libs.zxing.core)

    runtimeOnly(rootProject.libs.logback.classic)

    testImplementation(rootProject.libs.ktor.server.test.host)
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
