// lapis-net-cli: entry point / demo harness (V0.1.8 target).
// The only module that ships a concrete SLF4J backend (logback-classic) — library
// modules stay backend-agnostic so consumers of the protocol jars can choose their own.

plugins {
    application
}

application {
    mainClass.set("net.lapisphilosophorum.lapisnet.cli.LapisNetCliKt")
}

dependencies {
    implementation(project(":lapis-net-core"))
    implementation(project(":lapis-net-identity"))
    implementation(project(":lapis-net-storage"))
    implementation(project(":lapis-net-trust"))
    implementation(project(":lapis-net-networking"))
    // V0.9.15 - `node` subcommand: DHT directory + Madli (relay ranking/publishing).
    implementation(project(":lapis-net-directory"))
    implementation(project(":lapis-net-madli"))
    // V0.10.0-B - `--onion-relay`: onion relay infrastructure (no user traffic is routed over it yet).
    implementation(project(":lapis-net-onion-wire"))
    implementation(project(":lapis-net-onion"))

    runtimeOnly(rootProject.libs.logback.classic)
}
