import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    alias(libs.plugins.kotlin.jvm) apply false
    alias(libs.plugins.ktlint) apply false
}

allprojects {
    group = "net.lapisphilosophorum"
    version = "0.9.5"

    repositories {
        mavenCentral()
        // jvm-libp2p (lapis-net-networking) is not published to Maven Central - declared here,
        // not just in that module's own build.gradle.kts, because it's exposed as an `api`
        // dependency: any module compiling against lapis-net-networking (e.g. lapis-net-cli)
        // needs to resolve it too. See https://github.com/libp2p/jvm-libp2p ("Adding as a
        // dependency") for the up-to-date list of mirrors - all three are required, not just
        // the first: jvm-libp2p's own transitive dependencies (java-multibase, noise-java) are
        // split across JitPack and the Consensys artifact server.
        // Each is scoped to only the group(s) it actually needs to serve, so a future dependency
        // added anywhere in this build can't silently resolve through - and get build-on-demand
        // compiled from an arbitrary GitHub repo by - JitPack in particular.
        maven("https://dl.cloudsmith.io/public/libp2p/jvm-libp2p/maven/") {
            content { includeGroup("io.libp2p") }
        }
        // com.github.peergos: Nabu (DHT + Bitswap, lapis-net-storage) and its own forked
        // jvm-libp2p (excluded - see lapis-net-storage/build.gradle.kts for why).
        // com.github.ipld: java-cid, transitive via java-multiaddr, used directly in Nabu's
        // public API (Cid). com.github.dnsjava: Nabu pins this JitPack-mirrored coordinate
        // rather than the native dnsjava:dnsjava Maven Central artifact.
        maven("https://jitpack.io") {
            content {
                includeGroup("com.github.multiformats")
                includeGroup("com.github.peergos")
                includeGroup("com.github.ipld")
                includeGroup("com.github.dnsjava")
            }
        }
        maven("https://artifacts.consensys.net/public/maven/maven/") {
            content { includeGroup("tech.pegasys") }
        }
    }
}

subprojects {
    apply(plugin = "org.jetbrains.kotlin.jvm")
    apply(plugin = "org.jlleitschuh.gradle.ktlint")

    dependencies {
        add("implementation", rootProject.libs.kotlin.logging)
        add("implementation", rootProject.libs.slf4j.api)

        add("testImplementation", rootProject.libs.kotest.runner.junit5)
        add("testImplementation", rootProject.libs.kotest.assertions.core)
    }

    tasks.withType<KotlinCompile>().configureEach {
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_25)
        }
    }

    extensions.configure<org.gradle.api.plugins.JavaPluginExtension> {
        toolchain {
            languageVersion.set(JavaLanguageVersion.of(25))
        }
    }

    tasks.withType<Test>().configureEach {
        useJUnitPlatform()
    }
}
