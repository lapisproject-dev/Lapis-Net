// lapis-net-storage: DHT / content-storage via Nabu (Bitswap + Kademlia), layered on the
// lapis-net-networking Host.
//
// nabu and java-cid are `api`, not `implementation` - matching lapis-net-networking's treatment
// of jvm-libp2p (see that module's build.gradle.kts): this module's public API (NabuStorage's
// put/get/provide/findProviders) is built directly on Nabu's own Cid/Blockstore/Bitswap/
// Kademlia/PeerAddresses types, which are small immutable multiformats/domain value types (not
// low-level crypto primitives needing encapsulation), and this module's entire purpose per
// docs/architecture.adoc is to *be* the Nabu integration layer.
//
// CRITICAL classpath note: Nabu's own pom.xml pins a transitive dependency on
// com.github.peergos:jvm-libp2p:0.18.0-ipv6-mdns-wildcard - a Peergos-maintained *fork* of
// io.libp2p:jvm-libp2p (this project's own dependency, from lapis-net-networking) that ships
// overlapping io.libp2p.* packages under a different groupId. 361 of 829 shared class files
// differ in bytecode between the two artifacts (verified via jar tf + cmp before writing this
// module). The fork is excluded below and Nabu is forced to resolve against the official
// io.libp2p:jvm-libp2p already on this project's classpath instead. This is safe here because
// Nabu's Bitswap/Kademlia classes (and their engines) have zero compiled references to the
// io.libp2p.core.dsl.* builder classes that differ between the two jars - only Nabu's own
// unused org.peergos.HostBuilder touches those - confirmed both statically (javap/bytecode
// inspection) and at runtime (a throwaway two-node Bitswap put/get spike against the official
// jar passed cleanly). Host construction in this project always goes through
// lapis-net-networking's LapisNode.create() (the official jvm-libp2p DSL), never through Nabu's
// own HostBuilder/EmbeddedIpfs.
dependencies {
    implementation(project(":lapis-net-core"))
    api(project(":lapis-net-networking"))
    api(rootProject.libs.nabu) {
        exclude(group = "com.github.peergos", module = "jvm-libp2p")
    }
    api(rootProject.libs.java.cid)
    // wave Q20 - BlockProvideSchedulerTest attaches a logback ListAppender to prove no CID is logged.
    testImplementation(rootProject.libs.logback.classic)
}
