@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onionwire.path

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import java.net.InetAddress

class NetworkBucketTest :
    FunSpec({
        fun bucket(ip: String) = PeerDirectoryRelayNetworkLocator.bucketOf(InetAddress.getByName(ip))

        test("non-public ranges have no bucket") {
            listOf(
                "0.1.2.3",
                "192.0.2.5",
                "198.51.100.7",
                "203.0.113.9",
                "198.18.0.1",
                "198.19.255.1",
                "240.0.0.1",
                "255.255.255.255",
                "2001:db8::1",
                "10.0.0.1",
                "100.64.0.1",
                "fd00::1",
            ).forEach { bucket(it) shouldBe null }
        }

        test("public addresses keep their bucket") {
            bucket("8.8.8.8") shouldBe NetworkBucket.V4((8 shl 8) or 8)
            bucket("198.20.0.1") shouldBe NetworkBucket.V4((198 shl 8) or 20)
            (bucket("2001:4860::1") != null) shouldBe true
        }

        test("IPv6 buckets are the /48: same /48 equal, same /32 but different /48 differ") {
            bucket("2001:4860:1234:1::1") shouldBe NetworkBucket.V6(0x200148601234L)
            bucket("2001:4860:1234:ffff::9") shouldBe bucket("2001:4860:1234:1::1")
            (bucket("2001:4860:1235:1::1") != bucket("2001:4860:1234:1::1")) shouldBe true
            (bucket("2001:4861:1234:1::1") != bucket("2001:4860:1234:1::1")) shouldBe true
        }
    })
