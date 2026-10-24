package net.lapisphilosophorum.lapisnet.call

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

private fun sdp(vararg candidates: String): String =
    "v=0\r\no=- 1 1 IN IP4 10.0.0.9\r\ns=-\r\nt=0 0\r\nm=audio 54321 UDP/TLS/RTP/SAVPF 111\r\n" +
        "c=IN IP4 10.0.0.9\r\na=rtcp:54321 IN IP4 10.0.0.9\r\na=setup:actpass\r\n" +
        "a=fingerprint:sha-256 " + (1..32).joinToString(":") { "AB" } + "\r\n" +
        candidates.joinToString("") { "$it\r\n" }

private fun cand(
    address: String,
    component: Int = 1,
    transport: String = "udp",
    type: String = "host",
    foundation: Int = 1,
): String = "a=candidate:$foundation $component $transport 2122260223 $address 54321 typ $type"

class CallSdpExposureFilterTest :
    FunSpec({
        val dropped =
            listOf(
                "10.1.2.3",
                "172.16.0.5",
                "192.168.1.5",
                "127.0.0.1",
                "169.254.1.1",
                "0.0.0.0",
                "224.0.0.1",
                "100.64.1.1",
                "100.127.255.1",
                "fc00::1",
                "fd12:3456::1",
                "fe80::1",
                "::1",
                "::ffff:198.51.100.7",
                "abcd.local",
            )

        test("non-public candidates are dropped, a public one is kept") {
            for (a in dropped) {
                val out = CallSdpExposureFilter.filterLocal(sdp(cand(a)))
                out.contains("a=candidate") shouldBe false
            }
            val kept = CallSdpExposureFilter.filterLocal(sdp(cand("198.51.100.7")))
            kept.contains("198.51.100.7") shouldBe true
        }

        test("only udp host candidates survive") {
            CallSdpExposureFilter
                .filterRemote(
                    sdp(cand("198.51.100.7", transport = "tcp")),
                ).contains("a=candidate") shouldBe
                false
            CallSdpExposureFilter
                .filterRemote(
                    sdp(cand("198.51.100.7", type = "srflx")),
                ).contains("a=candidate") shouldBe
                false
        }

        test("at most one candidate per component, IPv4 before IPv6") {
            val out =
                CallSdpExposureFilter.filterLocal(
                    sdp(
                        cand("2001:db8::7", foundation = 1),
                        cand("198.51.100.7", foundation = 2),
                        cand("203.0.113.9", foundation = 3),
                        cand("2001:db8::8", component = 2, foundation = 4),
                    ),
                )
            out.lines().count { it.startsWith("a=candidate") } shouldBe 2
            out.contains("198.51.100.7") shouldBe true
            out.contains("203.0.113.9") shouldBe false
            out.contains("2001:db8::7") shouldBe false
            out.contains("2001:db8::8") shouldBe true
        }

        test("c=, a=rtcp: and o= addresses are rewritten to the placeholder") {
            val out = CallSdpExposureFilter.filterLocal(sdp(cand("198.51.100.7")))
            out.contains("10.0.0.9") shouldBe false
            out.contains("c=IN IP4 0.0.0.0") shouldBe true
            out.contains("a=rtcp:9 IN IP4 0.0.0.0") shouldBe true
            out.contains("o=- 1 1 IN IP4 0.0.0.0") shouldBe true
        }

        test("zero remaining candidates is allowed and the result still passes the remote policy") {
            val out = CallSdpExposureFilter.filterLocal(sdp(cand("192.168.1.5")))
            CallSdpPolicy.validateRemote(out, CallMediaKind.AUDIO)
            val withCandidate =
                CallSdpExposureFilter.filterLocal(
                    sdp(cand("192.168.1.5"), cand("198.51.100.7", foundation = 2)),
                )
            CallSdpPolicy.validateRemote(withCandidate, CallMediaKind.AUDIO)
        }

        test("malformed and hostile candidate lines are dropped without throwing") {
            val out =
                CallSdpExposureFilter.filterRemote(
                    sdp(
                        "a=candidate:x",
                        "a=candidate:1 1 udp 1 evil.example.com 1 typ host",
                        "a=candidate:1 1 udp 1 999.1.1.1 1 typ host",
                    ),
                )
            out.contains("a=candidate") shouldBe false
            out.contains("evil.example.com") shouldBe false
        }
    })
