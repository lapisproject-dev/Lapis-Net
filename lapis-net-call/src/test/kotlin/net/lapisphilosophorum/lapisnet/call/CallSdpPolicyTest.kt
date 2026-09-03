package net.lapisphilosophorum.lapisnet.call

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

/** A structurally realistic host-only audio offer, shaped like what `WebRtcCallMediaEngine` actually
 * produces (verified against the wave's own probe output) but hand-written here so this test suite
 * does not need a live native engine (gated separately in `WebRtcCallMediaEngineTest`). */
private fun validAudioSdp(
    candidateLines: String = "a=candidate:1 1 udp 2122260223 192.168.1.5 54321 typ host\r\n",
): String =
    "v=0\r\n" +
        "o=- 1 1 IN IP4 192.168.1.5\r\n" +
        "s=-\r\n" +
        "t=0 0\r\n" +
        "m=audio 54321 UDP/TLS/RTP/SAVPF 111\r\n" +
        "c=IN IP4 192.168.1.5\r\n" +
        "a=setup:actpass\r\n" +
        "a=fingerprint:sha-256 " +
        (1..32).joinToString(":") { "AB" } +
        "\r\n" +
        candidateLines

class CallSdpPolicyTest :
    FunSpec({
        test("a structurally valid host-only audio offer is accepted") {
            CallSdpPolicy.validateRemote(validAudioSdp(), CallMediaKind.AUDIO)
        }

        test("m=application (data channel) section is rejected") {
            val sdp =
                validAudioSdp().replace(
                    "m=audio 54321 UDP/TLS/RTP/SAVPF 111",
                    "m=application 54321 DTLS/SCTP 5000",
                )
            val e = shouldThrow<CallSdpRejectedException> { CallSdpPolicy.validateRemote(sdp, CallMediaKind.AUDIO) }
            e.reason shouldBe CallEndReason.MALFORMED_SIGNAL
        }

        test("m=video section is rejected with UNSUPPORTED_MEDIA") {
            val sdp =
                validAudioSdp().replace(
                    "m=audio 54321 UDP/TLS/RTP/SAVPF 111",
                    "m=video 54321 UDP/TLS/RTP/SAVPF 96",
                )
            val e = shouldThrow<CallSdpRejectedException> { CallSdpPolicy.validateRemote(sdp, CallMediaKind.AUDIO) }
            e.reason shouldBe CallEndReason.UNSUPPORTED_MEDIA
        }

        test("missing a=fingerprint is rejected") {
            val sdp = validAudioSdp().lineSequence().filterNot { it.startsWith("a=fingerprint:") }.joinToString("\r\n")
            shouldThrow<CallSdpRejectedException> { CallSdpPolicy.validateRemote(sdp, CallMediaKind.AUDIO) }
        }

        test("invalid (non-hex, wrong-length) a=fingerprint is rejected") {
            val sdp =
                validAudioSdp().lineSequence().joinToString("\r\n") { line ->
                    if (line.startsWith("a=fingerprint:")) "a=fingerprint:sha-256 not-a-real-fingerprint" else line
                }
            shouldThrow<CallSdpRejectedException> { CallSdpPolicy.validateRemote(sdp, CallMediaKind.AUDIO) }
        }

        test("more than MAX_CANDIDATES candidates is rejected") {
            val tooMany =
                (1..CallSdpPolicy.MAX_CANDIDATES + 1).joinToString("") { i ->
                    "a=candidate:$i 1 udp 2122260223 192.168.1.$i 5000$i typ host\r\n"
                }
            shouldThrow<CallSdpRejectedException> {
                CallSdpPolicy.validateRemote(
                    validAudioSdp(tooMany),
                    CallMediaKind.AUDIO,
                )
            }
        }

        // MINOR review-round finding (2026-09-02): tcp candidates used to be accepted alongside udp,
        // which - combined with no port/public-address restriction - contradicted this file's own
        // class doc comment's "can never turn this node into an unwitting STUN-request or
        // connection-attempt proxy toward a third party" claim (a compromised contact could otherwise
        // steer this node's ICE stack into outbound TCP connects against up to MAX_CANDIDATES
        // arbitrary host:port pairs). This wave has no use for TCP ICE at all - see
        // WebRtcCallMediaEngine's own PORTALLOCATOR_DISABLE_TCP flag for the symmetric local-side fix.
        test("candidate transport tcp is rejected - this wave is udp-only, both locally and remotely") {
            val sdp = validAudioSdp("a=candidate:1 1 tcp 2122260223 192.168.1.5 54321 typ host\r\n")
            shouldThrow<CallSdpRejectedException> { CallSdpPolicy.validateRemote(sdp, CallMediaKind.AUDIO) }
        }

        test("candidate transport is case-insensitive - TCP (uppercase) is rejected too") {
            val sdp = validAudioSdp("a=candidate:1 1 TCP 2122260223 192.168.1.5 54321 typ host\r\n")
            shouldThrow<CallSdpRejectedException> { CallSdpPolicy.validateRemote(sdp, CallMediaKind.AUDIO) }
        }

        test("candidate type srflx is rejected") {
            val sdp =
                validAudioSdp(
                    "a=candidate:1 1 udp 1686052607 203.0.113.9 54321 typ srflx raddr 192.168.1.5 rport 54321\r\n",
                )
            shouldThrow<CallSdpRejectedException> { CallSdpPolicy.validateRemote(sdp, CallMediaKind.AUDIO) }
        }

        test("candidate type relay is rejected") {
            val sdp =
                validAudioSdp(
                    "a=candidate:1 1 udp 41886719 198.51.100.1 3478 typ relay raddr 192.168.1.5 rport 54321\r\n",
                )
            shouldThrow<CallSdpRejectedException> { CallSdpPolicy.validateRemote(sdp, CallMediaKind.AUDIO) }
        }

        test("0.0.0.0 candidate address is rejected") {
            val sdp = validAudioSdp("a=candidate:1 1 udp 2122260223 0.0.0.0 54321 typ host\r\n")
            shouldThrow<CallSdpRejectedException> { CallSdpPolicy.validateRemote(sdp, CallMediaKind.AUDIO) }
        }

        test("IPv4 multicast candidate address is rejected") {
            val sdp = validAudioSdp("a=candidate:1 1 udp 2122260223 230.1.2.3 54321 typ host\r\n")
            shouldThrow<CallSdpRejectedException> { CallSdpPolicy.validateRemote(sdp, CallMediaKind.AUDIO) }
        }

        test(".local mDNS hostname candidate is rejected") {
            val sdp = validAudioSdp("a=candidate:1 1 udp 2122260223 8f3ecb92-1234.local 54321 typ host\r\n")
            shouldThrow<CallSdpRejectedException> { CallSdpPolicy.validateRemote(sdp, CallMediaKind.AUDIO) }
        }

        // Restlücke closed 2026-09-02: every check above the isIpLiteral gate is a string prefix/
        // suffix test that silently assumed the candidate address was already a numeric literal -
        // a plain hostname not ending in ".local" sailed through every one of them unchecked.

        test("a bare hostname (no dots) candidate address is rejected, not just .local names") {
            val sdp = validAudioSdp("a=candidate:1 1 udp 2122260223 localhost 54321 typ host\r\n")
            shouldThrow<CallSdpRejectedException> { CallSdpPolicy.validateRemote(sdp, CallMediaKind.AUDIO) }
        }

        test("an attacker-chosen DNS hostname candidate address is rejected without any resolution attempt") {
            val sdp = validAudioSdp("a=candidate:1 1 udp 2122260223 evil.example.com 54321 typ host\r\n")
            shouldThrow<CallSdpRejectedException> { CallSdpPolicy.validateRemote(sdp, CallMediaKind.AUDIO) }
        }

        test("a numeric-looking but out-of-range IPv4 candidate address is rejected as a non-literal") {
            val sdp = validAudioSdp("a=candidate:1 1 udp 2122260223 999.999.999.999 54321 typ host\r\n")
            shouldThrow<CallSdpRejectedException> { CallSdpPolicy.validateRemote(sdp, CallMediaKind.AUDIO) }
        }

        test("a valid global-unicast IPv6 candidate address stays accepted") {
            val sdp = validAudioSdp("a=candidate:1 1 udp 2122260223 2001:db8::42 54321 typ host\r\n")
            CallSdpPolicy.validateRemote(sdp, CallMediaKind.AUDIO)
        }

        test("more than MAX_SDP_LINES lines is rejected") {
            val padding = (1..CallSdpPolicy.MAX_SDP_LINES + 1).joinToString("\r\n") { "a=extra$it" }
            shouldThrow<CallSdpRejectedException> {
                CallSdpPolicy.validateRemote(
                    validAudioSdp() + padding,
                    CallMediaKind.AUDIO,
                )
            }
        }

        test("non-ASCII content is rejected") {
            shouldThrow<CallSdpRejectedException> {
                CallSdpPolicy.validateRemote(validAudioSdp() + "a=note:café\r\n", CallMediaKind.AUDIO)
            }
        }

        test("more than one m= section is rejected") {
            val sdp = validAudioSdp() + "m=audio 54322 UDP/TLS/RTP/SAVPF 111\r\n"
            shouldThrow<CallSdpRejectedException> { CallSdpPolicy.validateRemote(sdp, CallMediaKind.AUDIO) }
        }

        // Loopback/link-local as a REMOTE candidate address - never a legitimate peer address (see
        // CallSdpPolicy's own inline comment at these checks), unlike RFC 1918/site-local, which
        // stays allowed (covered by every "typ host" acceptance test above, e.g. 192.168.1.5).

        test("IPv4 loopback (127.0.0.1) candidate address is rejected") {
            val sdp = validAudioSdp("a=candidate:1 1 udp 2122260223 127.0.0.1 54321 typ host\r\n")
            shouldThrow<CallSdpRejectedException> { CallSdpPolicy.validateRemote(sdp, CallMediaKind.AUDIO) }
        }

        test("IPv4 loopback range (127.x.x.x, not just 127.0.0.1) candidate address is rejected") {
            val sdp = validAudioSdp("a=candidate:1 1 udp 2122260223 127.5.6.7 54321 typ host\r\n")
            shouldThrow<CallSdpRejectedException> { CallSdpPolicy.validateRemote(sdp, CallMediaKind.AUDIO) }
        }

        test("IPv6 loopback (::1) candidate address is rejected") {
            val sdp = validAudioSdp("a=candidate:1 1 udp 2122260223 ::1 54321 typ host\r\n")
            shouldThrow<CallSdpRejectedException> { CallSdpPolicy.validateRemote(sdp, CallMediaKind.AUDIO) }
        }

        test("IPv4 link-local/APIPA (169.254.x.x) candidate address is rejected") {
            val sdp = validAudioSdp("a=candidate:1 1 udp 2122260223 169.254.1.2 54321 typ host\r\n")
            shouldThrow<CallSdpRejectedException> { CallSdpPolicy.validateRemote(sdp, CallMediaKind.AUDIO) }
        }

        test("IPv6 link-local (fe80::/10) candidate address is rejected") {
            val sdp = validAudioSdp("a=candidate:1 1 udp 2122260223 fe80::1 54321 typ host\r\n")
            shouldThrow<CallSdpRejectedException> { CallSdpPolicy.validateRemote(sdp, CallMediaKind.AUDIO) }
        }

        test("RFC 1918 private-range candidate address stays accepted (LAN calls, not a leak vector)") {
            val sdp = validAudioSdp("a=candidate:1 1 udp 2122260223 10.0.0.42 54321 typ host\r\n")
            CallSdpPolicy.validateRemote(sdp, CallMediaKind.AUDIO)
        }

        // Restlücke closed 2026-09-02 (MEDIUM review finding): the loopback/link-local/multicast
        // checks above this comment used to be plain string prefix/suffix tests against the
        // candidate's UN-normalized text - every check below exercises an equivalent but
        // differently-spelled literal for the exact same address family/range as one of those tests
        // above, none of which the old string checks recognized.

        test("expanded IPv6 loopback (all-zeros-plus-1, no :: compression) candidate address is rejected") {
            val sdp =
                validAudioSdp(
                    "a=candidate:1 1 udp 2122260223 0000:0000:0000:0000:0000:0000:0000:0001 54321 typ host\r\n",
                )
            shouldThrow<CallSdpRejectedException> { CallSdpPolicy.validateRemote(sdp, CallMediaKind.AUDIO) }
        }

        test("partially-compressed IPv6 loopback (::0:1) candidate address is rejected") {
            val sdp = validAudioSdp("a=candidate:1 1 udp 2122260223 ::0:1 54321 typ host\r\n")
            shouldThrow<CallSdpRejectedException> { CallSdpPolicy.validateRemote(sdp, CallMediaKind.AUDIO) }
        }

        test("IPv4-mapped IPv6 loopback (::ffff:127.0.0.1) candidate address is rejected") {
            val sdp = validAudioSdp("a=candidate:1 1 udp 2122260223 ::ffff:127.0.0.1 54321 typ host\r\n")
            shouldThrow<CallSdpRejectedException> { CallSdpPolicy.validateRemote(sdp, CallMediaKind.AUDIO) }
        }

        test("IPv4-mapped IPv6 link-local (::ffff:169.254.1.1) candidate address is rejected") {
            val sdp = validAudioSdp("a=candidate:1 1 udp 2122260223 ::ffff:169.254.1.1 54321 typ host\r\n")
            shouldThrow<CallSdpRejectedException> { CallSdpPolicy.validateRemote(sdp, CallMediaKind.AUDIO) }
        }

        test("IPv4-mapped IPv6 multicast (::ffff:224.0.0.1) candidate address is rejected") {
            val sdp = validAudioSdp("a=candidate:1 1 udp 2122260223 ::ffff:224.0.0.1 54321 typ host\r\n")
            shouldThrow<CallSdpRejectedException> { CallSdpPolicy.validateRemote(sdp, CallMediaKind.AUDIO) }
        }

        // Restlücke closed 2026-09-02 (MINOR review finding): the broadcast check used to compare the
        // candidate's RAW text against the literal string "255.255.255.255" - the one address-space
        // check in this file that was never migrated to the normalized-InetAddress form the checks
        // above already use, and so remained bypassable by an equivalent but differently-spelled
        // literal exactly like every one of those did before their own fix.

        test("plain broadcast (255.255.255.255) candidate address is rejected") {
            val sdp = validAudioSdp("a=candidate:1 1 udp 2122260223 255.255.255.255 54321 typ host\r\n")
            shouldThrow<CallSdpRejectedException> { CallSdpPolicy.validateRemote(sdp, CallMediaKind.AUDIO) }
        }

        test("IPv4-mapped IPv6 broadcast (::ffff:255.255.255.255) candidate address is rejected") {
            val sdp = validAudioSdp("a=candidate:1 1 udp 2122260223 ::ffff:255.255.255.255 54321 typ host\r\n")
            shouldThrow<CallSdpRejectedException> { CallSdpPolicy.validateRemote(sdp, CallMediaKind.AUDIO) }
        }

        test("fully-expanded IPv4-mapped IPv6 broadcast (0:0:0:0:0:ffff:ffff:ffff) candidate address is rejected") {
            val sdp = validAudioSdp("a=candidate:1 1 udp 2122260223 0:0:0:0:0:ffff:ffff:ffff 54321 typ host\r\n")
            shouldThrow<CallSdpRejectedException> { CallSdpPolicy.validateRemote(sdp, CallMediaKind.AUDIO) }
        }
    })
