package net.lapisphilosophorum.lapisnet.call

import java.net.Inet4Address
import java.net.InetAddress
import java.net.UnknownHostException

/** Thrown by [CallSdpPolicy.validateRemote] when a peer-supplied SDP fails any of its checks. [reason]
 * is the [CallEndReason] `CallManager` should report back to the peer for this specific rejection -
 * [CallEndReason.UNSUPPORTED_MEDIA] for a media-kind mismatch, [CallEndReason.MALFORMED_SIGNAL] for
 * every other structural/policy violation. */
class CallSdpRejectedException(
    message: String,
    val reason: CallEndReason = CallEndReason.MALFORMED_SIGNAL,
) : RuntimeException(message)

/**
 * Validates a remote peer's SDP BEFORE it is ever handed to `WebRtcCallMediaEngine`'s
 * `setRemoteDescription` - the WebRTC-specific analogue of this codebase's established SSRF/scan-
 * vector defenses (see CLAUDE.md's "Security-Audit-Prüfliste" - "SSRF: URL-Whitelist ..., Private-
 * Range-Blocklist").
 *
 * **Why this is a real attack surface, not paranoia.** The SDP arrives AEAD-authenticated (it
 * travelled inside the same Double Ratchet ciphertext as a text DM - see `docs/architecture.adoc`'s
 * "1:1 calls over WebRTC" section), so the sender's IDENTITY is proven. But a compromised or
 * malicious CONTACT (not a stranger - someone this node has an established session with) could still
 * hand-craft an SDP whose `a=candidate:` lines name addresses this node's ICE stack would then send
 * traffic toward - the WebRTC-specific shape of the SSRF/portscan class this codebase's own security
 * checklist already covers for every other network-touching feature. This node's OWN
 * `WebRtcCallMediaEngine` never gathers anything but `typ host` UDP candidates and never contacts a
 * STUN/TURN server (see that class's own doc comment on `PORTALLOCATOR_DISABLE_STUN`/`_RELAY`/
 * `_TCP`) - this policy makes the REMOTE side hold to the SAME `typ host`/UDP-only/no-STUN-or-TURN
 * shape, so accepting a call can never make this node dial out over TCP to an attacker-chosen
 * address, nor gather-and-contact a STUN/TURN server on the remote's say-so. **What this does NOT
 * close** (tracked, not yet fixed - see [validateCandidateLine]'s own inline comment): the candidate
 * ADDRESS and PORT of a `typ host` UDP line are otherwise unrestricted - any public-unicast address/
 * port is accepted - so a compromised contact can still steer this node's ICE stack to send a bounded
 * number (at most [MAX_CANDIDATES]) of UDP STUN binding requests toward a third party of its choosing;
 * this policy narrows that surface to UDP `typ host` only, it does not eliminate it.
 *
 * Every check below has its own adversarial test in `CallSdpPolicyTest` - this class doc comment
 * states the rules; that test file is the authoritative, executable version of "rejected".
 */
object CallSdpPolicy {
    const val MAX_SDP_LINES = 400
    const val MAX_CANDIDATES = 30

    /** Matches a dotted-quad IPv4 literal with every octet in `0..255` and no leading zeros
     * (`010` is octal-ambiguous, never emitted by a real ICE stack, and rejected rather than
     * guessed at). Deliberately a plain character-class regex, never [java.net.InetAddress
     * .getByName] - that method resolves a NON-literal argument via an actual DNS query, which for
     * an untrusted, peer-supplied candidate address is exactly the "online-presence leak to an
     * attacker-chosen name" [isIpLiteral]'s own doc comment exists to prevent. A regex can only
     * ever say "yes/no", never make a network call. */
    private val IPV4_LITERAL_REGEX =
        Regex("^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$")

    /** A deliberately permissive (RFC 4291 §2.2) IPv6-literal matcher covering every `::`-
     * compression shape and an embedded-IPv4 tail - see [isIpLiteral]'s own doc comment for why
     * over-accepting here is harmless (an over-accepted string still has to clear every
     * multicast/loopback/link-local check below) while under-accepting would wrongly reject a
     * legitimate LAN peer's real address. Not a general-purpose IPv6 validator - only a literal-
     * vs-hostname discriminator. */
    private val IPV6_LITERAL_REGEX =
        Regex(
            "^(" +
                "([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|" +
                "([0-9a-fA-F]{1,4}:){1,7}:|" +
                "([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|" +
                "([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|" +
                "([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|" +
                "([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|" +
                "([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|" +
                "[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|" +
                ":((:[0-9a-fA-F]{1,4}){1,7}|:)|" +
                "([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\\.){3}" +
                "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])|" +
                "::(ffff(:0{1,4})?:)?((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\\.){3}" +
                "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])" +
                ")$",
        )

    /** `true` iff [address] is a numeric IPv4 or IPv6 literal - never resolves anything, never
     * makes a network call (see [IPV4_LITERAL_REGEX]'s own doc comment). An IPv6 literal's
     * optional `%<zone>` suffix is stripped before matching - a zone index is a purely local
     * scoping label, never a hostname component.
     *
     * **Why this gate exists at all - restlücke closed 2026-09-02.** Every other check in
     * [validateCandidateLine] (multicast/loopback/link-local/`.local`) is a STRING-PREFIX/SUFFIX
     * test that silently assumes [address] is already a numeric literal - a candidate address that
     * is instead an ordinary hostname (`localhost`, `evil.example.com`, anything not ending in
     * `.local`) matches none of those prefixes/suffixes and previously sailed through unchecked.
     * `WebRtcCallMediaEngine`'s underlying libwebrtc treats an unresolved candidate host as a name
     * to be resolved via the platform's own DNS resolver at ICE-connectivity-check time - so an
     * attacker-controlled hostname here would both (a) trigger a DNS query this node never chose
     * to make (an online-presence leak to a third party the attacker names) and (b) potentially
     * resolve to loopback/a third party's address, exactly the SSRF/portscan shape this object's
     * own class doc comment says accepting a call must never enable. Rejecting anything that is not
     * already a numeric literal closes both at once, with zero network activity of its own. */
    private fun isIpLiteral(address: String): Boolean {
        val withoutZone = address.substringBefore('%')
        return IPV4_LITERAL_REGEX.matches(withoutZone) || IPV6_LITERAL_REGEX.matches(withoutZone)
    }

    /** Parses an address [isIpLiteral] has already confirmed is a numeric literal into a JDK
     * [java.net.InetAddress], so [validateCandidateLine] can ask the platform's own, byte-level
     * `isLoopbackAddress`/`isLinkLocalAddress`/`isMulticastAddress`/`isAnyLocalAddress` instead of
     * re-implementing them as string prefix/suffix checks on the address's ORIGINAL, un-normalized
     * text.
     *
     * **Why this does not reintroduce the DNS-leak/SSRF risk [isIpLiteral] itself exists to close**
     * (restlücke closed 2026-09-02, MEDIUM finding): [java.net.InetAddress.getByName] only performs
     * a DNS lookup when its argument is NOT already a recognized numeric literal - for a literal, the
     * JDK's own `sun.net.util.IPAddressUtil` textToNumericFormat fast path parses the bytes directly
     * and returns without ever touching a resolver, exactly the same "yes/no, never a network call"
     * guarantee [IPV4_LITERAL_REGEX]/[IPV6_LITERAL_REGEX] already give for the literal-vs-hostname
     * question. This function is only ever called AFTER [isIpLiteral] has already returned `true`
     * for the same string, so that fast path is the only one ever taken here.
     *
     * **Why this closes real, not just theoretical, bypasses**: the JDK normalizes equivalent
     * spellings of the same address before these checks run - `0000:0000:0000:0000:0000:0000:0000
     * :0001` and `::0:1` both parse to the same value as `::1`, and an IPv4-mapped IPv6 literal like
     * `::ffff:127.0.0.1` is returned as an [java.net.Inet4Address] for `127.0.0.1` (see that method's
     * own javadoc) - none of which the OLD prefix/suffix checks on the raw string ever recognized. */
    private fun normalizedLiteralAddress(address: String): InetAddress =
        InetAddress.getByName(address.substringBefore('%'))

    /** @throws CallSdpRejectedException if [sdp] fails any check. Never mutates or returns anything -
     * a pure gate, called purely for its potential exception. */
    fun validateRemote(
        sdp: String,
        expected: CallMediaKind,
    ) {
        require(expected == CallMediaKind.AUDIO) {
            "CallSdpPolicy only knows how to validate AUDIO - AUDIO_VIDEO is rejected upstream " +
                "by CallSignalCodec before this function is ever reached"
        }

        if (sdp.length > CallSignalCodec.MAX_SDP_BYTES) {
            throw CallSdpRejectedException("sdp exceeds ${CallSignalCodec.MAX_SDP_BYTES} bytes: ${sdp.length}")
        }
        if (!sdp.all { it.code in 0..127 }) {
            throw CallSdpRejectedException("sdp must be pure US-ASCII")
        }

        val lines = sdp.split("\r\n", "\n").filter { it.isNotEmpty() }
        if (lines.size > MAX_SDP_LINES) {
            throw CallSdpRejectedException("sdp has too many lines: ${lines.size} > $MAX_SDP_LINES")
        }

        validateExactlyOneAudioMediaSection(lines)
        validateDtlsFingerprintAndSetup(lines)
        validateCandidates(lines)
    }

    private fun validateExactlyOneAudioMediaSection(lines: List<String>) {
        val mediaLines = lines.filter { it.startsWith("m=") }
        if (mediaLines.size != 1) {
            throw CallSdpRejectedException("sdp must declare exactly one m= section, found ${mediaLines.size}")
        }
        val mediaType = mediaLines[0].removePrefix("m=").substringBefore(' ')
        when (mediaType) {
            "audio" -> Unit
            "video" ->
                throw CallSdpRejectedException(
                    "sdp declares an unsupported m=video section",
                    CallEndReason.UNSUPPORTED_MEDIA,
                )
            "application" ->
                // A DataChannel (SCTP) section would let an "audio call" carry an arbitrary
                // bidirectional data tunnel instead - see this object's own class doc comment on
                // why a call's media path must stay confined to exactly what it claims to be.
                throw CallSdpRejectedException(
                    "sdp declares an m=application (data channel) section - not a supported call shape",
                )
            else -> throw CallSdpRejectedException("sdp declares an unsupported m=$mediaType section")
        }
    }

    private fun validateDtlsFingerprintAndSetup(lines: List<String>) {
        val fingerprintLines = lines.filter { it.startsWith("a=fingerprint:") }
        if (fingerprintLines.size != 1) {
            throw CallSdpRejectedException(
                "sdp must declare exactly one a=fingerprint line, found ${fingerprintLines.size}",
            )
        }
        val fingerprintLine = fingerprintLines[0].removePrefix("a=fingerprint:")
        val parts = fingerprintLine.split(' ', limit = 2)
        if (parts.size != 2 || parts[0] != "sha-256") {
            throw CallSdpRejectedException("sdp fingerprint must use sha-256")
        }
        val hexGroups = parts[1].split(':')
        val validHex = hexGroups.size == 32 && hexGroups.all { it.length == 2 && it.all { c -> c.isHexDigit() } }
        if (!validHex) {
            throw CallSdpRejectedException("sdp fingerprint is not a valid 32-byte colon-separated hex string")
        }
        if (lines.none { it.startsWith("a=setup:") }) {
            throw CallSdpRejectedException("sdp is missing a required a=setup line")
        }
    }

    private fun Char.isHexDigit(): Boolean = this in '0'..'9' || this in 'a'..'f' || this in 'A'..'F'

    private fun validateCandidates(lines: List<String>) {
        val candidateLines = lines.filter { it.startsWith("a=candidate:") }
        if (candidateLines.size > MAX_CANDIDATES) {
            throw CallSdpRejectedException(
                "sdp declares too many ICE candidates: ${candidateLines.size} > $MAX_CANDIDATES",
            )
        }
        candidateLines.forEach(::validateCandidateLine)
    }

    /** One `a=candidate:<foundation> <component> <transport> <priority> <address> <port> typ
     * <type> ...` line, per RFC 5245 §15.1. */
    private fun validateCandidateLine(line: String) {
        val tokens = line.removePrefix("a=candidate:").trim().split(Regex("\\s+"))
        if (tokens.size < 6) {
            throw CallSdpRejectedException("malformed a=candidate line: too few fields")
        }
        val transport = tokens[2].lowercase()
        // MINOR review-round finding (2026-09-02): `tcp` used to be accepted here alongside `udp`,
        // which - combined with no restriction on the candidate PORT or on public-unicast addresses
        // below - contradicted this object's own class doc comment's claim that accepting a call
        // "can never turn this node into an unwitting STUN-request or connection-attempt proxy toward
        // a third party": an authenticated-but-compromised contact could hand-craft up to
        // MAX_CANDIDATES `a=candidate:... tcp ... <any address> <any port> typ host` lines, and
        // libwebrtc's default-enabled TCP-candidate connection attempts would then make THIS node
        // dial out to every one of them - a real, if bounded, port-scan/connect vector against third
        // parties. This wave gathers only Non-Trickle, `typ host` UDP candidates of its own (see
        // WebRtcCallMediaEngine's own PORTALLOCATOR_DISABLE_TCP flag) and has no use for TCP ICE at
        // all, so rejecting it on the remote side too closes the gap outright rather than merely
        // narrowing the doc claim.
        if (transport != "udp") {
            throw CallSdpRejectedException("candidate transport must be udp, was $transport")
        }
        val address = tokens[4]

        val typIndex = tokens.indexOf("typ")
        val candidateType = if (typIndex in 0 until tokens.lastIndex) tokens[typIndex + 1] else null
        if (candidateType != "host") {
            throw CallSdpRejectedException(
                "candidate type must be host (no srflx/prflx/relay this wave), was $candidateType",
            )
        }

        if (address.endsWith(".local", ignoreCase = true)) {
            throw CallSdpRejectedException("candidate address is an mDNS hostname, not a resolvable IP: $address")
        }
        // General hostname gate - see isIpLiteral's own doc comment for why this must run BEFORE
        // (and independently of) every address-space check below: those all assume a numeric
        // literal already, so without this gate ANY hostname not ending in ".local" (localhost,
        // an attacker-chosen DNS name, ...) would silently skip every one of them.
        if (!isIpLiteral(address)) {
            throw CallSdpRejectedException(
                "candidate address is not a numeric IP literal (hostname candidates are rejected): $address",
            )
        }
        // Unspecified/multicast/loopback/link-local, all checked on the JDK-NORMALIZED form of the
        // address rather than plain prefix/suffix tests against its raw, un-normalized text -
        // restlücke closed 2026-09-02 (MEDIUM finding): an equivalent but differently-spelled literal
        // - `0000:0000:0000:0000:0000:0000:0000:0001` or `::0:1` for `::1`, `::ffff:127.0.0.1` for
        // `127.0.0.1`, and so on for the 169.254.*/224-239.*/fe80::-fec0:: ranges - previously sailed
        // straight through every one of the string checks this block replaces, because none of them
        // recognized any spelling but the one each check's author happened to write. See
        // [normalizedLiteralAddress]'s own doc comment for why parsing here performs no DNS lookup:
        // [isIpLiteral] just above already proved this string is a literal, and the JDK's own literal
        // fast path is the only one [InetAddress.getByName] ever takes for one.
        val normalized =
            try {
                normalizedLiteralAddress(address)
            } catch (e: UnknownHostException) {
                // Should be unreachable - isIpLiteral() just confirmed this is a valid IPv4/IPv6
                // literal - but never let an internal parser disagreement escape as anything other
                // than the same rejection every other malformed-address case here produces.
                throw CallSdpRejectedException("candidate address could not be parsed as a literal: $address")
            }
        if (normalized.isAnyLocalAddress()) {
            throw CallSdpRejectedException("candidate address is unspecified: $address")
        }
        if (normalized.isMulticastAddress()) {
            throw CallSdpRejectedException("candidate address is multicast: $address")
        }
        // Loopback and link-local (APIPA/fe80::/10) are deliberately blocked here even though RFC
        // 1918/site-local addresses stay allowed (unlike MultiaddrHygiene's dial-time guard, RFC
        // 1918 IS this project's expected same-LAN call peer address space - see this object's own
        // class doc comment). Neither loopback nor link-local can ever be a REMOTE peer's own
        // reachable address: loopback always names "whichever machine is asking" - accepting it here
        // would make this node's ICE stack send a STUN binding request at ITSELF or, worse, at
        // whatever unrelated service a malicious contact knows is listening on localhost - and
        // link-local is scoped to a single, unrouted broadcast segment with no meaningful notion of
        // "the peer's own address" a remote SDP could legitimately claim.
        if (normalized.isLoopbackAddress()) {
            throw CallSdpRejectedException("candidate address is loopback: $address")
        }
        if (normalized.isLinkLocalAddress()) {
            throw CallSdpRejectedException("candidate address is link-local: $address")
        }
        // Broadcast, checked on the same JDK-NORMALIZED form as every range check above - restlücke
        // closed 2026-09-02 (MINOR finding): the previous version of this check compared the RAW,
        // un-normalized text against the literal string "255.255.255.255", which is exactly the class
        // of bypass the surrounding normalization work above (isAnyLocalAddress/isMulticastAddress/
        // isLoopbackAddress/isLinkLocalAddress) already closed for every OTHER address-space check -
        // `::ffff:255.255.255.255` and its fully-expanded form `0:0:0:0:0:ffff:ffff:ffff` are the
        // bit-identical address, but the JDK maps neither to `Inet4Address.getHostAddress() ==
        // "255.255.255.255"` as a STRING, so the raw comparison let both sail through. Checking the
        // limited-broadcast address by its actual BYTES (four 0xFF octets on the normalized
        // Inet4Address - `normalized.address` is 4 bytes for an Inet4Address, including the one an
        // IPv4-mapped IPv6 literal normalizes to, per InetAddress.getByName's own javadoc) closes
        // every spelling at once, the same way the byte-level checks above do.
        if (normalized is Inet4Address && normalized.address.all { it == 0xFF.toByte() }) {
            throw CallSdpRejectedException("candidate address is a broadcast address: $address")
        }
    }
}
