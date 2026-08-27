package net.lapisphilosophorum.lapisnet.dm

import io.libp2p.core.multiformats.Multiaddr
import io.libp2p.core.multiformats.Protocol
import java.net.InetAddress
import java.net.UnknownHostException

/**
 * SSRF-style hygiene guard for automatically-dialed, gossip-supplied [Multiaddr]s - security audit
 * round 1 finding (2026-08-2x): [MailboxPoller.attemptOne] resolves and dials a
 * [net.lapisphilosophorum.lapisnet.directory.PeerRecord]'s addresses for whatever sender identity a
 * signed [MailboxPointer] NAMES - an attacker-chosen value, since anyone can mint a throwaway
 * identity, publish a [net.lapisphilosophorum.lapisnet.directory.PeerRecord] for it naming ARBITRARY
 * addresses, and sign a mailbox pointer claiming to be that sender - with NO local user involvement
 * at all, on a timer. This is the first place in the codebase that automatically dials gossip-
 * supplied addresses with no local intent behind the dial at all - see [MailboxPoller.attemptOne]'s
 * own doc comment for the full "reflection/internal-probe primitive" analysis this closes.
 *
 * **Deliberately narrower than a textbook SSRF blocklist (RFC 1918 / loopback / APIPA / `::1`) -
 * a scoped, documented judgment call, not the full standing checklist applied blindly.** This
 * codebase's OWN documented networking model (`DmSessionManager`'s own class doc comment: "no
 * working NAT traversal... this wave supports only DIRECT-DIALABLE peers - same-LAN, or otherwise
 * directly reachable") makes loopback and RFC 1918/site-local addresses the PRIMARY, EXPECTED peer
 * address space for this entire project, not an anomaly - every two-node test in this module dials
 * `127.0.0.1` by construction (`LapisNode`'s own `DEFAULT_LISTEN_ADDRESS`), and a real same-LAN
 * deployment dials `192.168.x.x`/`10.x.x.x` the exact same way. Blocking either here would not
 * merely be conservative, it would make `MailboxPoller` unable to fetch ANYTHING in this project's
 * only currently-supported deployment shape - a strictly worse regression than the vulnerability
 * being closed, and inconsistent with `DmSessionManager.send`/`DmProtocol.dial` already dialing the
 * SAME `PeerDirectoryGossip`-resolved, equally attacker-forgeable addresses with zero filtering
 * (the "trust gossiped multiaddrs" model this class's own doc comment already attributes to V0.8.1,
 * unchanged by this fix). What IS blocked - `isAnyLocalAddress` (wildcard `0.0.0.0`/`::`, never a
 * real peer's own reachable address in ANY deployment shape, and a documented cross-platform
 * footgun where dialing it can silently resolve to loopback) and `isMulticastAddress` (never a
 * legitimate unicast Bitswap peer target either) - has no legitimate use as a dial target under
 * ANY of this project's supported models, so filtering it costs nothing while still closing the
 * cheapest, most nonsensical shape of "attacker names an address this node should never touch."
 * The broader DoS/blast-radius concern (an attacker directing large volumes of automated dials
 * anywhere at all) is what [MailboxPoller.POLL_PASS_WALL_CLOCK_BUDGET]/
 * [MailboxPoller.MAX_FETCH_ATTEMPTS_PER_SENDER_PER_PASS] bound instead - see that class's own doc
 * comment.
 *
 * **Only inspects the numeric `ip4`/`ip6` component of a [Multiaddr], never resolves anything.** A
 * `dns4`/`dns6`/`dnsaddr` component is intentionally left unfiltered here - resolving it would
 * itself be a network call inside a "should this be dialed" decision (exactly the kind of hazard
 * this guard exists to bound), and libp2p's own dialer resolves DNS components later, at actual
 * dial time, not before. Deliberately conservative: an address this function cannot classify as
 * `ip4`/`ip6` is allowed through unfiltered, mirroring [InetAddress.getByName]'s own numeric-only
 * fast path (no network call: an `ip4`/`ip6` multiaddr component's string form is always already a
 * literal numeric address, never a hostname).
 */
internal object MultiaddrHygiene {
    /**
     * `true` iff [address] carries an `ip4`/`ip6` component that resolves (purely locally - see
     * this object's own class doc comment) to a wildcard/any-local or multicast address - see this
     * object's own class doc comment for why loopback/site-local/link-local are deliberately NOT
     * included here. An address with no `ip4`/`ip6` component at all (e.g. `dns4` alone, or a
     * structurally odd address this codebase's own [io.libp2p] dependency would reject at dial time
     * anyway) is NOT blocked here - `false`.
     */
    fun isBlockedPrivateOrLocal(address: Multiaddr): Boolean {
        val ipComponent = address.filterComponents(Protocol.IP4, Protocol.IP6).firstOrNull() ?: return false
        val inet =
            try {
                InetAddress.getByName(ipComponent.stringValue)
            } catch (e: UnknownHostException) {
                // Should not happen for a numeric ip4/ip6 component's own string form - fail open
                // (allow through) rather than let a malformed component crash the poll pass; the
                // underlying dial attempt below still has its own DEFAULT_TIMEOUT bound regardless.
                return false
            }
        return inet.isAnyLocalAddress || inet.isMulticastAddress
    }
}
