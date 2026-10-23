package net.lapisphilosophorum.lapisnet.networking.dcutr

import java.time.Duration

/** Operator switch for TCP hole punching (DCUtR). See [HolePunchConfig.isActive]. */
enum class HolePunchMode {
    /** On exactly when the node is declared to be behind a NAT (`reachability=private`). */
    AUTO,

    /** On regardless of the declared reachability; a platform without `SO_REUSEPORT` aborts the start. */
    ON,

    /** No dcutr, no Identify, no reuse-port transport. */
    OFF,
    ;

    companion object {
        fun parse(raw: String): HolePunchMode? =
            when (raw.trim().lowercase()) {
                "auto" -> AUTO
                "on" -> ON
                "off" -> OFF
                else -> null
            }
    }
}

/**
 * Hole-punching limits. Every default is deliberately small: an attempt costs the peer at most two
 * outgoing dials, and the number of attempts, concurrent sessions and tracked peers is bounded.
 *
 * @property declaredPrivate set by the application from the operator's declared reachability; with
 *  [HolePunchMode.AUTO] it decides whether the feature is active
 * @property allowNonPublicAddresses test only (loopback punching). Programmatic, never an operator option.
 */
data class HolePunchConfig(
    val mode: HolePunchMode = HolePunchMode.AUTO,
    val declaredPrivate: Boolean = false,
    val maxAttemptsPerPeer: Int = 3,
    val backoffBase: Duration = Duration.ofSeconds(30),
    val backoffMax: Duration = Duration.ofMinutes(30),
    val protocolTimeout: Duration = Duration.ofSeconds(10),
    val punchTimeout: Duration = Duration.ofSeconds(5),
    val maxConcurrentUpgrades: Int = 4,
    val maxTrackedPeers: Int = 256,
    val relayCloseGrace: Duration = Duration.ofSeconds(10),
    val observedAddressThreshold: Int = 1,
    val maxResponderSessionsPerPeerPerWindow: Int = 3,
    val responderWindow: Duration = Duration.ofMinutes(10),
    val allowNonPublicAddresses: Boolean = false,
    /**
     * Wave V0.10.0-E: the node runs in anonymity mode. Hole punching (DCUtR) and the Identify responder reveal observed
     * and listen addresses, so they are forbidden here: only [HolePunchMode.OFF] is accepted. This guards the library
     * level too, not just the option parsing.
     */
    val anonymityMode: Boolean = false,
) {
    init {
        require(!anonymityMode || mode == HolePunchMode.OFF) {
            "hole punching and Identify are not allowed in anonymity mode"
        }
        require(maxAttemptsPerPeer > 0) { "maxAttemptsPerPeer must be positive" }
        require(!backoffBase.isNegative && !backoffBase.isZero) { "backoffBase must be positive" }
        require(backoffMax >= backoffBase) { "backoffMax must not be below backoffBase" }
        require(!protocolTimeout.isNegative && !protocolTimeout.isZero) { "protocolTimeout must be positive" }
        require(!punchTimeout.isNegative && !punchTimeout.isZero) { "punchTimeout must be positive" }
        require(maxConcurrentUpgrades > 0) { "maxConcurrentUpgrades must be positive" }
        require(maxTrackedPeers > 0) { "maxTrackedPeers must be positive" }
        require(!relayCloseGrace.isNegative) { "relayCloseGrace must not be negative" }
        require(observedAddressThreshold > 0) { "observedAddressThreshold must be positive" }
        require(maxResponderSessionsPerPeerPerWindow > 0) { "maxResponderSessionsPerPeerPerWindow must be positive" }
        require(!responderWindow.isNegative && !responderWindow.isZero) { "responderWindow must be positive" }
    }

    /** Whether the feature is requested at all (before the platform check). [reachabilityPrivate] is the node's own declaration. */
    fun isActive(reachabilityPrivate: Boolean): Boolean =
        when (mode) {
            HolePunchMode.ON -> true
            HolePunchMode.AUTO -> declaredPrivate || reachabilityPrivate
            HolePunchMode.OFF -> false
        }

    /** The Identify responder (needed on relays too, so a NAT'd peer can learn its observed address) runs unless OFF. */
    val answersIdentify: Boolean get() = mode != HolePunchMode.OFF

    companion object {
        /** The library default: off, so existing callers and tests are unaffected. Applications choose their own default. */
        val DISABLED = HolePunchConfig(mode = HolePunchMode.OFF)
    }
}
