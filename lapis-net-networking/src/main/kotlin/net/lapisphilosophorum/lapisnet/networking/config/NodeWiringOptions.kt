package net.lapisphilosophorum.lapisnet.networking.config

import net.lapisphilosophorum.lapisnet.networking.dcutr.HolePunchConfig
import net.lapisphilosophorum.lapisnet.networking.dcutr.HolePunchMode
import net.lapisphilosophorum.lapisnet.networking.relay.NodeReachability
import net.lapisphilosophorum.lapisnet.networking.relay.RelayConfig

/** How the operator declares the node's reachability from the outside. Never guessed, never inferred. */
enum class DeclaredReachability {
    PUBLIC,
    PRIVATE,
    UNDECLARED,
    ;

    /** [UNDECLARED] maps to [NodeReachability.UNSPECIFIED]. */
    fun toNodeReachability(): NodeReachability =
        when (this) {
            PUBLIC -> NodeReachability.PUBLIC
            PRIVATE -> NodeReachability.PRIVATE
            UNDECLARED -> NodeReachability.UNSPECIFIED
        }
}

/**
 * Wave V0.10.0-E: `--anonymity=on|off`. Only the exact lower-case words are accepted. EXPERIMENTAL and incomplete: in
 * [ON] the node publishes its directory presence through onion circuits, chooses paths with persistent guards and
 * carries direct messages, mail and call signals over circuits. Call media is NOT anonymised: calls are off unless
 * `--anonymity-allow-call-media=true`, in which case call media connects directly and reveals the IP address.
 */
enum class AnonymityMode {
    OFF,
    ON,
    ;

    companion object {
        fun parse(raw: String): AnonymityMode? =
            when (raw) {
                "on" -> ON
                "off" -> OFF
                else -> null
            }
    }
}

/**
 * Wave V0.10.0-H: `--anonymity-padding=standard|off`. Only the exact lower-case words are accepted. `standard` (the
 * default) pads message sizes to size classes, sends cover cells towards the guard and shapes outgoing cells into time
 * slices; `off` sends exactly what is needed, so an observer of the connection sees message sizes and timing. Without
 * effect (but valid) while `--anonymity=off`.
 */
enum class AnonymityPaddingMode(
    val wire: String,
) {
    STANDARD("standard"),
    OFF("off"),
    ;

    companion object {
        fun parse(raw: String): AnonymityPaddingMode? = entries.firstOrNull { it.wire == raw }
    }
}

/** Thrown for any invalid operator-supplied wiring value. Never swallowed into a default: the process must not start. */
class InvalidWiringOptionException(
    message: String,
) : IllegalArgumentException(message)

/**
 * The shared vocabulary by which the browser and the CLI switch the V0.9.x library features on
 * (automatic relay selection, DHT fallback, relay-reliability publishing). Lives in this module because
 * both entry points depend on it, mirroring [net.lapisphilosophorum.lapisnet.networking.BootstrapConfig].
 *
 * **Every value is validated and an invalid one aborts the start** - a typo must never silently fall back to
 * a default, because several of these switches change what the node reveals to the network.
 *
 * @property autoRelay the EFFECTIVE value (already resolved against [reachability])
 */
data class NodeWiringOptions(
    val reachability: DeclaredReachability = DeclaredReachability.UNDECLARED,
    val autoRelay: Boolean = false,
    val dhtFallback: Boolean = true,
    val publishRelayReliability: Boolean = false,
    val holePunching: HolePunchMode = HolePunchMode.AUTO,
    /**
     * V0.10.0-B: serve as an onion relay (`--onion-relay`). Off by default. Infrastructure only: no user traffic is
     * routed over circuits yet and nothing is anonymised. The switch is consumed by the CLI node; the browser ignores it.
     */
    val onionRelay: Boolean = false,
    /**
     * V0.10.0-E: anonymous directory publication over onion circuits (`--anonymity=on`). Experimental, off by default.
     * Excludes hole punching (forced off) and `--onion-relay` (the relay descriptor would bind identity and address).
     */
    val anonymity: AnonymityMode = AnonymityMode.OFF,
    /**
     * V0.10.0-G: allow calls in anonymity mode (`--anonymity-allow-call-media`). Only valid with `anonymity=on`.
     * Call media then connects directly and reveals the IP address to the other party and to network observers.
     */
    val anonymityAllowCallMedia: Boolean = false,
    /** V0.10.0-H: padding and timing protection in anonymity mode (`--anonymity-padding`). Without effect while anonymity is off. */
    val anonymityPadding: AnonymityPaddingMode = AnonymityPaddingMode.STANDARD,
) {
    /**
     * The [RelayConfig] to create the node with. [NodeReachability.PRIVATE] is set only when [autoRelay] is on:
     * with `reachability=private` but `auto-relay=false` the selector must stay off, and a PRIVATE config would
     * both let a later [net.lapisphilosophorum.lapisnet.networking.LapisNode.startAutoRelay] start it and impose the
     * `targetRelayCount <= maxReservations` check for nothing. The declared value is still kept in [reachability]
     * for the status panel.
     */
    fun relayConfig(base: RelayConfig = RelayConfig.CLIENT_ONLY): RelayConfig {
        val effective =
            when {
                autoRelay -> NodeReachability.PRIVATE
                reachability == DeclaredReachability.PUBLIC -> NodeReachability.PUBLIC
                else -> NodeReachability.UNSPECIFIED
            }
        return base.copy(reachability = effective)
    }

    /**
     * The hole-punching configuration for [net.lapisphilosophorum.lapisnet.networking.LapisNode.create]. With the
     * default `auto` it is active exactly when the operator declared `reachability=private`.
     */
    fun holePunchConfig(base: HolePunchConfig = HolePunchConfig()): HolePunchConfig =
        if (anonymity == AnonymityMode.ON) {
            // DCUtR and Identify reveal addresses: forced off, whatever the base says
            base.copy(mode = HolePunchMode.OFF, declaredPrivate = false, anonymityMode = true)
        } else {
            base.copy(mode = holePunching, declaredPrivate = reachability == DeclaredReachability.PRIVATE)
        }

    /** `true` when the operator declared `private` but did not switch auto-relay on (the library heuristic then sees UNSPECIFIED). */
    val declaredPrivateWithoutAutoRelay: Boolean
        get() = reachability == DeclaredReachability.PRIVATE && !autoRelay

    companion object {
        const val KEY_REACHABILITY = "reachability"
        const val KEY_AUTO_RELAY = "auto-relay"
        const val KEY_DHT_FALLBACK = "dht-fallback"
        const val KEY_PUBLISH_RELAY_RELIABILITY = "publish-relay-reliability"
        const val KEY_HOLE_PUNCHING = "hole-punching"
        const val KEY_ONION_RELAY = "onion-relay"
        const val KEY_ANONYMITY = "anonymity"
        const val KEY_ANONYMITY_ALLOW_CALL_MEDIA = "anonymity-allow-call-media"
        const val KEY_ANONYMITY_PADDING = "anonymity-padding"

        /** Environment variable prefix: `LAPISNET_REACHABILITY`, `LAPISNET_AUTO_RELAY`, ... */
        const val ENV_PREFIX = "LAPISNET_"

        val KNOWN_KEYS: Set<String> =
            setOf(
                KEY_REACHABILITY,
                KEY_AUTO_RELAY,
                KEY_DHT_FALLBACK,
                KEY_PUBLISH_RELAY_RELIABILITY,
                KEY_HOLE_PUNCHING,
                KEY_ONION_RELAY,
                KEY_ANONYMITY,
                KEY_ANONYMITY_ALLOW_CALL_MEDIA,
                KEY_ANONYMITY_PADDING,
            )

        /** The environment variable name of [key], e.g. `auto-relay` to `LAPISNET_AUTO_RELAY`. */
        fun envNameOf(key: String): String = ENV_PREFIX + key.uppercase().replace('-', '_')

        /**
         * Resolves canonical (kebab-case) keys to options.
         *
         * @throws InvalidWiringOptionException for an unknown key, an invalid value or an inconsistent combination
         */
        fun resolve(raw: Map<String, String>): NodeWiringOptions {
            validateValues(raw)
            val reachability =
                raw[KEY_REACHABILITY]?.let { parseReachability(it) } ?: DeclaredReachability.UNDECLARED
            val autoRelayExplicit = raw[KEY_AUTO_RELAY]?.let { parseBoolean(KEY_AUTO_RELAY, it) }
            if (autoRelayExplicit == true && reachability != DeclaredReachability.PRIVATE) {
                throw InvalidWiringOptionException("--auto-relay requires --reachability=private")
            }
            val autoRelay = autoRelayExplicit ?: (reachability == DeclaredReachability.PRIVATE)
            val dhtFallback = raw[KEY_DHT_FALLBACK]?.let { parseBoolean(KEY_DHT_FALLBACK, it) } ?: true
            val publish =
                raw[KEY_PUBLISH_RELAY_RELIABILITY]?.let { parseBoolean(KEY_PUBLISH_RELAY_RELIABILITY, it) } ?: false
            val holePunchingRaw = raw[KEY_HOLE_PUNCHING]?.let { parseHolePunching(it) }
            val onionRelay = raw[KEY_ONION_RELAY]?.let { parseBoolean(KEY_ONION_RELAY, it) } ?: false
            val anonymity = raw[KEY_ANONYMITY]?.let { parseAnonymity(it) } ?: AnonymityMode.OFF
            val allowCallMedia =
                raw[KEY_ANONYMITY_ALLOW_CALL_MEDIA]?.let { parseBoolean(KEY_ANONYMITY_ALLOW_CALL_MEDIA, it) } ?: false
            val anonymityPadding =
                raw[KEY_ANONYMITY_PADDING]?.let { parseAnonymityPadding(it) } ?: AnonymityPaddingMode.STANDARD
            if (allowCallMedia && anonymity != AnonymityMode.ON) {
                throw InvalidWiringOptionException("--anonymity-allow-call-media requires --anonymity=on")
            }
            if (anonymity == AnonymityMode.ON) {
                // an explicit auto/on is a conflict, never silently overridden; only a missing key resolves to off
                if (holePunchingRaw != null && holePunchingRaw != HolePunchMode.OFF) {
                    throw InvalidWiringOptionException("hole-punching cannot be enabled while anonymity=on")
                }
                if (onionRelay) {
                    throw InvalidWiringOptionException("onion-relay cannot be combined with anonymity=on")
                }
            }
            val holePunching =
                if (anonymity == AnonymityMode.ON) HolePunchMode.OFF else holePunchingRaw ?: HolePunchMode.AUTO
            return NodeWiringOptions(
                reachability,
                autoRelay,
                dhtFallback,
                publish,
                holePunching,
                onionRelay,
                anonymity,
                allowCallMedia,
                anonymityPadding,
            )
        }

        /**
         * Checks every key and value of ONE configuration source on its own (without the cross-option rules of
         * [resolve]), so that an invalid value is rejected even where a higher-priority source would override it.
         */
        fun validateValues(raw: Map<String, String>) {
            for ((key, value) in raw) {
                when (key) {
                    KEY_REACHABILITY -> parseReachability(value)
                    KEY_AUTO_RELAY,
                    KEY_DHT_FALLBACK,
                    KEY_PUBLISH_RELAY_RELIABILITY,
                    KEY_ONION_RELAY,
                    KEY_ANONYMITY_ALLOW_CALL_MEDIA,
                    ->
                        parseBoolean(key, value)
                    KEY_HOLE_PUNCHING -> parseHolePunching(value)
                    KEY_ANONYMITY -> parseAnonymity(value)
                    KEY_ANONYMITY_PADDING -> parseAnonymityPadding(value)
                    else -> throw InvalidWiringOptionException("unknown option --$key")
                }
            }
        }

        /** Reads the wiring options out of an environment map; absent variables are simply not set. */
        fun fromEnvironment(env: Map<String, String>): Map<String, String> =
            KNOWN_KEYS.mapNotNull { key -> env[envNameOf(key)]?.let { key to it } }.toMap()

        /**
         * Parses `--key=value` arguments. Anything else (a bare word, `--key` without a value, a repeated key)
         * is an error.
         */
        fun parseCliArgs(args: List<String>): Map<String, String> {
            val result = LinkedHashMap<String, String>()
            for (arg in args) {
                if (!arg.startsWith("--") || '=' !in arg) {
                    throw InvalidWiringOptionException("unexpected argument '$arg' (expected --key=value)")
                }
                val key = arg.substring(2, arg.indexOf('='))
                val value = arg.substring(arg.indexOf('=') + 1)
                if (key.isEmpty()) {
                    throw InvalidWiringOptionException(
                        "unexpected argument '$arg' (expected --key=value)",
                    )
                }
                if (key in result) throw InvalidWiringOptionException("duplicate option --$key")
                result[key] = value
            }
            return result
        }

        private fun parseReachability(raw: String): DeclaredReachability =
            when (raw.trim().lowercase()) {
                "public" -> DeclaredReachability.PUBLIC
                "private" -> DeclaredReachability.PRIVATE
                "undeclared" -> DeclaredReachability.UNDECLARED
                else -> throw InvalidWiringOptionException("--reachability must be public|private|undeclared")
            }

        private fun parseAnonymity(raw: String): AnonymityMode =
            AnonymityMode.parse(raw) ?: throw InvalidWiringOptionException("--anonymity must be on|off")

        private fun parseAnonymityPadding(raw: String): AnonymityPaddingMode =
            AnonymityPaddingMode.parse(raw)
                ?: throw InvalidWiringOptionException("--anonymity-padding must be standard|off")

        private fun parseHolePunching(raw: String): HolePunchMode =
            HolePunchMode.parse(raw) ?: throw InvalidWiringOptionException("--hole-punching must be auto|on|off")

        private fun parseBoolean(
            key: String,
            raw: String,
        ): Boolean =
            when (raw.trim().lowercase()) {
                "true" -> true
                "false" -> false
                else -> throw InvalidWiringOptionException("--$key must be true|false")
            }

        /** Operator-facing help for the shared options. */
        val HELP_TEXT: String =
            """
            |Shared node options (--key=value; defaults in brackets):
            |  --reachability=public|private|undeclared   [undeclared]
            |        How this node is reachable from the outside. Never guessed: declare it.
            |  --auto-relay=true|false                    [true if reachability=private, else false]
            |        Hold reservations with relay nodes picked from the peer directory (ranked by Madli).
            |        Requires --reachability=private. This node never becomes a relay server.
            |  --dht-fallback=true|false                  [true]
            |        Use the DHT as a fallback for peer records, prekeys and offline mail/DM pointers.
            |        METADATA: DHT lookups reveal query timing and key interest (inbox, prekey and directory
            |        keys) to the DHT peers asked. Disable with --dht-fallback=false.
            |  --hole-punching=auto|on|off                [auto]
            |        TCP hole punching (DCUtR): replace a relayed connection by a direct one. auto = only when
            |        --reachability=private. on = always (aborts the start where SO_REUSEPORT is missing, e.g.
            |        Windows). off = no hole punching and no Identify. Verified on loopback only. Uses a
            |        transport whose listener port other processes of the same OS user may share.
            |  --publish-relay-reliability=true|false     [false]
            |        Publish the relay reliability observed by this node as signed Madli vectors.
            |        Default off: older nodes reject v2 vectors as invalid and lower the gossip peer score of
            |        whoever forwards them.
            |  --onion-relay=true|false                   [false]
            |        Serve as an onion relay (infrastructure only). Creates a rotating onion key (kept
            |        encrypted with the keystore passphrase, in memory only without one), announces a signed
            |        relay descriptor (gossip, and the DHT value when --dht-fallback is on) and answers circuit
            |        CREATE/EXTEND cells. NO user traffic is routed over circuits yet and nothing is anonymised;
            |        the descriptor makes this node's identity and address publicly known as a relay.
            |  --anonymity=on|off   (experimental, default off) anonymises directory, direct messages, mail and call signals; call media is direct
            |        With on: the directory entry is published only through circuits (persistent guards, diverse
            |        paths), hole punching is switched off, and the start is refused together with
            |        --hole-punching=auto|on or --onion-relay=true.
            |  --anonymity-allow-call-media=true|false    [false]   (only with --anonymity=on)
            |        Allow calls in anonymity mode. Call media then connects directly and reveals your IP
            |        address to the other party and to network observers.
            |  --anonymity-padding=standard|off           [standard]   (only effective with --anonymity=on)
            |        standard: message sizes are padded to size classes, cover cells are sent towards the guard
            |        and outgoing cells leave in time slices of 50 ms. Costs a little traffic (about 21 MiB per
            |        day on average, at most about 84 MiB per day on your guard link) and up to 50 ms latency per
            |        send. off: no padding; an observer of your connection sees message sizes and timing.
            """.trimMargin()
    }
}
