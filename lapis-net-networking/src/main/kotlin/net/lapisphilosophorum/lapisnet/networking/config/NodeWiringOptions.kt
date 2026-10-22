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
        base.copy(mode = holePunching, declaredPrivate = reachability == DeclaredReachability.PRIVATE)

    /** `true` when the operator declared `private` but did not switch auto-relay on (the library heuristic then sees UNSPECIFIED). */
    val declaredPrivateWithoutAutoRelay: Boolean
        get() = reachability == DeclaredReachability.PRIVATE && !autoRelay

    companion object {
        const val KEY_REACHABILITY = "reachability"
        const val KEY_AUTO_RELAY = "auto-relay"
        const val KEY_DHT_FALLBACK = "dht-fallback"
        const val KEY_PUBLISH_RELAY_RELIABILITY = "publish-relay-reliability"
        const val KEY_HOLE_PUNCHING = "hole-punching"

        /** Environment variable prefix: `LAPISNET_REACHABILITY`, `LAPISNET_AUTO_RELAY`, ... */
        const val ENV_PREFIX = "LAPISNET_"

        val KNOWN_KEYS: Set<String> =
            setOf(KEY_REACHABILITY, KEY_AUTO_RELAY, KEY_DHT_FALLBACK, KEY_PUBLISH_RELAY_RELIABILITY, KEY_HOLE_PUNCHING)

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
            val holePunching = raw[KEY_HOLE_PUNCHING]?.let { parseHolePunching(it) } ?: HolePunchMode.AUTO
            return NodeWiringOptions(reachability, autoRelay, dhtFallback, publish, holePunching)
        }

        /**
         * Checks every key and value of ONE configuration source on its own (without the cross-option rules of
         * [resolve]), so that an invalid value is rejected even where a higher-priority source would override it.
         */
        fun validateValues(raw: Map<String, String>) {
            for ((key, value) in raw) {
                when (key) {
                    KEY_REACHABILITY -> parseReachability(value)
                    KEY_AUTO_RELAY, KEY_DHT_FALLBACK, KEY_PUBLISH_RELAY_RELIABILITY -> parseBoolean(key, value)
                    KEY_HOLE_PUNCHING -> parseHolePunching(value)
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
            """.trimMargin()
    }
}
