package net.lapisphilosophorum.lapisnet.browser

import net.lapisphilosophorum.lapisnet.dm.DmAcceptancePolicy
import net.lapisphilosophorum.lapisnet.networking.config.InvalidWiringOptionException
import net.lapisphilosophorum.lapisnet.networking.config.NodeWiringOptions
import net.lapisphilosophorum.lapisnet.policy.AcceptanceGate
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.util.Properties

/**
 * Which DM/call acceptance gates the operator switched on (V0.9.15). **All off by default** (accept-all): with the
 * gates on by default an empty trust graph would silently block every stranger, including a legitimate first
 * contact. [AcceptanceGate]s combine with OR semantics (a sender passing any one is accepted), see
 * [net.lapisphilosophorum.lapisnet.policy.AcceptanceGateEvaluator].
 */
data class DmAcceptanceSettings(
    val veritasGate: Boolean = false,
    /** `null` = no Karma gate. Validated: finite and `>= 0`. */
    val karmaMinScore: Double? = null,
    /** Validated `>= 1`. The Lightning-deposit bypass floor of the policy. */
    val minDepositMsat: Long = DmAcceptancePolicy.DM_DEFAULT_MIN_DEPOSIT_MSAT,
) {
    init {
        require(karmaMinScore == null || (karmaMinScore.isFinite() && karmaMinScore >= 0.0)) {
            "karmaMinScore must be finite and >= 0"
        }
        require(minDepositMsat >= 1) { "minDepositMsat must be >= 1" }
    }

    fun gates(): List<AcceptanceGate> =
        buildList {
            if (veritasGate) add(AcceptanceGate.VeritasPath)
            karmaMinScore?.let { add(AcceptanceGate.KarmaThreshold(it)) }
        }

    val enabled: Boolean get() = gates().isNotEmpty()
}

/** The complete operator configuration of one browser process: shared wiring options plus acceptance gates. */
data class BrowserConfig(
    val wiring: NodeWiringOptions = NodeWiringOptions(),
    val acceptance: DmAcceptanceSettings = DmAcceptanceSettings(),
) {
    companion object {
        val DEFAULT = BrowserConfig()

        /** Name of the optional properties file inside `LAPISNET_HOME`. */
        const val FILE_NAME = "browser.properties"

        /** Hard cap on the file size: the file is operator-written and tiny. */
        const val MAX_FILE_BYTES = 64 * 1024L

        private const val KEY_VERITAS_GATE = "dm-veritas-gate"
        private const val KEY_KARMA_MIN = "dm-karma-min-score"
        private const val KEY_MIN_DEPOSIT = "dm-min-deposit-msat"
        private val ACCEPTANCE_KEYS = setOf(KEY_VERITAS_GATE, KEY_KARMA_MIN, KEY_MIN_DEPOSIT)

        /** File key (camelCase) to canonical key. */
        private val FILE_KEYS =
            mapOf(
                "reachability" to NodeWiringOptions.KEY_REACHABILITY,
                "autoRelay" to NodeWiringOptions.KEY_AUTO_RELAY,
                "dhtFallback" to NodeWiringOptions.KEY_DHT_FALLBACK,
                "publishRelayReliability" to NodeWiringOptions.KEY_PUBLISH_RELAY_RELIABILITY,
                "dmAcceptance.veritasGate" to KEY_VERITAS_GATE,
                "dmAcceptance.karmaMinScore" to KEY_KARMA_MIN,
                "dmAcceptance.minDepositMsat" to KEY_MIN_DEPOSIT,
            )

        /** The Lapis Net home directory: `$LAPISNET_HOME`, else `~/.lapisnet`. */
        fun defaultHome(env: Map<String, String> = System.getenv()): Path =
            Path.of(env["LAPISNET_HOME"] ?: (System.getProperty("user.home") + "/.lapisnet"))

        /**
         * Precedence: command-line arguments, then `LAPISNET_*` environment variables, then
         * `$home/browser.properties`, then the defaults. **An invalid value in ANY source aborts**, even where a
         * higher-priority source would have overridden it.
         *
         * @throws InvalidWiringOptionException on any invalid, unknown or inconsistent setting, or an unreadable file
         */
        fun load(
            args: List<String>,
            env: Map<String, String> = System.getenv(),
            home: Path = defaultHome(env),
        ): BrowserConfig {
            val fromFile = readFile(home.resolve(FILE_NAME))
            val fromEnv = readEnv(env)
            val fromArgs = NodeWiringOptions.parseCliArgs(args)
            val merged = LinkedHashMap<String, String>()
            for (layer in listOf(fromFile, fromEnv, fromArgs)) {
                validateLayer(layer)
                merged.putAll(layer)
            }
            val wiring = NodeWiringOptions.resolve(merged.filterKeys { it in NodeWiringOptions.KNOWN_KEYS })
            return BrowserConfig(wiring, resolveAcceptance(merged))
        }

        private fun validateLayer(layer: Map<String, String>) {
            NodeWiringOptions.validateValues(layer.filterKeys { it in NodeWiringOptions.KNOWN_KEYS })
            for (key in layer.keys) {
                if (key !in NodeWiringOptions.KNOWN_KEYS && key !in ACCEPTANCE_KEYS) {
                    throw InvalidWiringOptionException("unknown option --$key")
                }
            }
            resolveAcceptance(layer)
        }

        private fun resolveAcceptance(raw: Map<String, String>): DmAcceptanceSettings {
            val veritas = raw[KEY_VERITAS_GATE]?.let { parseBoolean(KEY_VERITAS_GATE, it) } ?: false
            val karma = raw[KEY_KARMA_MIN]?.let { parseKarma(it) }
            val deposit =
                raw[KEY_MIN_DEPOSIT]?.let { parseDeposit(it) } ?: DmAcceptancePolicy.DM_DEFAULT_MIN_DEPOSIT_MSAT
            return DmAcceptanceSettings(veritas, karma, deposit)
        }

        private fun parseBoolean(
            key: String,
            raw: String,
        ): Boolean =
            when (raw.trim().lowercase()) {
                "true" -> true
                "false" -> false
                else -> throw InvalidWiringOptionException("--$key must be true|false")
            }

        private fun parseKarma(raw: String): Double {
            val value =
                raw.trim().toDoubleOrNull()
                    ?: throw InvalidWiringOptionException("--$KEY_KARMA_MIN must be a number")
            if (!value.isFinite() || value < 0.0) {
                throw InvalidWiringOptionException("--$KEY_KARMA_MIN must be finite and >= 0")
            }
            return value
        }

        private fun parseDeposit(raw: String): Long {
            val value =
                raw.trim().toLongOrNull()
                    ?: throw InvalidWiringOptionException("--$KEY_MIN_DEPOSIT must be an integer")
            if (value < 1) throw InvalidWiringOptionException("--$KEY_MIN_DEPOSIT must be >= 1")
            return value
        }

        private fun readEnv(env: Map<String, String>): Map<String, String> {
            val result = LinkedHashMap(NodeWiringOptions.fromEnvironment(env))
            for (key in ACCEPTANCE_KEYS) {
                env[NodeWiringOptions.envNameOf(key)]?.let { result[key] = it }
            }
            return result
        }

        private fun readFile(path: Path): Map<String, String> {
            if (!Files.exists(path)) return emptyMap()
            val properties = Properties()
            val size =
                try {
                    Files.size(path)
                } catch (e: IOException) {
                    throw InvalidWiringOptionException("$FILE_NAME is not readable")
                }
            if (size > MAX_FILE_BYTES) {
                throw InvalidWiringOptionException("$FILE_NAME is larger than $MAX_FILE_BYTES bytes")
            }
            try {
                Files.newInputStream(path).use { properties.load(it) }
            } catch (e: IOException) {
                throw InvalidWiringOptionException("$FILE_NAME is not readable")
            } catch (e: IllegalArgumentException) {
                throw InvalidWiringOptionException("$FILE_NAME is malformed")
            }
            val result = LinkedHashMap<String, String>()
            for (name in properties.stringPropertyNames()) {
                val canonical =
                    FILE_KEYS[name] ?: throw InvalidWiringOptionException("unknown key '$name' in $FILE_NAME")
                result[canonical] = properties.getProperty(name)
            }
            return result
        }

        /** Help text for the browser-specific settings. */
        val HELP_TEXT: String =
            """
            |Browser settings (same keys as command-line options, environment variables and $FILE_NAME):
            |  --dm-veritas-gate=true|false      [false]   file key dmAcceptance.veritasGate
            |  --dm-karma-min-score=<number>     [off]     file key dmAcceptance.karmaMinScore (finite, >= 0)
            |  --dm-min-deposit-msat=<integer>   [1000000] file key dmAcceptance.minDepositMsat (>= 1)
            |Acceptance gates are off by default (everybody is accepted). With a gate on, a sender who passes
            |none of them is quarantined (DM) or silently blocked (call). Priority: arguments, environment
            |(LAPISNET_*), ${'$'}LAPISNET_HOME/$FILE_NAME, defaults. An invalid value aborts the start.
            """.trimMargin()
    }
}
