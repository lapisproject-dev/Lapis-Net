package net.lapisphilosophorum.lapisnet.networking

import io.libp2p.core.Connection
import io.libp2p.core.PeerInfo
import java.io.File
import java.time.Duration
import java.time.Instant

// Helpers shared by the three real-node relay specs (MultiNodeCircuitRelayTest,
// MultiNodeCircuitStallTest, MultiNodeRelayConnectionReuseTest). They only wait and describe; none of
// them retries anything or relaxes what a test asserts.

/** Whether [condition] held before [timeout] elapsed (polled every 20 ms, checked once more at the end). */
internal fun awaitTrue(
    timeout: Duration,
    condition: () -> Boolean,
): Boolean {
    val deadline = Instant.now().plus(timeout)
    while (Instant.now().isBefore(deadline)) {
        if (condition()) return true
        Thread.sleep(20)
    }
    return condition()
}

/** Whether [condition] held continuously for [stableFor] before [timeout] elapsed. */
internal fun awaitStably(
    timeout: Duration,
    stableFor: Duration,
    condition: () -> Boolean,
): Boolean {
    val deadline = Instant.now().plus(timeout)
    var since: Instant? = null
    while (Instant.now().isBefore(deadline)) {
        if (condition()) {
            val start = since ?: Instant.now().also { since = it }
            if (!Instant.now().isBefore(start.plus(stableFor))) return true
        } else {
            since = null
        }
        Thread.sleep(20)
    }
    return false
}

/**
 * The messages of [error] and of every cause, joined. [LapisNode.connect] wraps the underlying
 * failure, and the interesting detail (the relay's refusal status) lives in the cause chain rather
 * than in the top-level message.
 */
internal fun causeChain(error: Throwable): String =
    generateSequence(error) { it.cause }.mapNotNull { it.message }.joinToString(" | ")

/** The exception classes of [error] and of every cause, outermost first. */
internal fun causeClasses(error: Throwable): String =
    generateSequence(error) { it.cause }.joinToString(" <- ") { it::class.java.simpleName }

/**
 * Diagnostic channel, **off unless** the test JVM was started with `-PlapisDiag=true` (which sets the
 * `lapis.diag.logdir` system property, see this module's build file): appends one timestamped line to
 * `<logdir>/diag.log`. Costs nothing otherwise.
 */
internal fun diag(message: () -> String) {
    val dir = System.getProperty("lapis.diag.logdir") ?: return
    runCatching {
        File(dir, "diag.log").appendText("${Instant.now()} [${Thread.currentThread().name}] ${message()}\n")
    }
}

/** A thread dump restricted to the threads that matter for the relay specs, for the diagnostic log. */
private fun relayThreadDump(): String =
    Thread
        .getAllStackTraces()
        .filterKeys { Regex("nioEventLoop|lapis-relay-control|kotest|Test worker").containsMatchIn(it.name) }
        .entries
        .joinToString("\n") { (thread, frames) ->
            "  ${thread.name} (${thread.state})\n" + frames.take(12).joinToString("\n") { "      at $it" }
        }

/** What the relay [relay] looks like right now - attached to every failure so it can be read off a CI log. */
private fun relayState(relay: LapisNode?): String =
    if (relay == null) {
        "relay: n/a"
    } else {
        "relay: pausedLegs=${relay.relayFlowStats.pausedLegs()}, " +
            "stallClosures=${relay.relayFlowStats.stallClosures()}, circuits=${relay.relayCircuitCount()}"
    }

/**
 * Runs [block] and, when it throws, rethrows an [AssertionError] that says **which step** failed,
 * after how many milliseconds, what the relay's flow-control gauges showed, how much heap was in
 * use, and the full cause chain (messages and classes). The original exception stays the cause.
 *
 * It is a pure description layer: [block] runs exactly once, nothing is retried, and a success is
 * returned untouched.
 */
internal fun <T> diagnosed(
    step: String,
    relay: LapisNode? = null,
    block: () -> T,
): T {
    val started = Instant.now()
    try {
        return block()
    } catch (error: Throwable) {
        val elapsed = Duration.between(started, Instant.now()).toMillis()
        val runtime = Runtime.getRuntime()
        val summary =
            "$step failed after $elapsed ms; ${relayState(relay)}; " +
                "heap used=${(runtime.totalMemory() - runtime.freeMemory()) shr 20} MiB " +
                "of max ${runtime.maxMemory() shr 20} MiB; " +
                "causes: ${causeClasses(error)} - ${causeChain(error)}"
        diag { "$summary\n${relayThreadDump()}" }
        throw AssertionError(summary, error)
    }
}

/** [LapisNode.connect] with [diagnosed]'s description attached to a failure. */
internal fun connectDiagnosed(
    node: LapisNode,
    peer: PeerInfo,
    timeout: Duration = Duration.ofSeconds(45),
    relay: LapisNode? = null,
    step: String = "connect to ${peer.peerId}",
): Connection = diagnosed(step, relay) { node.connect(peer, timeout) }
