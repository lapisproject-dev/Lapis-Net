@file:OptIn(ExperimentalOnionApi::class)

package net.lapisphilosophorum.lapisnet.onionwire.anonymity

import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptor
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi
import net.lapisphilosophorum.lapisnet.onion.RendezvousClientState
import net.lapisphilosophorum.lapisnet.onion.RendezvousFailure
import net.lapisphilosophorum.lapisnet.onionwire.RendezvousFailedException
import java.security.SecureRandom
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletionException
import java.util.concurrent.ExecutionException
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * One client-side retry of a rendezvous with a DIFFERENT rendezvous point (fix wave "rendezvous after guard failover").
 *
 * Why: a service whose effective guard equals the client's rendezvous point can not build the rendezvous circuit when no
 * other persisted guard is usable (a relay can not appear twice in a path, and entering through a fresh relay would be
 * an attacker-triggerable guard discovery). The service then drops the rendezvous silently and the client waits in
 * AWAIT_RENDEZVOUS2 until its timeout. The client can not know that, but a second attempt with another rendezvous point
 * succeeds.
 *
 * Rules: at most [maxAttempts] attempts (one retry). A retry happens only after [RendezvousFailure.TIMEOUT] in
 * [RendezvousClientState.AWAIT_RENDEZVOUS2] or after [RendezvousFailure.RENDEZVOUS_POINT]; never after a clear answer of
 * the service (NO_INTRODUCTION, AUTHENTICATION, INVALID_DESCRIPTOR) and never after a refusal of the circuit governor
 * (every retry goes through the same governor, so the protection against build storms is unchanged). The retry waits a
 * random [jitterMin]..[jitterMax], excludes the first rendezvous point and never uses a warm circuit. The pattern is the
 * same for every client and target (fixed bound, random jitter). Each attempt gets the full timeout, so the worst case
 * is `maxAttempts * timeout + jitterMax`. After [isClosed] turned `true` nothing new is started.
 */
internal class RendezvousRetry<S : Any, W : Any>(
    private val attempt: (
        rp: OnionRelayDescriptor,
        prebuilt: W?,
        timeout: Duration,
    ) -> CompletableFuture<S>,
    private val selectRendezvousPoint: (exclude: Set<Secp256k1PublicKey>) -> OnionRelayDescriptor?,
    private val schedule: (delayMillis: Long, task: () -> Unit) -> Unit,
    private val random: SecureRandom,
    private val isClosed: () -> Boolean = { false },
    private val onRetry: () -> Unit = {},
    private val maxAttempts: Int = 2,
    private val jitterMin: Duration = 2.seconds,
    private val jitterMax: Duration = 6.seconds,
    /** Closes a stream that arrived after the result was already completed. */
    private val discard: (S) -> Unit = {},
) {
    init {
        require(maxAttempts >= 1) { "maxAttempts must be at least 1" }
        require(!jitterMin.isNegative() && jitterMax >= jitterMin) { "invalid jitter range" }
    }

    fun run(
        first: OnionRelayDescriptor,
        prebuilt: W?,
        timeout: Duration,
    ): CompletableFuture<S> {
        val result = CompletableFuture<S>()
        go(1, first, prebuilt, setOf(first.identity), timeout, result)
        return result
    }

    private fun go(
        n: Int,
        rp: OnionRelayDescriptor,
        prebuilt: W?,
        exclude: Set<Secp256k1PublicKey>,
        timeout: Duration,
        result: CompletableFuture<S>,
    ) {
        val f =
            try {
                attempt(rp, prebuilt, timeout)
            } catch (e: RuntimeException) {
                CompletableFuture.failedFuture(e)
            }
        f.whenComplete { stream, error ->
            if (error == null) {
                if (!result.complete(stream)) runCatching { discard(stream) }
                return@whenComplete
            }
            val cause = unwrap(error)
            if (n >= maxAttempts || !retryable(cause) || isClosed() || result.isDone) {
                result.completeExceptionally(cause)
                return@whenComplete
            }
            onRetry()
            try {
                schedule(jitterMillis()) {
                    if (isClosed() || result.isDone) {
                        result.completeExceptionally(cause)
                    } else {
                        val next = runCatching { selectRendezvousPoint(exclude) }.getOrNull()
                        if (next == null || next.identity in exclude) {
                            result.completeExceptionally(cause)
                        } else {
                            go(n + 1, next, null, exclude + next.identity, timeout, result)
                        }
                    }
                }
            } catch (e: RuntimeException) {
                // the scheduler is shut down: no retry
                result.completeExceptionally(cause)
            }
        }
    }

    private fun jitterMillis(): Long {
        val min = jitterMin.inWholeMilliseconds
        val span = jitterMax.inWholeMilliseconds - min
        return min + if (span > 0) random.nextLong(span + 1) else 0L
    }

    companion object {
        /** The failures after which a second rendezvous point is tried (see the class comment). */
        internal fun retryable(cause: Throwable): Boolean =
            cause is RendezvousFailedException &&
                // a governor refusal of the rendezvous circuit also ends in RENDEZVOUS_POINT: never retried
                !cause.refusedByGovernor &&
                (
                    (
                        cause.reason == RendezvousFailure.TIMEOUT &&
                            cause.atState == RendezvousClientState.AWAIT_RENDEZVOUS2
                    ) ||
                        cause.reason == RendezvousFailure.RENDEZVOUS_POINT
                )

        private fun unwrap(t: Throwable): Throwable {
            var c = t
            while ((c is CompletionException || c is ExecutionException) && c.cause != null) c = c.cause!!
            return c
        }
    }
}
