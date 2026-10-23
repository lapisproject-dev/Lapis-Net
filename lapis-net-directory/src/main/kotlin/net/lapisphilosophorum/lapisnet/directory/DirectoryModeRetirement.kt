package net.lapisphilosophorum.lapisnet.directory

import io.github.oshai.kotlinlogging.KotlinLogging

private val logger = KotlinLogging.logger {}

/**
 * The normal-mode (OFF) side of a mode switch (wave V0.10.0-E). A node that ran in anonymity mode and now starts in
 * normal mode must retire its anonymous record: a revocation that covers every still-valid [AnonymousPeerRecord].
 * Nothing in the code did this before (the plan existed in [DirectoryModeTransition.prepare], no caller).
 *
 * The revocation is sent from the own node (the identity is about to be published together with its address anyway, so
 * the revocation links nothing new). The OFF state is persisted only after the revocation went out: if publishing
 * fails, the next start finds the old mode again and builds a fresh, higher-numbered revocation.
 */
object DirectoryModeRetirement {
    /**
     * @param publishRevocation hands the revocation to the network (e.g. the anonymous-record gossip); it MUST throw
     * if the revocation could not be sent
     * @return `true` once the node is persisted as being in normal mode (first start, unchanged mode or revocation
     * sent); `false` if the revocation could not be sent and the previous (anonymity) state is kept for a retry
     */
    fun onNormalStart(
        transition: DirectoryModeTransition,
        publishRevocation: (AnonymousPeerRecord) -> Unit,
    ): Boolean {
        val plan = transition.prepare(DirectoryAnonymityMode.OFF)
        if (plan is DirectoryTransitionPlan.Revocation) {
            try {
                publishRevocation(plan.record)
            } catch (e: RuntimeException) {
                logger.warn {
                    "anonymous record revocation could not be sent (${e.javaClass.simpleName}); will retry at the next start"
                }
                return false
            }
        }
        transition.nextSequence(DirectoryAnonymityMode.OFF)
        return true
    }
}
