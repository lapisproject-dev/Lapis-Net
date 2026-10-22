package net.lapisphilosophorum.lapisnet.onionwire

import net.lapisphilosophorum.lapisnet.directory.OnionRelayDescriptor
import net.lapisphilosophorum.lapisnet.onion.CircuitPurpose
import net.lapisphilosophorum.lapisnet.onion.ExperimentalOnionApi

/**
 * Supplies the complete relay path of a circuit whose LAST hop is [OnionPathProvider.pathEndingAt]'s `last`. There is
 * deliberately no path selection in this wave (guards, diversity, bandwidth weighting are wave E): the hidden-service
 * host and client ask the provider, tests give fixed paths. A production-quality provider would never return a path
 * of fewer than three relays. The provider decides; nothing here checks anonymity properties of the path.
 */
@ExperimentalOnionApi
fun interface OnionPathProvider {
    fun pathEndingAt(
        last: OnionRelayDescriptor,
        purpose: CircuitPurpose,
    ): List<OnionRelayDescriptor>
}
