package net.lapisphilosophorum.lapisnet.directory

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.onion.OnionServiceDescriptor
import java.time.Instant

/** The outcome of resolving an identity through the mixed directory. Every `toString` is redacted. */
sealed interface DirectoryReachability {
    /** Reachable only through the onion service; [descriptor] holds the introduction points. */
    class Hidden(
        val record: AnonymousPeerRecord,
        val descriptor: OnionServiceDescriptor,
    ) : DirectoryReachability {
        override fun toString(): String = "Hidden(REDACTED)"
    }

    /** The identity announced an onion presence but its service descriptor is not (yet) known. */
    class HiddenDescriptorMissing(
        val record: AnonymousPeerRecord,
    ) : DirectoryReachability {
        override fun toString(): String = "HiddenDescriptorMissing(REDACTED)"
    }

    /** Reachable the classic way. */
    class Direct(
        val record: PeerRecord,
    ) : DirectoryReachability {
        override fun toString(): String = "Direct(REDACTED)"
    }

    /** The identity retired its onion presence and has no (newer) address record. */
    data object Revoked : DirectoryReachability

    data object Unknown : DirectoryReachability
}

/**
 * Resolution API over the mixed directory (wave V0.10.0-D). Callers in DM, Mail and Call are NOT wired to it in this
 * wave (that is wave F): there is no user traffic over circuits yet. The newer of the two record types (by sequence
 * number, anonymous wins a tie) decides. A DHT lookup of the service descriptor shows the DHT the sender's interest.
 */
class AnonymousDirectory(
    private val directory: PeerDirectoryGossip,
    private val descriptors: OnionServiceDescriptorIndex,
    private val serviceDht: OnionServiceDht? = null,
    private val wallClock: () -> Instant = Instant::now,
) {
    fun resolve(identity: Secp256k1PublicKey): DirectoryReachability {
        val now = wallClock().epochSecond
        val anonymous = directory.anonymousRecords.currentIncludingRevocation(identity, now)
        val direct = directory.lookup(identity, now)
        if (anonymous != null && (direct == null || anonymous.sequenceNumber >= direct.sequenceNumber)) {
            if (anonymous.revoked) return DirectoryReachability.Revoked
            val serviceKey = checkNotNull(anonymous.serviceKey)
            val local = descriptors.current(serviceKey, now)
            if (local != null) return DirectoryReachability.Hidden(anonymous, local)
            val address = checkNotNull(anonymous.onionAddress)
            val remote = runCatching { serviceDht?.resolve(address) }.getOrNull()
            return if (remote != null) {
                DirectoryReachability.Hidden(anonymous, remote)
            } else {
                DirectoryReachability.HiddenDescriptorMissing(anonymous)
            }
        }
        if (direct != null) return DirectoryReachability.Direct(direct)
        return DirectoryReachability.Unknown
    }
}
