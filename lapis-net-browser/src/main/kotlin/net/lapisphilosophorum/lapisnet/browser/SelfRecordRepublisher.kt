package net.lapisphilosophorum.lapisnet.browser

import io.github.oshai.kotlinlogging.KotlinLogging
import io.libp2p.core.multiformats.Multiaddr
import net.lapisphilosophorum.lapisnet.directory.DhtOutbox
import net.lapisphilosophorum.lapisnet.directory.DirectoryDht
import net.lapisphilosophorum.lapisnet.directory.DirectoryDhtPublishResult
import net.lapisphilosophorum.lapisnet.directory.PeerCapability
import net.lapisphilosophorum.lapisnet.directory.PeerDirectoryGossip
import net.lapisphilosophorum.lapisnet.directory.PeerRecord
import net.lapisphilosophorum.lapisnet.directory.PrekeyBundleGossip
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.ratchet.PrekeyStore
import java.time.Instant
import kotlin.time.Duration
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.seconds

private val logger = KotlinLogging.logger {}

/**
 * Keeps this node's own [PeerRecord] and prekey bundle current (V0.9.15). Before this class the browser published them
 * exactly once at start; but a node behind a NAT only learns its `/p2p-circuit` addresses AFTER the relay
 * reservations succeeded, i.e. after that one publication - without a re-publication a private node would hold
 * reservations nobody can dial. Call [tick] periodically (it is cheap when nothing changed).
 *
 *  - **Gossip**: re-announced when [addresses] changed, or [maxGossipInterval] has passed.
 *  - **DHT** (only when [directoryDht] is set): published on the same triggers, and whenever the [outbox] holds
 *    entries - the outbox is the only way offline mail/DM pointers reach the DHT, and `publishOwn` is what carries
 *    them. At most one attempt per [minDhtAttemptInterval] (the library throttles as well; a throttled call is not
 *    counted as done and is retried). The DHT value must fit a few KiB, so it carries a REDUCED prekey bundle (two
 *    one-time prekeys; none if even that is too large) - an exhausted one-time prekey only costs X3DH its optional
 *    one-time part.
 *
 * The capability set stays `{DM}`. **Never RELAY**: this node does not serve as a relay for others.
 */
internal class SelfRecordRepublisher(
    private val identity: DualKeyIdentity,
    private val addresses: () -> List<Multiaddr>,
    private val peerDirectory: PeerDirectoryGossip,
    private val prekeyBundleGossip: PrekeyBundleGossip,
    private val prekeyStore: PrekeyStore,
    private val directoryDht: DirectoryDht?,
    private val outbox: DhtOutbox?,
    private val maxGossipInterval: Duration = 6.hours,
    private val minDhtAttemptInterval: Duration = 300.seconds,
    private val recordTtlSeconds: Long = DM_SELF_RECORD_TTL_SECONDS,
    private val clockMillis: () -> Long = System::currentTimeMillis,
) {
    private var gossipAddresses: Set<String>? = null
    private var gossipAtMillis: Long? = null
    private var dhtAddresses: Set<String>? = null
    private var dhtPublishedAtMillis: Long? = null
    private var dhtAttemptAtMillis: Long? = null

    /** `true` if nothing happened yet ([since] `null`) or [window] has passed since [since]. */
    private fun elapsed(
        since: Long?,
        now: Long,
        window: Duration,
    ): Boolean = since == null || now - since >= window.inWholeMilliseconds

    /** Number of gossip publications so far (tests). */
    @Volatile var gossipPublications: Int = 0
        private set

    /** Number of DHT publication ATTEMPTS, successful or not (tests: proves the throttling of attempts). */
    @Volatile var dhtAttempts: Int = 0
        private set

    /** Number of DHT publications that were actually performed (tests). */
    @Volatile var dhtPublications: Int = 0
        private set

    @Synchronized
    fun tick(includeDht: Boolean = true) {
        val now = clockMillis()
        val current = addresses().map { it.toString() }.toSet()
        val gossipDue = gossipAddresses != current || elapsed(gossipAtMillis, now, maxGossipInterval)
        val dhtDue =
            includeDht &&
                directoryDht != null &&
                (
                    dhtAddresses != current ||
                        elapsed(dhtPublishedAtMillis, now, maxGossipInterval) ||
                        (outbox?.size() ?: 0) > 0
                ) &&
                elapsed(dhtAttemptAtMillis, now, minDhtAttemptInterval)
        if (!gossipDue && !dhtDue) return

        val nowSeconds = Instant.ofEpochMilli(now).epochSecond
        val notValidAfter = nowSeconds + recordTtlSeconds
        val record =
            PeerRecord.create(
                identity = identity,
                addresses = addresses(),
                capabilities = setOf(PeerCapability.DM),
                // Wall-clock epoch millis, see BrowserServer.start: anti-rollback needs a restart-safe counter.
                sequenceNumber = now,
                notValidAfterEpochSecond = notValidAfter,
                nowEpochSecond = nowSeconds,
            )
        if (gossipDue) {
            peerDirectory.announce(record)
            prekeyBundleGossip.announce(prekeyStore.publishBundle(identity, notValidAfter, nowEpochSecond = nowSeconds))
            gossipAddresses = current
            gossipAtMillis = now
            gossipPublications++
        }
        if (dhtDue) {
            directoryDht.let { dht ->
                dhtAttemptAtMillis = now
                dhtAttempts++
                if (publishToDht(dht, record, notValidAfter, nowSeconds)) {
                    dhtAddresses = current
                    dhtPublishedAtMillis = now
                    dhtPublications++
                }
            }
        }
    }

    private fun publishToDht(
        dht: DirectoryDht,
        record: PeerRecord,
        notValidAfter: Long,
        nowSeconds: Long,
    ): Boolean {
        for (oneTimePrekeys in listOf(REDUCED_ONE_TIME_PREKEYS, 0)) {
            val bundle =
                prekeyStore.publishBundle(
                    identity,
                    notValidAfter,
                    maxOneTimePrekeys = oneTimePrekeys,
                    nowEpochSecond = nowSeconds,
                )
            try {
                return dht.publishOwn(identity, record, bundle).reachedPeers()
            } catch (e: IllegalArgumentException) {
                logger.debug { "directory DHT value too large with $oneTimePrekeys one-time prekeys; reducing" }
            } catch (e: Exception) {
                logger.warn { "publishing the own record to the DHT failed (${e.javaClass.simpleName}); will retry" }
                return false
            }
        }
        // Even without one-time prekeys it did not fit: publish the record alone so the node stays dialable.
        return try {
            dht.publishOwn(identity, record, null).reachedPeers()
        } catch (e: Exception) {
            logger.warn { "publishing the own record to the DHT failed (${e.javaClass.simpleName}); will retry" }
            false
        }
    }

    /**
     * Only a publication that at least one DHT peer acknowledged counts as done: with an empty routing table the value
     * is held locally only (0 attempted, 0 acknowledged), and must be retried after [minDhtAttemptInterval].
     */
    private fun DirectoryDhtPublishResult.reachedPeers(): Boolean = !skippedByRateLimit && acknowledged > 0

    companion object {
        /** One-time prekeys carried by the DHT copy of the bundle. */
        const val REDUCED_ONE_TIME_PREKEYS = 2
    }
}
