package net.lapisphilosophorum.lapisnet.ratchet

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.EncryptionKeyBinding
import net.lapisphilosophorum.lapisnet.identity.IdentityRepository
import net.lapisphilosophorum.lapisnet.identity.KeystoreDecryptionException
import net.lapisphilosophorum.lapisnet.identity.PassphraseProvider
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.identity.X25519KeyPair
import net.lapisphilosophorum.lapisnet.identity.X25519PrivateKey
import net.lapisphilosophorum.lapisnet.identity.X25519PublicKey
import java.io.IOException
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import java.security.SecureRandom
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import kotlin.io.path.exists

private val logger = KotlinLogging.logger {}

private val VALID_LABEL = Regex("^[A-Za-z0-9_-]{1,64}\$")
private val DIRECTORY_PERMISSIONS = PosixFilePermissions.fromString("rwx------")
private val FILE_PERMISSIONS = PosixFilePermissions.fromString("rw-------")

/** Thrown by [PrekeyStore.consumeOneTimePrekey] when the named id is unknown or has already been
 * consumed - both are HARD failures; neither ever silently falls back to a signed-prekey-only
 * handshake (see [net.lapisphilosophorum.lapisnet.ratchet.X3dh]'s doc comment for why prekey
 * EXHAUSTION, an initiator-side condition, is a different and legitimate degradation path from
 * one-time-prekey REUSE, which this exception exists to prevent absolutely). Also thrown by
 * [PrekeyStore.generateOneTimePrekeys] if growing the entry list would exceed
 * [PrekeyStoreFileFormat.MAX_ONE_TIME_PREKEY_ENTRIES] without enough tombstones available to prune. */
class PrekeyConsumptionException(
    message: String,
) : RuntimeException(message)

/**
 * The result of a successful [PrekeyStore.consumeOneTimePrekey] call: the consumed [id] paired
 * with its [privateKey], so a caller (specifically [X3dh.respond]) can assert the two actually
 * correspond rather than trusting that a private key handed to it was consumed under the id the
 * initiator's header names - see [X3dh.respond]'s doc comment for why that assertion matters. A
 * bare [X25519PrivateKey] carries no id, so a caller wiring bug that consumes the wrong id would
 * otherwise silently derive a mismatched secret that only fails much later, at first AEAD use.
 *
 * **`internal` constructor, deliberately NOT a `data class`** - a caller-visible public constructor
 * (plus a `data class`'s synthesized `copy()`) would let ANY caller mint a `ConsumedOneTimePrekey`
 * for an id/key pair that was never actually run through [PrekeyStore.consumeOneTimePrekey],
 * undermining exactly the ordering contract [X3dh.respond]'s check 3 relies on this type to
 * enforce: "the one-time prekey named in the header was durably consumed via [PrekeyStore] BEFORE
 * [X3dh.respond] is called". Restricting construction to this module (only [PrekeyStore] actually
 * constructs one, in [PrekeyStore.consumeOneTimePrekey]) makes that ordering a property the type
 * system enforces, not merely a caller-discipline convention stated in a doc comment - the same
 * reasoning [PrekeyBundle.fromDecoded]'s own `internal` visibility already applies to a different
 * caller-discipline contract in this module.
 */
class ConsumedOneTimePrekey internal constructor(
    val id: Int,
    val privateKey: X25519PrivateKey,
) {
    /** Never exposes [privateKey] - mirrors [X3dhSharedSecret.toString]'s identical REDACTED
     * discipline for the same reason: this is key material, never fit to log. */
    override fun toString(): String = "ConsumedOneTimePrekey(id=$id, privateKey=REDACTED)"
}

/**
 * Local storage for the PRIVATE halves of an identity's X3DH key material: the X25519 identity
 * private key, the current signed-prekey private key, and every one-time prekey's private key -
 * tombstoned, never deleted, once consumed (see [consumeOneTimePrekey]'s doc comment for the full
 * durability contract this class exists to provide). Reuses
 * [net.lapisphilosophorum.lapisnet.identity.FileIdentityRepository]'s established persistence
 * pattern (atomic temp-file-then-move writes, POSIX 0600/0700 permission hardening,
 * Argon2id/AES-256-GCM encryption at rest via
 * [net.lapisphilosophorum.lapisnet.identity.KeystoreEncryption]) rather than inventing a new one -
 * see [PrekeyStoreFileFormat]'s class doc comment for the on-disk layout this class encodes/decodes
 * through.
 *
 * **Deliberately does NOT touch `DualKeyIdentity`, `KeystoreFileFormat`,
 * `FileIdentityRepository`, or `IdentityRepository`** - the X25519 identity key's private half
 * lives HERE, in its own file, under its own `.lnpk` extension, entirely separate from an
 * identity's existing `.lnid` keystore. No keystore format version bump, no migration path, no
 * change to any module that already embeds an
 * [net.lapisphilosophorum.lapisnet.identity.IdentityBinding] - stated explicitly so a reviewer does
 * not go looking for a v3 keystore.
 *
 * **[encryptionBinding] is deliberately NOT a stored/cached field on this class** - a documented,
 * deliberate simplification over an earlier draft of this design that considered caching it after
 * [create] while recomputing it on [open]. Computing an [EncryptionKeyBinding] requires the
 * identity's secp256k1 PRIVATE key (to sign), which this store never holds (it only ever sees the
 * identity's PUBLIC key, [ownerIdentity]) - so [publishBundle] always recomputes it fresh from the
 * [DualKeyIdentity] the caller supplies, on every call, both right after [create] and after any
 * later [open]. Because `Secp256k1KeyPair.sign` is RFC 6979-deterministic, this recomputation is
 * byte-stable across calls - noted here, but never depended on for correctness.
 */
class PrekeyStore private constructor(
    private val file: Path,
    private val passphraseProvider: PassphraseProvider,
    @Volatile private var state: PrekeyStoreState,
) {
    /** The secp256k1 identity this store's key material belongs to - PUBLIC key only, this store
     * never holds (or needs) the corresponding secp256k1 private key. */
    val ownerIdentity: Secp256k1PublicKey get() = state.ownerIdentity

    /** This identity's X25519 encryption sub-key, public half - stable for this store's lifetime
     * (there is no "rotate the identity key" operation, mirroring how a [DualKeyIdentity]'s own
     * secp256k1/Ed25519 keys never rotate either).
     *
     * **Serves this instance's cached [state], not disk truth - may be stale relative to a second
     * live [PrekeyStore] handle open against the same file.** Harmless for THIS particular field
     * specifically, because the X25519 identity key never rotates (unlike [signedPrekeyId]/
     * [signedPrekeyPrivateKey], see their doc comments for where staleness here actually bites). */
    val x25519IdentityPublicKey: X25519PublicKey
        get() = X25519KeyPair.fromPrivateKeyBytes(state.x25519IdentityPrivateKeyBytes).publicKey

    /** The currently active signed prekey's id - changes on [rotateSignedPrekey].
     *
     * **Serves this instance's cached [state], not disk truth.** If a second live [PrekeyStore]
     * handle open against the same file calls [rotateSignedPrekey], THIS handle's [signedPrekeyId]/
     * [signedPrekeyPublicKey]/[signedPrekeyPrivateKey] keep returning the pre-rotation values until
     * this handle itself performs a mutating call (which re-reads disk truth) or is re-opened. A
     * caller wiring [X3dh.respond] with a stale `signedPrekeyId`/`signedPrekeyPrivateKey` pair
     * rejects legitimate initiations at [X3dh.respond]'s check 1 - re-open this handle after any
     * out-of-band rotation performed through a different handle. */
    val signedPrekeyId: Int get() = state.signedPrekeyId

    /** The currently active signed prekey's public half - changes on [rotateSignedPrekey]. Same
     * cached-[state], re-open-after-out-of-band-mutation caveat as [signedPrekeyId]. */
    val signedPrekeyPublicKey: X25519PublicKey
        get() = X25519KeyPair.fromPrivateKeyBytes(state.signedPrekeyPrivateKeyBytes).publicKey

    /** Same cached-[state] caveat as [signedPrekeyId]: may under-report ids a second live handle
     * has since consumed via [consumeOneTimePrekey], or over-report ids it has since generated. Only
     * [publishBundle] itself re-reads disk truth before offering one-time prekeys in a bundle - this
     * accessor is informational only and should not be used to decide whether a specific id is still
     * safe to publish. */
    @Synchronized
    fun availableOneTimePrekeyIds(): List<Int> =
        state.entries
            .filter { it.state == OneTimePrekeyState.AVAILABLE }
            .map { it.id }
            .sorted()

    /** Same cached-[state] caveat as [availableOneTimePrekeyIds]. */
    @Synchronized
    fun availableOneTimePrekeyCount(): Int = state.entries.count { it.state == OneTimePrekeyState.AVAILABLE }

    /** Builds and signs a [PrekeyBundle] from the PUBLIC halves this store holds, for [identity] -
     * which must own this store ([identity].secp256k1KeyPair.publicKey must equal [ownerIdentity]).
     * See this class's doc comment for why [EncryptionKeyBinding] is always recomputed here, never
     * cached. Offers at most [maxOneTimePrekeys] of the currently AVAILABLE one-time prekeys
     * (lowest ids first) - an empty list (e.g. after full exhaustion) still produces a bundle that
     * passes all three of [PrekeyBundle.verify]/[net.lapisphilosophorum.lapisnet.ratchet.verifyEncryptionBinding]/
     * [net.lapisphilosophorum.lapisnet.ratchet.verifySignedPrekey] - the SPEC's exhaustion-must-not-crash
     * requirement, one layer up from [net.lapisphilosophorum.lapisnet.ratchet.X3dh] itself.
     *
     * **Re-reads disk truth via [withExclusiveFileAccess] before selecting which one-time prekeys to
     * offer - never this instance's own cached [state].** Unlike the plain read accessors above
     * (which stay on the cached snapshot, documented as informational-only), this method's output is
     * published to the network and directly drives what a peer may attempt to consume: publishing an
     * already-consumed id here (because a second live handle durably consumed it via
     * [consumeOneTimePrekey] after this handle's own cache was last refreshed) causes every initiator
     * that picks it to hit an unavoidable [X3dh]-layer failure at the responder, per [X3dh.respond]'s
     * mandatory-abort contract - a self-inflicted, entirely avoidable handshake-failure loop.
     *
     * **Owns and persists [sequenceNumber] itself - no longer a caller-supplied parameter.** An
     * earlier version of this method took `sequenceNumber` as a plain argument, trusting every
     * caller to track a strictly-monotonic-per-identity counter correctly across process restarts
     * and multiple call sites - exactly the kind of state an identity's own store should own,
     * mirroring how [signedPrekeyId]/[nextOneTimePrekeyId] are already this store's own responsibility
     * rather than caller-supplied. [PrekeyStoreState.nextBundleSequenceNumber] is the persisted
     * counter this method claims-then-increments, atomically, under the same exclusive critical
     * section [consumeOneTimePrekey] uses - so two concurrently-open handles on the same file can
     * never publish two bundles with the same sequence number (the exact property
     * `PrekeyBundleIndex`, in `lapis-net-directory`, relies on for its latest-wins-by-sequence-number
     * ordering).
     *
     * **The counter is claimed and persisted AFTER [PrekeyBundle.create] has already built and signed
     * the bundle, not before** - so a bundle-creation failure (e.g. [notValidAfterEpochSecond] too
     * far beyond [nowEpochSecond], see [PrekeyBundle.create]'s own `require`) never burns a sequence
     * number. Unlike a one-time prekey (irreplaceable once consumed), a "gap" in the bundle sequence
     * is completely harmless - `PrekeyBundleIndex` only requires strict monotonicity, never
     * consecutive values - so this ordering is purely a courtesy against needless gaps, not a
     * correctness requirement the way persist-before-mutate is for [consumeOneTimePrekey].
     */
    @Synchronized
    fun publishBundle(
        identity: DualKeyIdentity,
        notValidAfterEpochSecond: Long,
        maxOneTimePrekeys: Int = PrekeyBundleCodec.MAX_ONE_TIME_PREKEYS,
        nowEpochSecond: Long = Instant.now().epochSecond,
    ): PrekeyBundle {
        require(identity.secp256k1KeyPair.publicKey == ownerIdentity) {
            "identity does not match this prekey store's owner"
        }
        return withExclusiveFileAccess { onDiskState ->
            state = onDiskState
            val x25519PublicKey =
                X25519KeyPair.fromPrivateKeyBytes(onDiskState.x25519IdentityPrivateKeyBytes).publicKey
            val encryptionBinding = EncryptionKeyBinding.create(identity.secp256k1KeyPair, x25519PublicKey)
            val signedPrekeyPublic =
                X25519KeyPair.fromPrivateKeyBytes(onDiskState.signedPrekeyPrivateKeyBytes).publicKey
            val offeredOneTimePrekeys =
                onDiskState.entries
                    .filter { it.state == OneTimePrekeyState.AVAILABLE }
                    .sortedBy { it.id }
                    .take(maxOneTimePrekeys)
                    .map { OneTimePrekey(it.id, X25519KeyPair.fromPrivateKeyBytes(it.privateKeyBytes).publicKey) }

            val bundle =
                PrekeyBundle.create(
                    identity = identity,
                    encryptionBinding = encryptionBinding,
                    signedPrekeyId = onDiskState.signedPrekeyId,
                    signedPrekey = signedPrekeyPublic,
                    oneTimePrekeys = offeredOneTimePrekeys,
                    sequenceNumber = onDiskState.nextBundleSequenceNumber,
                    notValidAfterEpochSecond = notValidAfterEpochSecond,
                    nowEpochSecond = nowEpochSecond,
                )

            val newState =
                PrekeyStoreState(
                    ownerIdentity = onDiskState.ownerIdentity,
                    x25519IdentityPrivateKeyBytes = onDiskState.x25519IdentityPrivateKeyBytes,
                    signedPrekeyId = onDiskState.signedPrekeyId,
                    signedPrekeyPrivateKeyBytes = onDiskState.signedPrekeyPrivateKeyBytes,
                    nextOneTimePrekeyId = onDiskState.nextOneTimePrekeyId,
                    nextBundleSequenceNumber = onDiskState.nextBundleSequenceNumber + 1,
                    entries = onDiskState.entries,
                )
            persistAtomically(newState)
            state = newState
            bundle
        }
    }

    /**
     * THE one-shot, durable consumption gate. Marks the one-time prekey [id] permanently CONSUMED
     * and returns it paired with its private key as a [ConsumedOneTimePrekey] - once this call
     * succeeds, no later call (on this instance OR any instance opened later against the SAME file,
     * including across a process restart, **including a second [PrekeyStore] handle already open
     * against this same file right now, in this process or another**) can ever consume [id] again.
     *
     * **Never trusts this instance's own cached [state] for the availability check or the base of
     * the new state image - always re-reads and re-decodes the CURRENT bytes on disk first, inside
     * the same exclusive critical section that then writes the result.** A second live
     * [PrekeyStore] handle opened against this file has its OWN cached `state` snapshot, taken at
     * ITS OWN [open]/[create] time; if this method mutated from that cached snapshot instead, two
     * concurrently-open handles could each independently believe a different one-time prekey is
     * still available and each successfully consume one - and because each write persists that
     * handle's ENTIRE (stale) entry list, the second write would silently erase the first handle's
     * tombstone too, resurrecting an already-consumed id as available again on disk. Re-reading
     * disk truth inside the lock is what actually closes that gap, not merely documents it away.
     *
     * Executes in exactly this order - **this ordering is load-bearing, persist BEFORE mutate, and
     * BEFORE returning**:
     * 1. Acquire exclusive access to [file] via [withExclusiveFileAccess] (see that method's doc
     *    comment for the two independent layers of mutual exclusion this provides) and re-read the
     *    CURRENT on-disk state through it.
     * 2. Look up the entry in that freshly-read state. Unknown id or already-`CONSUMED` ->
     *    [PrekeyConsumptionException], a hard failure that NEVER falls back to a signed-prekey-only
     *    handshake (that fallback is only ever correct for initiator-side prekey EXHAUSTION - a
     *    different condition, see [net.lapisphilosophorum.lapisnet.ratchet.X3dh]'s doc comment).
     * 3. Copy the 32 private-key bytes into a local array this function owns.
     * 4. Build the NEW state image in memory (this entry CONSUMED, its 32 key bytes zeroed), based
     *    on the freshly-read on-disk state - [this.state] is NOT yet touched.
     * 5. Encode and write the new state to a temp file, `FileChannel.force(true)` it, then
     *    atomically `Files.move` it over [file].
     * 6. ONLY after the move succeeds, assign the new state to [this.state] (this instance's own
     *    cache, so its OTHER accessors stop looking stale too) and release the exclusive lock.
     * 7. Return the copied private key, id-paired, wrapped in a fresh [ConsumedOneTimePrekey].
     *
     * **Why persist-before-mutate, not the reverse.** If the write in step 5 fails, nothing has
     * changed on disk OR in memory - the exception propagates, the prekey stays available, and the
     * handshake simply does not happen: a clean, safe failure. If the process crashes between step
     * 5 and step 6, the prekey is durably consumed and its private half is gone: the pending
     * handshake is lost, which is the SAFE direction. The reverse order (mutate then persist) has a
     * failure mode where in-memory state says consumed but on-disk state says available, so a
     * restart resurrects a prekey a peer may already have used - precisely the reuse this method
     * exists to prevent. `FileChannel.force(true)` before the atomic move is what makes "the write
     * succeeded" mean "the bytes reached stable storage", not merely "they reached the page cache".
     *
     * **Tombstones, not deletions.** A consumed entry is retained with zeroed key bytes rather than
     * removed, so a replay names an id that is KNOWN-CONSUMED rather than UNKNOWN - both are hard
     * failures at step 2, but the distinction matters for [generateOneTimePrekeys]'s pruning
     * discipline, see that method's doc comment.
     *
     * **On a [persistAtomically] failure, the already-constructed [X25519PrivateKey] from step 3 is
     * explicitly [X25519PrivateKey.destroy]ed before the exception propagates - it never lingers on
     * the heap unzeroed with no caller ever having received a handle to destroy it themselves.**
     * Building that object BEFORE persisting is deliberate and stays that way (see the numbered
     * steps above: it is what lets a degenerate stored scalar be caught before the tombstone is
     * burned) - but a caller can only clean up key material it actually received, and on this
     * failure path it never does, since the exception propagates before this method returns
     * anything. Nothing else about the failure mode changes: per step 5's persist-before-mutate
     * discipline, a [persistAtomically] failure here means NOTHING was durably consumed - the
     * one-time prekey remains available and the handshake simply does not happen - so destroying
     * this in-memory copy is pure heap hygiene, not a change to that contract.
     */
    @Synchronized
    fun consumeOneTimePrekey(id: Int): ConsumedOneTimePrekey =
        withExclusiveFileAccess { onDiskState ->
            val entry =
                onDiskState.entries.find { it.id == id }
                    ?: throw PrekeyConsumptionException("unknown one-time prekey id $id")
            if (entry.state == OneTimePrekeyState.CONSUMED) {
                throw PrekeyConsumptionException("one-time prekey $id has already been consumed")
            }

            val privateKeyCopy = entry.privateKeyBytes.copyOf()
            try {
                // Construct (and therefore validate) the X25519PrivateKey BEFORE persisting the
                // tombstone below - X25519PrivateKey's constructor copies privateKeyCopy internally
                // (see its own doc comment), so the later privateKeyCopy.fill(0) in this method's
                // finally block cannot affect the copy it already made. Building this first means a
                // structurally-decodable-but-degenerate (all-zero/all-ones) stored scalar throws
                // BEFORE the entry is burned, rather than after - this call's documented contract is
                // that a failure never consumes the id.
                val consumedPrivateKey = X25519PrivateKey(privateKeyCopy)
                var persisted = false
                try {
                    val newEntries =
                        onDiskState.entries.map {
                            if (it.id ==
                                id
                            ) {
                                OneTimePrekeyStoreEntry(it.id, OneTimePrekeyState.CONSUMED, ByteArray(32))
                            } else {
                                it
                            }
                        }
                    val newState =
                        PrekeyStoreState(
                            ownerIdentity = onDiskState.ownerIdentity,
                            x25519IdentityPrivateKeyBytes = onDiskState.x25519IdentityPrivateKeyBytes,
                            signedPrekeyId = onDiskState.signedPrekeyId,
                            signedPrekeyPrivateKeyBytes = onDiskState.signedPrekeyPrivateKeyBytes,
                            nextOneTimePrekeyId = onDiskState.nextOneTimePrekeyId,
                            nextBundleSequenceNumber = onDiskState.nextBundleSequenceNumber,
                            entries = newEntries,
                        )
                    persistAtomically(newState)
                    state = newState
                    persisted = true
                    ConsumedOneTimePrekey(id, consumedPrivateKey)
                } finally {
                    // See this method's doc comment for why this is pure heap hygiene, not a
                    // correctness change: a persist failure already means nothing was durably
                    // consumed, regardless of whether this in-memory copy is zeroed.
                    if (!persisted) consumedPrivateKey.destroy()
                }
            } finally {
                privateKeyCopy.fill(0)
            }
        }

    /** Returns a fresh [X25519PrivateKey] wrapping this store's X25519 identity private key. The
     * caller owns the returned object's lifetime and should call
     * [net.lapisphilosophorum.lapisnet.identity.X25519PrivateKey.destroy] on it when done - never
     * call `destroy()` from inside this store, mirroring `ecdhSharedSecret`'s identical reasoning
     * about not destroying a caller-supplied key it does not own. */
    @Synchronized
    fun x25519IdentityPrivateKey(): X25519PrivateKey = X25519PrivateKey(state.x25519IdentityPrivateKeyBytes)

    /** Returns a fresh [X25519PrivateKey] wrapping the currently active signed prekey's private
     * key. Same caller-owns-the-lifetime contract as [x25519IdentityPrivateKey]. */
    @Synchronized
    fun signedPrekeyPrivateKey(): X25519PrivateKey = X25519PrivateKey(state.signedPrekeyPrivateKeyBytes)

    /** Generates a fresh signed-prekey keypair, assigns it the next sequential id, persists, and
     * returns the new id. Exposed as a directly callable primitive - nothing in this wave calls it
     * on any periodic schedule, mirroring `PeerRecordIndex.evictExpired`'s identical "not wired to
     * any periodic/background scheduler in this sub-wave" stance (this codebase has no scheduling
     * infrastructure to hook into yet). */
    @Synchronized
    fun rotateSignedPrekey(random: SecureRandom = SecureRandom()): Int =
        withExclusiveFileAccess { onDiskState ->
            val newKeyPair = X25519KeyPair.generate(random)
            val newId = onDiskState.signedPrekeyId + 1
            val newState =
                PrekeyStoreState(
                    ownerIdentity = onDiskState.ownerIdentity,
                    x25519IdentityPrivateKeyBytes = onDiskState.x25519IdentityPrivateKeyBytes,
                    signedPrekeyId = newId,
                    signedPrekeyPrivateKeyBytes = newKeyPair.privateKey.bytes,
                    nextOneTimePrekeyId = onDiskState.nextOneTimePrekeyId,
                    nextBundleSequenceNumber = onDiskState.nextBundleSequenceNumber,
                    entries = onDiskState.entries,
                )
            persistAtomically(newState)
            state = newState
            newId
        }

    /**
     * Generates [count] fresh one-time prekeys with sequential ids starting at the current
     * `nextOneTimePrekeyId`, persists, and returns their public halves.
     *
     * **Pruning discipline, safe ONLY because `nextOneTimePrekeyId` is strictly monotonic and never
     * rewinds** (enforced by [PrekeyStoreState]'s own init block). When appending would exceed
     * [PrekeyStoreFileFormat.MAX_ONE_TIME_PREKEY_ENTRIES], the OLDEST tombstones (`CONSUMED`
     * entries, lowest id first) are pruned first - NEVER an `AVAILABLE` entry. If there are not
     * enough tombstones to prune down to the cap, this throws [PrekeyConsumptionException] rather
     * than silently dropping a live, unconsumed prekey. A pruned id can never be reallocated (the
     * counter only ever increases), so a later replay naming a pruned id still fails at
     * [consumeOneTimePrekey]'s "unknown id" branch exactly as if the tombstone were still present -
     * pruning cannot reopen reuse.
     */
    @Synchronized
    fun generateOneTimePrekeys(
        count: Int,
        random: SecureRandom = SecureRandom(),
    ): List<OneTimePrekey> {
        require(count >= 0) { "count must be >= 0, was $count" }
        if (count == 0) return emptyList()
        return withExclusiveFileAccess { onDiskState ->
            val newKeyPairs = (0 until count).map { X25519KeyPair.generate(random) }
            val startId = onDiskState.nextOneTimePrekeyId
            val newEntries =
                newKeyPairs.mapIndexed {
                    i,
                    kp,
                    ->
                    OneTimePrekeyStoreEntry(startId + i, OneTimePrekeyState.AVAILABLE, kp.privateKey.bytes)
                }
            var allEntries = onDiskState.entries + newEntries

            if (allEntries.size > PrekeyStoreFileFormat.MAX_ONE_TIME_PREKEY_ENTRIES) {
                val overflow = allEntries.size - PrekeyStoreFileFormat.MAX_ONE_TIME_PREKEY_ENTRIES
                val tombstones = allEntries.filter { it.state == OneTimePrekeyState.CONSUMED }.sortedBy { it.id }
                if (tombstones.size < overflow) {
                    throw PrekeyConsumptionException(
                        "cannot generate $count new one-time prekeys - only ${tombstones.size} tombstones available " +
                            "to prune but $overflow slots would need to be freed without dropping a live prekey",
                    )
                }
                val idsToPrune = tombstones.take(overflow).map { it.id }.toSet()
                allEntries = allEntries.filterNot { it.id in idsToPrune }
            }

            val newState =
                PrekeyStoreState(
                    ownerIdentity = onDiskState.ownerIdentity,
                    x25519IdentityPrivateKeyBytes = onDiskState.x25519IdentityPrivateKeyBytes,
                    signedPrekeyId = onDiskState.signedPrekeyId,
                    signedPrekeyPrivateKeyBytes = onDiskState.signedPrekeyPrivateKeyBytes,
                    nextOneTimePrekeyId = startId + count,
                    nextBundleSequenceNumber = onDiskState.nextBundleSequenceNumber,
                    entries = allEntries,
                )
            persistAtomically(newState)
            state = newState
            newKeyPairs.mapIndexed { i, kp -> OneTimePrekey(startId + i, kp.publicKey) }
        }
    }

    /**
     * Runs [block] with exclusive access to [file], having first re-read and re-decoded the
     * CURRENT on-disk state - never this instance's own cached [state], which may be stale relative
     * to a second [PrekeyStore] handle open against the same file (see [consumeOneTimePrekey]'s doc
     * comment for the reuse this closes). Two independent layers of mutual exclusion, both needed:
     *
     * 1. [perFileMonitors] - a plain JVM `synchronized` monitor keyed by this file's canonical path,
     *    shared by every [PrekeyStore] instance in this process that points at the same file.
     *    Needed because [java.nio.channels.FileLock] does NOT block a second acquisition attempt
     *    from the SAME JVM - it throws `OverlappingFileLockException` instead (a JDK-documented
     *    restriction: file locks are held on behalf of the entire JVM, not per-thread). Without this
     *    monitor, two concurrently-open handles in ONE process racing this method would crash with
     *    that exception rather than safely serializing.
     * 2. [FileChannel.lock] - an OS-level exclusive advisory lock, so a second process (not just a
     *    second in-process handle) also serializes against this critical section - the scenario a
     *    real multi-process deployment can actually hit.
     *
     * **The OS lock in layer 2 is taken on a dedicated sidecar file ([lockChannelFor]), never on
     * [file] itself - this is load-bearing, not a style choice.** POSIX advisory locks (what
     * [FileChannel.lock] provides on Linux/macOS) are held on the underlying INODE, not the path.
     * [persistAtomically] durably writes via temp-file-then-`Files.move` (`ATOMIC_MOVE`), which
     * re-points the path [file] at a BRAND NEW inode while the OLD inode - the one this method's
     * lock would actually be held on, if the lock were taken on [file] itself - is still locked but
     * no longer reachable via the path. A second process opening [file] AFTER that rename gets the
     * new inode, which nobody holds a lock on, so its own `channel.lock()` would succeed
     * immediately even though the first process's critical section (which may still be running
     * [block], including a nested [persistAtomically] call) has not finished - two processes end up
     * inside the critical section at once, exactly the one-time-prekey reuse this class exists to
     * prevent. The sidecar file is never renamed or replaced by any write path in this class, so
     * its inode - and therefore the lock held on it - stays valid and effective across every rename
     * this method's [block] may perform. [create] takes the same sidecar lock around its own
     * initial write, for the identical reason (see that method's doc comment).
     *
     * [file] must already exist (every caller of this method only ever runs after [create] has
     * written it at least once). The sidecar lock file need not exist beforehand -
     * [lockChannelFor] creates it on first use, and it is never cleaned up, mirroring the store
     * file's own lifetime.
     */
    private fun <T> withExclusiveFileAccess(block: (onDiskState: PrekeyStoreState) -> T): T =
        synchronized(monitorFor(file)) {
            lockChannelFor(file).use { lockChannel ->
                lockChannel.lock().use {
                    val bytes = Files.readAllBytes(file)
                    val passphrase = passphraseProvider.get()
                    try {
                        val onDiskState = PrekeyStoreFileFormat.decodeAuto(bytes, passphrase)
                        block(onDiskState)
                    } finally {
                        passphrase?.fill('\u0000')
                    }
                }
            }
        }

    private fun persistAtomically(newState: PrekeyStoreState) {
        val baseDirectory = file.parent
        val passphrase = passphraseProvider.get()
        try {
            // Defense in depth against a passphraseProvider that is NOT stable across calls (the
            // real production provider is stable for a given BrowserServer.start() lifetime - see
            // BrowserServer's own dmPrekeyMasterPassphrase doc comment - but this class has no way
            // to enforce that on an arbitrary caller-supplied PassphraseProvider). Refuses to write
            // an unencrypted (v1) file over an already-encrypted (v2) one just because THIS
            // particular get() call came back null - that would silently strip encryption from
            // X3DH private key material that a previous call correctly wrote as v2, with no
            // exception and no on-disk trace of what happened. A genuinely intentional "stop
            // encrypting this store" is not a supported operation; an operator who wants that must
            // delete and recreate the store.
            if (passphrase == null && file.exists()) {
                val onDiskVersion = PrekeyStoreFileFormat.formatVersionOf(Files.readAllBytes(file))
                check(onDiskVersion != PrekeyStoreFileFormat.FORMAT_VERSION_2) {
                    "refusing to persist an unencrypted (v1) prekey store over an existing " +
                        "encrypted (v2) one at $file - passphraseProvider.get() returned null this " +
                        "time even though the store on disk is currently encrypted, which would " +
                        "silently downgrade X3DH private key material to plaintext. The " +
                        "passphraseProvider must resolve the SAME passphrase (or consistently " +
                        "null) for this store's entire lifetime, never a real passphrase on some " +
                        "calls and null on others."
                }
            }
            val bytes =
                if (passphrase != null) {
                    PrekeyStoreFileFormat.encodeEncrypted(newState, passphrase)
                } else {
                    PrekeyStoreFileFormat.encode(newState)
                }
            val tempFile =
                if (supportsPosixPermissions(baseDirectory)) {
                    Files.createTempFile(
                        baseDirectory,
                        "${file.fileName}.",
                        ".tmp",
                        PosixFilePermissions.asFileAttribute(FILE_PERMISSIONS),
                    )
                } else {
                    Files.createTempFile(baseDirectory, "${file.fileName}.", ".tmp")
                }
            FileChannel.open(tempFile, StandardOpenOption.WRITE).use { channel ->
                channel.write(java.nio.ByteBuffer.wrap(bytes))
                channel.force(true)
            }
            Files.move(tempFile, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
            // The temp file's own force(true) above makes ITS bytes durable; the rename itself is a
            // separate directory-metadata operation that a crash right after Files.move can still
            // lose on some filesystems, leaving the directory entry pointing at the PRE-consumption
            // file - resurrecting an already-consumed one-time prekey. fsync-ing the parent directory
            // closes that remaining gap (POSIX only; there is no Windows equivalent, and opening a
            // directory as a FileChannel is a POSIX-specific capability anyway).
            fsyncDirectoryBestEffort(baseDirectory)
        } finally {
            passphrase?.fill('\u0000')
        }
    }

    private fun fsyncDirectoryBestEffort(directory: Path) {
        if (!supportsPosixPermissions(directory)) return
        try {
            FileChannel.open(directory, StandardOpenOption.READ).use { dirChannel ->
                dirChannel.force(true)
            }
        } catch (e: IOException) {
            // Best-effort: the temp file's own force(true) before the rename already makes the
            // BYTES durable; only the rename's own directory-entry durability is weakened if this
            // fails (e.g. some FUSE/network-mounted POSIX filesystems refuse to open a directory for
            // reading at all).
            logger.warn(e) {
                "failed to fsync parent directory $directory after an atomic prekey store write - " +
                    "the written bytes are still durable, but the rename's own durability is now " +
                    "filesystem-dependent"
            }
        }
    }

    private fun supportsPosixPermissions(path: Path): Boolean = "posix" in path.fileSystem.supportedFileAttributeViews()

    companion object {
        const val DEFAULT_ONE_TIME_PREKEY_COUNT = 100
        const val PREKEY_STORE_FILE_EXTENSION = "lnpk"

        /** The first sequence number [publishBundle] ever claims for a freshly [create]d store -
         * mirrors [PrekeyBundle]'s/[PrekeyStoreState]'s own `>= 1` (never `0`) convention for this
         * counter; see [PrekeyStoreState]'s doc comment for why `0` is reserved as "never issued". */
        internal const val INITIAL_BUNDLE_SEQUENCE_NUMBER = 1L

        /** Backs [withExclusiveFileAccess]'s same-JVM mutual-exclusion layer - see that method's doc
         * comment for why a plain monitor is needed in addition to [FileChannel.lock]. Keyed by
         * [canonicalize]d path so two [PrekeyStore] instances opened via different (but equivalent,
         * e.g. relative vs. absolute, OR symlink-aliased) [Path]s to the same file still share one
         * monitor - see [canonicalize]'s doc comment for the symlink-aliasing gap this closes. */
        private val perFileMonitors = ConcurrentHashMap<Path, Any>()

        private fun monitorFor(path: Path): Any = perFileMonitors.getOrPut(canonicalize(path)) { Any() }

        /** Resolves [path]'s PARENT directory to its real, symlink-free form (via [Path.toRealPath])
         * and re-appends the file name, falling back to plain [Path.toAbsolutePath]/[Path.normalize]
         * if the parent does not exist yet (every real caller - [create] via
         * `Files.createDirectories`, every other caller via an already-successful prior [create] -
         * ensures the parent exists first, so this fallback is only ever exercised by a caller that
         * skipped that precondition, and is no worse than not resolving symlinks at all).
         *
         * **The same-JVM aliasing gap this closes.** [monitorFor]'s in-JVM monitor and
         * [lockChannelFor]'s OS-level [FileChannel] lock must agree on which real file they are
         * protecting. [FileChannel.lock] resolves symlinks transparently when the OS opens the file,
         * so two [PrekeyStore]s opened via two DIFFERENT but symlink-equivalent [Path]s to the SAME
         * real file already end up holding an OS-level lock on the SAME inode - but the JDK tracks
         * same-JVM file locks by that real-file identity, not by the [Path] string used to open the
         * channel, so a second `channel.lock()` call from within this JVM throws
         * `OverlappingFileLockException` instead of blocking, per [withExclusiveFileAccess]'s own doc
         * comment on why the plain monitor layer exists at all. Canonicalizing BOTH [monitorFor]'s
         * key AND the path [lockFileFor] derives the sidecar name from - by routing both through this
         * function - makes the two symlink-aliased [Path]s collapse onto the SAME monitor object too,
         * so the in-JVM `synchronized` layer actually serializes the two handles instead of both
         * reaching `channel.lock()` and one of them crashing. */
        private fun canonicalize(path: Path): Path {
            val parent = path.parent ?: return path.toAbsolutePath().normalize()
            return try {
                parent.toRealPath().resolve(path.fileName)
            } catch (e: IOException) {
                path.toAbsolutePath().normalize()
            }
        }

        /** The sidecar file whose OS-level lock [withExclusiveFileAccess] and [create] actually
         * hold - see [withExclusiveFileAccess]'s doc comment for why the lock cannot be taken on
         * the store file itself. `<file>.lock`, sitting beside the store file it guards - never
         * renamed, never replaced, never cleaned up (mirroring the store file's own lifetime).
         * [storeFile] is [canonicalize]d first - see that function's doc comment for why. */
        private fun lockFileFor(storeFile: Path): Path =
            canonicalize(storeFile).resolveSibling("${storeFile.fileName}.lock")

        /** Opens (creating on first use) the sidecar lock file for [storeFile] - read/write so
         * [FileChannel.lock] can take an exclusive lock on it. Applies this class's usual 0600
         * permission hardening on creation, when the filesystem supports it, matching every other
         * file this class writes; the lock file's CONTENTS are never read or written. */
        private fun lockChannelFor(storeFile: Path): FileChannel {
            val lockFile = lockFileFor(storeFile)
            val options = setOf(StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE)
            return if ("posix" in storeFile.fileSystem.supportedFileAttributeViews()) {
                FileChannel.open(lockFile, options, PosixFilePermissions.asFileAttribute(FILE_PERMISSIONS))
            } else {
                FileChannel.open(lockFile, options)
            }
        }

        private fun fileFor(
            baseDirectory: Path,
            label: String,
        ): Path {
            require(VALID_LABEL.matches(label)) {
                "invalid prekey store label '$label' - must match ${VALID_LABEL.pattern} (no path separators or traversal)"
            }
            return baseDirectory.resolve("$label.$PREKEY_STORE_FILE_EXTENSION")
        }

        /** Rejects [file] if group/other permission bits are set - the load-time tamper-evidence
         * mirror of `FileIdentityRepository.checkPermissionsAreHardened`'s identical check for
         * `.lnid` keystores, applied here to `.lnpk` prekey stores for the same reason: [create]/
         * [PrekeyStore.persistAtomically] always write 0600 files, so anything looser found at
         * [open] time is evidence of tampering or a misconfigured host, not a state this method
         * should silently trust with X3DH private key material. No-op on filesystems without POSIX
         * permission support (e.g. Windows) - mirrors every other permission check in this class. */
        private fun checkPermissionsAreHardened(file: Path) {
            if ("posix" !in file.fileSystem.supportedFileAttributeViews()) return
            val actual = Files.getPosixFilePermissions(file)
            val tooPermissive =
                actual.any {
                    it == PosixFilePermission.GROUP_READ ||
                        it == PosixFilePermission.GROUP_WRITE ||
                        it == PosixFilePermission.GROUP_EXECUTE ||
                        it == PosixFilePermission.OTHERS_READ ||
                        it == PosixFilePermission.OTHERS_WRITE ||
                        it == PosixFilePermission.OTHERS_EXECUTE
                }
            check(!tooPermissive) {
                "refusing to load prekey store file with loose permissions: $file (expected rw------- / 0600; " +
                    "run `chmod 600 $file`)"
            }
        }

        /** Creates a brand-new prekey store for [identity] under `<baseDirectory>/<label>.lnpk`.
         * Refuses to overwrite an existing file - a silent overwrite would destroy consumption
         * tombstones and re-enable one-time-prekey reuse.
         *
         * **The existence check and the initial write are performed under the same sidecar-file
         * lock [withExclusiveFileAccess] uses for every later mutation** (see that method's doc
         * comment for why the lock lives on a sidecar, not on [file] itself). Without this, two
         * concurrent [create] calls for the same label - or a [create] racing an already-open
         * [PrekeyStore] handle's writes - could both observe `!file.exists()` before either has
         * written, and the second call's write would then silently clobber the first's, destroying
         * whatever consumption tombstones the first store had already accumulated: exactly the
         * silent-overwrite this method's own `check` exists to prevent, just reached via a race
         * instead of a direct repeat call. */
        fun create(
            baseDirectory: Path,
            identity: DualKeyIdentity,
            label: String = IdentityRepository.DEFAULT_LABEL,
            oneTimePrekeyCount: Int = DEFAULT_ONE_TIME_PREKEY_COUNT,
            passphraseProvider: PassphraseProvider = PassphraseProvider { null },
            random: SecureRandom = SecureRandom(),
        ): PrekeyStore {
            Files.createDirectories(baseDirectory)
            if ("posix" in baseDirectory.fileSystem.supportedFileAttributeViews()) {
                Files.setPosixFilePermissions(baseDirectory, DIRECTORY_PERMISSIONS)
            }
            val file = fileFor(baseDirectory, label)
            return synchronized(monitorFor(file)) {
                lockChannelFor(file).use { lockChannel ->
                    lockChannel.lock().use {
                        check(!file.exists()) { "refusing to overwrite existing prekey store file $file" }

                        val x25519IdentityKeyPair = X25519KeyPair.generate(random)
                        val signedPrekeyKeyPair = X25519KeyPair.generate(random)
                        val oneTimeKeyPairs = (0 until oneTimePrekeyCount).map { X25519KeyPair.generate(random) }
                        val entries =
                            oneTimeKeyPairs.mapIndexed {
                                i,
                                kp,
                                ->
                                OneTimePrekeyStoreEntry(i, OneTimePrekeyState.AVAILABLE, kp.privateKey.bytes)
                            }

                        val initialState =
                            PrekeyStoreState(
                                ownerIdentity = identity.secp256k1KeyPair.publicKey,
                                x25519IdentityPrivateKeyBytes = x25519IdentityKeyPair.privateKey.bytes,
                                signedPrekeyId = 0,
                                signedPrekeyPrivateKeyBytes = signedPrekeyKeyPair.privateKey.bytes,
                                nextOneTimePrekeyId = oneTimePrekeyCount,
                                nextBundleSequenceNumber = INITIAL_BUNDLE_SEQUENCE_NUMBER,
                                entries = entries,
                            )
                        val store = PrekeyStore(file, passphraseProvider, initialState)
                        store.persistAtomically(initialState)
                        store
                    }
                }
            }
        }

        /** Loads an existing prekey store, or `null` if none exists at `<baseDirectory>/<label>.lnpk`.
         * Auto-migrates a legacy plaintext (v1) store to encrypted (v2) if [passphraseProvider]
         * supplies a real passphrase, mirroring `FileIdentityRepository.load`'s identical
         * idempotent migration.
         *
         * **The migration write itself goes through [withExclusiveFileAccess], never
         * `persistAtomically` on the lock-free snapshot read above.** That initial
         * `Files.readAllBytes` only decides WHETHER a migration is needed; the write that actually
         * happens re-reads and re-decodes disk truth INSIDE the same exclusive critical section
         * every mutator uses, and persists THAT re-read state, never the snapshot taken above.
         * Migrating from the lock-free snapshot would replay a possibly-already-stale entry list
         * over the file, silently erasing a tombstone a concurrently-open handle's
         * [consumeOneTimePrekey] persisted in the meantime - exactly the reuse that method's own doc
         * comment promises is impossible, via a sibling write path that promise didn't originally
         * cover.
         *
         * **Load-time POSIX permission tamper-evidence check, mirroring
         * `FileIdentityRepository.load`'s identical `checkPermissionsAreHardened` call for `.lnid`
         * keystores.** [create]/[persistAtomically] always write this file 0600 - so anything looser
         * found here is evidence of tampering, a misconfigured host, or a file that was copied/
         * restored without preserving permissions, none of which this method should silently trust
         * with X3DH private key material. Runs BEFORE [Files.readAllBytes], for the same
         * fail-loud-before-touching-the-bytes reasoning `FileIdentityRepository.load` applies. */
        fun open(
            baseDirectory: Path,
            label: String = IdentityRepository.DEFAULT_LABEL,
            passphraseProvider: PassphraseProvider = PassphraseProvider { null },
        ): PrekeyStore? {
            val file = fileFor(baseDirectory, label)
            if (!file.exists()) return null
            checkPermissionsAreHardened(file)
            val bytes = Files.readAllBytes(file)
            val passphrase = passphraseProvider.get()
            try {
                val state = PrekeyStoreFileFormat.decodeAuto(bytes, passphrase)
                val store = PrekeyStore(file, passphraseProvider, state)
                if (PrekeyStoreFileFormat.formatVersionOf(bytes) == PrekeyStoreFileFormat.FORMAT_VERSION_1 &&
                    passphrase != null
                ) {
                    logger.info { "migrating legacy v1 prekey store '$label' to encrypted v2 at rest" }
                    store.withExclusiveFileAccess { onDiskState ->
                        store.persistAtomically(onDiskState)
                        store.state = onDiskState
                    }
                }
                return store
            } finally {
                passphrase?.fill('\u0000')
            }
        }
    }
}

/** Re-exported so callers of this module do not also need to import
 * [net.lapisphilosophorum.lapisnet.identity.KeystoreDecryptionException] from `lapis-net-identity`
 * just to catch a wrong-passphrase failure from [PrekeyStore.open]. */
internal typealias PrekeyStoreDecryptionException = KeystoreDecryptionException
