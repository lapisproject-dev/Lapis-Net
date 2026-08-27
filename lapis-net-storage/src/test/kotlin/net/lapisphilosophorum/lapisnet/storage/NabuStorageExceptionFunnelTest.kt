package net.lapisphilosophorum.lapisnet.storage

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions

/**
 * Regression test for the exception-funnel gap `awaitOrWrap` had for a SYNCHRONOUS throw: Nabu's
 * `FileBlockstore.put` catches a local `IOException` (disk full, permission denied, read-only
 * filesystem) itself and rethrows it as a bare `RuntimeException` on the CALLING thread -
 * `Files.write`/`Files.createDirectories` fail before a `CompletableFuture` is ever produced, the
 * exception is thrown while evaluating `awaitOrWrap`'s `block()` argument, not while waiting on
 * its result. `awaitOrWrap`'s try/catch previously only caught `TimeoutException`/
 * `ExecutionException`/`InterruptedException` - the failure modes `.get()` on an
 * already-returned future can produce - so that bare `RuntimeException` propagated straight out of
 * [NabuStorage.put] unwrapped, breaking every gossip validator's "persist, catch
 * `NabuStorageException`, release reservation + reject" contract (see e.g.
 * `net.lapisphilosophorum.lapisnet.dm.MailboxGossip.onGossipMessage`).
 *
 * Mirrors `net.lapisphilosophorum.lapisnet.ratchet.PrekeyStoreTest`'s established technique of
 * forcing a genuine local I/O failure via `Files.setPosixFilePermissions` on a real filesystem
 * path rather than mocking - here applied to a directory (`r-xr-xr-x`, no write access) instead
 * of PrekeyStoreTest's file (`rw-r--r--`), since the failure this test targets is
 * `Files.createDirectories` being denied under a read-only parent - this reproduces the exact
 * synchronous-throw scenario, not merely its symptom.
 */
class NabuStorageExceptionFunnelTest :
    FunSpec({
        test("put on a read-only blockstore directory throws NabuStorageException, not a raw RuntimeException") {
            val node = LapisNode.create(DualKeyIdentity.generate())
            node.start(bootstrapPeers = emptyList())
            try {
                val blockstoreDir = Files.createTempDirectory("nabu-storage-exception-funnel-test")
                val storage = NabuStorage.attach(node, blockstoreDir)
                // FileBlockstore.attach() already created this "blocks" subdirectory - see
                // FileBlockstore's constructor. Every put() writes under it.
                val blocksDir = blockstoreDir.resolve("blocks")
                if ("posix" !in blocksDir.fileSystem.supportedFileAttributeViews()) return@test

                // Strip write access on the blocks root itself. FileBlockstore.put shards each
                // block under a 2-character subdirectory of "blocks" (derived from the block's own
                // hash) that does not exist yet for a fresh directory - so Files.createDirectories
                // must create a new entry inside "blocks", which now fails with an
                // AccessDeniedException. (FileBlockstore.put's own self-heal logic only tries to
                // fix write permissions on directories BELOW "blocks", never on "blocks" itself -
                // verified against the resolved nabu-v0.8.0 jar's decompiled bytecode - so this
                // genuinely fails rather than being silently repaired.)
                Files.setPosixFilePermissions(blocksDir, PosixFilePermissions.fromString("r-xr-xr-x"))
                try {
                    val exception =
                        shouldThrow<NabuStorageException> {
                            storage.put("this write must fail - the directory is read-only".toByteArray())
                        }
                    exception.message shouldBe "failed to put block"
                    // The original IOException-derived RuntimeException from FileBlockstore.put is
                    // preserved as the cause, not swallowed.
                    exception.cause.shouldNotBeNull()
                } finally {
                    // Restore write access so temp-directory cleanup doesn't itself fail.
                    Files.setPosixFilePermissions(blocksDir, PosixFilePermissions.fromString("rwxr-xr-x"))
                }
            } finally {
                node.stop()
            }
        }
    })
