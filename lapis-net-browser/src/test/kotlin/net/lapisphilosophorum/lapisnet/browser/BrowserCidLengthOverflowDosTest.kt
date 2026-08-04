package net.lapisphilosophorum.lapisnet.browser

import io.ipfs.cid.Cid
import io.ipfs.multibase.Base58
import io.ipfs.multibase.Multibase
import io.ipfs.multihash.Multihash
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.longs.shouldBeLessThan
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.testing.testApplication
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import net.lapisphilosophorum.lapisnet.core.cid.CidBytesValidation
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.karma.BitcoinTimeAnchorSource
import net.lapisphilosophorum.lapisnet.karma.KarmaGossip
import net.lapisphilosophorum.lapisnet.karma.TimeAnchorLookupResult
import net.lapisphilosophorum.lapisnet.mail.InboxGossip
import net.lapisphilosophorum.lapisnet.mail.MailSender
import net.lapisphilosophorum.lapisnet.mail.SentFolder
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import net.lapisphilosophorum.lapisnet.trust.VeritasGossip
import net.lapisphilosophorum.lapisnet.virtus.LtrGossip
import java.io.ByteArrayOutputStream
import java.nio.file.Files

private val json = Json { ignoreUnknownKeys = true }

/**
 * Same wall-clock discipline as [net.lapisphilosophorum.lapisnet.mail.MailCidLengthOverflowDosTest]
 * - generous headroom above a plain allocation-free varint parse, far below what an unbounded
 * `new byte[0x7FFFFFFF]` allocation attempt costs.
 */
private const val MAX_ALLOWED_MILLIS = 5_000L

private fun elapsedMillis(block: () -> Unit): Long {
    val start = System.nanoTime()
    block()
    return (System.nanoTime() - start) / 1_000_000
}

/** Mirrors `io.ipfs.multihash.Multihash.putUvarint`/`readVarint`'s exact LEB128 semantics - see
 * [net.lapisphilosophorum.lapisnet.mail.MailCidLengthOverflowDosTest]'s identical helper. */
private fun writeVarint(
    out: ByteArrayOutputStream,
    value: Long,
) {
    var x = value
    while (x < 0 || x >= 0x80) {
        out.write(((x and 0x7f) or 0x80).toInt())
        x = x ushr 7
    }
    out.write(x.toInt())
}

/** Hand-builds a candidate CID byte array - `version(varint) | codec(varint) | multihash-
 * type(varint) | multihash-length(varint)` - that declares [declaredMultihashLength] but supplies
 * NO actual hash bytes after it. Identical shape to
 * [net.lapisphilosophorum.lapisnet.mail.MailCidLengthOverflowDosTest]'s `maliciousCidBytes`: CID
 * version 1, codec Raw (`0x55`), multihash type sha2_256 (`0x12`). */
private fun maliciousCidBytes(declaredMultihashLength: Long): ByteArray {
    val sha2256TypeIndex = Multihash.Type.sha2_256.index
    val out = ByteArrayOutputStream()
    writeVarint(out, 1) // CID version 1
    writeVarint(out, 0x55) // codec Raw
    writeVarint(out, sha2256TypeIndex.toLong()) // multihash type
    writeVarint(out, declaredMultihashLength) // multihash length - the attack payload
    return out.toByteArray()
}

/** The multibase-encoded (base32, `Multibase.decode`'s common path) string form of
 * [maliciousCidBytes] - what an attacker would actually send as `targetCid`/`cid` in a request
 * body, or as the `{cid}` path segment of `GET /api/mail/thread/{cid}` /
 * `GET /api/mail/attachment/{cid}`. */
private fun maliciousMultibaseCidString(declaredMultihashLength: Long): String =
    Multibase.encode(Multibase.Base.Base32, maliciousCidBytes(declaredMultihashLength))

private fun testCid(seed: Byte): Cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { seed })

private object CidOverflowTestNoAnchorSource : BitcoinTimeAnchorSource {
    override fun findFirstOutgoingTransaction(pubkey: Secp256k1PublicKey): TimeAnchorLookupResult =
        TimeAnchorLookupResult.NotFound

    override fun currentChainTipHeight(): Int = 0
}

/** Minimal single-node harness - mirrors [BrowserApiRoutingTest]'s `TestHarness`, trimmed to only
 * what `POST /api/karma` needs to exercise [parseCidOrNull] end to end through a real route. */
private class MinimalHarness {
    val identity: DualKeyIdentity = DualKeyIdentity.generate()
    val node: LapisNode = LapisNode.create(identity)
    val storage: NabuStorage
    val pubsub: GossipPubSub
    val veritas: VeritasGossip
    val virtus: LtrGossip
    val karma: KarmaGossip
    val posts: PostAnnouncementGossip
    val karmaAnchorCache: KarmaAnchorCache
    val mailInbox: InboxGossip
    val mailSender: MailSender
    val sentFolder: SentFolder
    val deps: BrowserApiDependencies

    init {
        node.start(bootstrapPeers = emptyList())
        storage = NabuStorage.attach(node, Files.createTempDirectory("browser-cid-overflow-dos"))
        pubsub = GossipPubSub.attach(node)
        veritas = VeritasGossip.attach(pubsub, storage)
        virtus = LtrGossip.attach(pubsub, storage)
        karma = KarmaGossip.attach(pubsub, storage)
        posts = PostAnnouncementGossip.attach(pubsub, storage)
        karmaAnchorCache = KarmaAnchorCache(CidOverflowTestNoAnchorSource)
        mailInbox = InboxGossip.attach(pubsub, storage, identity.secp256k1KeyPair.publicKey)
        mailSender = MailSender(pubsub, storage)
        sentFolder = SentFolder()
        deps =
            BrowserApiDependencies(
                identity,
                node,
                storage,
                veritas,
                virtus,
                karma,
                posts,
                karmaAnchorCache,
                mailInbox,
                mailSender,
                sentFolder,
            )
    }

    fun stop() {
        mailInbox.stop()
        posts.stop()
        karma.stop()
        virtus.stop()
        veritas.stop()
        pubsub.stop()
        storage.stop()
        runCatching { node.stop() }
    }
}

/**
 * Regression test for a MAJOR, auditor-confirmed gap in `lapis-net-browser`: unlike every other
 * CID-decoding call site in this project (`MessageEnvelopeCodec`, `MessageBodyCodec`,
 * `LtrRecordCodec`, `KarmaVoteCodec`, `VeritasGrantCodec`, all guarded by [CidBytesValidation]),
 * [parseCidOrNull] called `io.ipfs.cid.Cid.decode(String)` directly - which internally does
 * `Multibase.decode(v)` then `Cid.cast(data)`, the identical unguarded `Multihash.deserialize`'s
 * `byte[] hash = new byte[len]`-before-bound-check construct this whole wave exists to close.
 * Reachable via `POST /api/karma` (`targetCid`), `POST /api/ltr/lightning` (`cid`), and `GET
 * /api/mail/thread/{cid}` / `GET /api/mail/attachment/{cid}` - all of it before any signature
 * check, on a server bound to `127.0.0.1` with no CORS plugin installed, so any webpage the user's
 * browser visits while the node is running could trigger it with a plain cross-origin request.
 * Fixed by making [parseCidOrNull] decode the multibase/base58 bytes itself and run them through
 * [CidBytesValidation] before ever calling `Cid.cast`/`Multihash.deserialize` - see that function's
 * doc comment for the two guarded paths.
 */
class BrowserCidLengthOverflowDosTest :
    FunSpec({
        val maliciousLengths = listOf(0x7FFFFFFFL, 1_073_741_824L)

        maliciousLengths.forEach { declaredLength ->
            test("parseCidOrNull rejects a multibase-encoded CID declaring multihash length $declaredLength") {
                val value = maliciousMultibaseCidString(declaredLength)
                val elapsed = elapsedMillis { parseCidOrNull(value).shouldBeNull() }
                elapsed shouldBeLessThan MAX_ALLOWED_MILLIS
            }
        }

        test("parseCidOrNull accepts a genuine multibase-encoded CIDv1 sha2-256 string") {
            parseCidOrNull(testCid(1).toString()).shouldNotBeNull()
        }

        test("parseCidOrNull accepts a genuine legacy base58 CIDv0 (\"Qm...\") string") {
            val v0 = Cid.buildV0(Multihash(Multihash.Type.sha2_256, ByteArray(32) { 7 }))
            val encoded = v0.toString()
            encoded.length shouldBe 46
            encoded.startsWith("Qm") shouldBe true
            parseCidOrNull(encoded).shouldNotBeNull()
        }

        test("parseCidOrNull rejects garbage input without throwing") {
            parseCidOrNull("not a cid at all").shouldBeNull()
            parseCidOrNull("").shouldBeNull()
            parseCidOrNull("Qm" + "x".repeat(44)).shouldBeNull() // 46 chars, "Qm"-prefixed, invalid base58 shape
        }

        // Defense-in-depth coverage for io.ipfs.cid.Cid.decode(String)'s OTHER unguarded path - the
        // legacy CIDv0 shortcut (Multihash.fromBase58, bypassing Cid.cast entirely) - exercised
        // directly against the raw bytes rather than a base58 string: a 46-character, "Qm"-prefixed
        // base58 string's decoded byte count is tightly coupled to its numeric magnitude (see
        // CidBytesValidation.isSafeToDeserializeMultihash's doc comment), so a multi-gigabyte
        // declared length cannot be embedded in that particular string shape - but parseCidOrNull's
        // legacy branch is guarded unconditionally, on the same footing as every other call site,
        // rather than relying on that magnitude coupling to hold forever.
        test("Base58.decode of a well-formed CIDv0 multihash round-trips through the legacy branch guard") {
            val v0 = Cid.buildV0(Multihash(Multihash.Type.sha2_256, ByteArray(32) { 9 }))
            val decoded = Base58.decode(v0.toString())
            CidBytesValidation.isSafeToDeserializeMultihash(decoded) shouldBe true
        }

        test(
            "end-to-end: POST /api/karma rejects a length-overflow targetCid with 400, never crashes",
        ) {
            val harness = MinimalHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }

                    val start = System.nanoTime()
                    val response =
                        client.post("/api/karma") {
                            contentType(ContentType.Application.Json)
                            setBody(
                                json.encodeToString(
                                    NewKarmaVoteRequest(maliciousMultibaseCidString(0x7FFFFFFFL)),
                                ),
                            )
                        }
                    val elapsed = (System.nanoTime() - start) / 1_000_000
                    response.status shouldBe HttpStatusCode.BadRequest
                    response.bodyAsText().isNotBlank() shouldBe true
                    elapsed shouldBeLessThan MAX_ALLOWED_MILLIS

                    // Confirms the server process is still alive and serving other routes - the
                    // strongest evidence the malicious request above didn't crash/OOM the JVM.
                    val identityResponse = client.get("/api/identity")
                    identityResponse.status shouldBe HttpStatusCode.OK
                }
            } finally {
                harness.stop()
            }
        }
    })
