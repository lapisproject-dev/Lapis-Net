package net.lapisphilosophorum.lapisnet.browser

import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.Chain
import fr.acinq.bitcoin.PrivateKey
import fr.acinq.bitcoin.utils.Either
import fr.acinq.lightning.Feature
import fr.acinq.lightning.FeatureSupport
import fr.acinq.lightning.Features
import fr.acinq.lightning.MilliSatoshi
import fr.acinq.lightning.payment.Bolt11Invoice
import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.testing.testApplication
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
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
import net.lapisphilosophorum.lapisnet.virtus.LightningProofVerifier
import net.lapisphilosophorum.lapisnet.virtus.LtrGossip
import net.lapisphilosophorum.lapisnet.virtus.MAX_INITIAL_VALUE_MSAT
import java.nio.file.Files
import java.security.MessageDigest
import java.security.SecureRandom

private val json = Json { ignoreUnknownKeys = true }

private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

private fun ByteArray.toHexString(): String = joinToString("") { "%02x".format(it) }

private val INVOICE_FEATURES =
    Features(
        mapOf(
            Feature.VariableLengthOnion to FeatureSupport.Mandatory,
            Feature.PaymentSecret to FeatureSupport.Mandatory,
        ),
    )

/** A [BitcoinTimeAnchorSource] that always reports "not found", with zero real network I/O -
 * mirrors [BrowserApiRoutingTest]'s identically-named/-shaped private helper (not reusable across
 * files - each test file in this module keeps its own copy of this small fixture). */
private object LightningTestNoAnchorSource : BitcoinTimeAnchorSource {
    override fun findFirstOutgoingTransaction(pubkey: Secp256k1PublicKey): TimeAnchorLookupResult =
        TimeAnchorLookupResult.NotFound

    override fun currentChainTipHeight(): Int = 0
}

/** Mirrors [BrowserApiRoutingTest]'s private `TestHarness` - a single, never-connected [LapisNode]
 * plus every [BrowserApiDependencies] field, real signing/gossip/indexing, zero real network I/O. */
private class LightningTestHarness(
    val identity: DualKeyIdentity = DualKeyIdentity.generate(),
) {
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
        storage = NabuStorage.attach(node, Files.createTempDirectory("lightning-ltr-endpoint-test"))
        pubsub = GossipPubSub.attach(node)
        veritas = VeritasGossip.attach(pubsub, storage)
        virtus = LtrGossip.attach(pubsub, storage)
        karma = KarmaGossip.attach(pubsub, storage)
        posts = PostAnnouncementGossip.attach(pubsub, storage)
        karmaAnchorCache = KarmaAnchorCache(LightningTestNoAnchorSource)
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

private fun testCid(seed: Byte): Cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { seed })

/** Builds a real, cryptographically valid `(preimage, signedInvoice)` pair for [viewId] and [cid] -
 * exactly what an author who paid a real BOLT-11 invoice with their own wallet, out-of-band, would
 * submit to `POST /api/ltr/lightning`. Mirrors [LightningProofVerifierTest]'s `ValidTuple`
 * construction (same scalar for both the Lapis viewId and the ACINQ Lightning node key). */
private fun validPreimageAndInvoice(
    cid: Cid,
    viewId: Secp256k1KeyPair,
    amountMsat: Long,
): Pair<ByteArray, String> {
    val preimage = ByteArray(32).also { SecureRandom().nextBytes(it) }
    val paymentHash = sha256(preimage)
    val memo = LightningProofVerifier.canonicalMemo(cid, viewId.publicKey)
    val invoice =
        Bolt11Invoice
            .create(
                chain = Chain.Mainnet,
                amount = MilliSatoshi(amountMsat),
                paymentHash = ByteVector32(paymentHash),
                privateKey = PrivateKey(viewId.privateKey.bytes),
                description = Either.Left(memo),
                minFinalCltvExpiryDelta = Bolt11Invoice.DEFAULT_MIN_FINAL_EXPIRY_DELTA,
                features = INVOICE_FEATURES,
            ).write()
    return preimage to invoice
}

class LightningLtrEndpointTest :
    FunSpec({
        test(
            "POST /api/ltr/lightning with a valid (preimage, signedInvoice) pair succeeds, is reflected " +
                "in the record count, and echoes the invoice's own amount",
        ) {
            val harness = LightningTestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }

                    val viewId = Secp256k1KeyPair.generate()
                    val cid = testCid(1)
                    val amountMsat = 3_000_000L
                    val (preimage, invoice) = validPreimageAndInvoice(cid, viewId, amountMsat)

                    val response =
                        client.post("/api/ltr/lightning") {
                            contentType(ContentType.Application.Json)
                            setBody(
                                json.encodeToString(
                                    NewLightningLtrRequest(
                                        cid = cid.toString(),
                                        viewIdHex = viewId.publicKey.bytes.toHexString(),
                                        preimageHex = preimage.toHexString(),
                                        signedInvoice = invoice,
                                    ),
                                ),
                            )
                        }

                    response.status shouldBe HttpStatusCode.OK
                    val body = json.decodeFromString<NewLightningLtrResponse>(response.bodyAsText())
                    body.cid shouldBe cid.toString()
                    body.initialValueMsat shouldBe amountMsat
                    body.ltrRecordCount shouldBe 1
                }
            } finally {
                harness.stop()
            }
        }

        test("POST /api/ltr/lightning with a crypto-invalid proof (wrong signer) returns 400") {
            val harness = LightningTestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }

                    val viewId = Secp256k1KeyPair.generate()
                    val otherSigner = Secp256k1KeyPair.generate()
                    val cid = testCid(1)
                    val amountMsat = 3_000_000L
                    // Signed by otherSigner, not viewId - fails the mandatory recipient-binding check.
                    val (preimage, invoice) = validPreimageAndInvoice(cid, otherSigner, amountMsat)

                    val response =
                        client.post("/api/ltr/lightning") {
                            contentType(ContentType.Application.Json)
                            setBody(
                                json.encodeToString(
                                    NewLightningLtrRequest(
                                        cid = cid.toString(),
                                        viewIdHex = viewId.publicKey.bytes.toHexString(),
                                        preimageHex = preimage.toHexString(),
                                        signedInvoice = invoice,
                                    ),
                                ),
                            )
                        }

                    response.status shouldBe HttpStatusCode.BadRequest
                    val body = json.decodeFromString<ErrorResponse>(response.bodyAsText())
                    body.error.isNotBlank() shouldBe true
                }
            } finally {
                harness.stop()
            }
        }

        test("POST /api/ltr/lightning with a malformed cid returns 400, not a crash") {
            val harness = LightningTestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }

                    val response =
                        client.post("/api/ltr/lightning") {
                            contentType(ContentType.Application.Json)
                            setBody(
                                json.encodeToString(
                                    NewLightningLtrRequest(
                                        cid = "not-a-real-cid",
                                        viewIdHex =
                                            Secp256k1KeyPair
                                                .generate()
                                                .publicKey.bytes
                                                .toHexString(),
                                        preimageHex = ByteArray(32).toHexString(),
                                        signedInvoice = "lnbc1x",
                                    ),
                                ),
                            )
                        }

                    response.status shouldBe HttpStatusCode.BadRequest
                }
            } finally {
                harness.stop()
            }
        }

        test("POST /api/ltr/lightning with a malformed viewIdHex returns 400, not a crash") {
            val harness = LightningTestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }

                    val response =
                        client.post("/api/ltr/lightning") {
                            contentType(ContentType.Application.Json)
                            setBody(
                                json.encodeToString(
                                    NewLightningLtrRequest(
                                        cid = testCid(1).toString(),
                                        viewIdHex = "not-hex",
                                        preimageHex = ByteArray(32).toHexString(),
                                        signedInvoice = "lnbc1x",
                                    ),
                                ),
                            )
                        }

                    response.status shouldBe HttpStatusCode.BadRequest
                }
            } finally {
                harness.stop()
            }
        }

        // --- C1 fix: one real payment must not mint unbounded LTR weight via repeat POSTs -------

        test(
            "POSTing the identical (preimage, signedInvoice) pair twice succeeds the first time and returns " +
                "400 the second time - the record count never exceeds 1",
        ) {
            val harness = LightningTestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }

                    val viewId = Secp256k1KeyPair.generate()
                    val cid = testCid(1)
                    val amountMsat = 3_000_000L
                    val (preimage, invoice) = validPreimageAndInvoice(cid, viewId, amountMsat)
                    val requestBody =
                        json.encodeToString(
                            NewLightningLtrRequest(
                                cid = cid.toString(),
                                viewIdHex = viewId.publicKey.bytes.toHexString(),
                                preimageHex = preimage.toHexString(),
                                signedInvoice = invoice,
                            ),
                        )

                    val first =
                        client.post("/api/ltr/lightning") {
                            contentType(ContentType.Application.Json)
                            setBody(requestBody)
                        }
                    val second =
                        client.post("/api/ltr/lightning") {
                            contentType(ContentType.Application.Json)
                            setBody(requestBody)
                        }

                    first.status shouldBe HttpStatusCode.OK
                    val firstBody = json.decodeFromString<NewLightningLtrResponse>(first.bodyAsText())
                    firstBody.ltrRecordCount shouldBe 1

                    second.status shouldBe HttpStatusCode.BadRequest
                    val secondBody = json.decodeFromString<ErrorResponse>(second.bodyAsText())
                    secondBody.error.isNotBlank() shouldBe true

                    // The record count for this (cid, viewId) must still be exactly 1 - the second
                    // POST must not have minted a second unit of weight from the one real payment.
                    harness.virtus.currentRecords(cid, viewId.publicKey) shouldHaveSize 1
                }
            } finally {
                harness.stop()
            }
        }

        // --- MINOR fix: an oversized invoice amount must fail with a clean 400, not a 500 -------

        test(
            "POST /api/ltr/lightning with an invoice amount above MAX_INITIAL_VALUE_MSAT returns a clean " +
                "400, not an unsanitized 500",
        ) {
            val harness = LightningTestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }

                    val viewId = Secp256k1KeyPair.generate()
                    val cid = testCid(1)
                    // A BOLT-11 invoice's own amount decoder has no upper bound - this legally
                    // encodes a value above LtrRecord's MIN..MAX_INITIAL_VALUE_MSAT range (well
                    // within Long range, so no arithmetic overflow here - just outside the
                    // protocol-level supply-cap range LtrRecord.create enforces).
                    val oversizedAmountMsat = MAX_INITIAL_VALUE_MSAT + 1_000_000_000L
                    val (preimage, invoice) = validPreimageAndInvoice(cid, viewId, oversizedAmountMsat)

                    val response =
                        client.post("/api/ltr/lightning") {
                            contentType(ContentType.Application.Json)
                            setBody(
                                json.encodeToString(
                                    NewLightningLtrRequest(
                                        cid = cid.toString(),
                                        viewIdHex = viewId.publicKey.bytes.toHexString(),
                                        preimageHex = preimage.toHexString(),
                                        signedInvoice = invoice,
                                    ),
                                ),
                            )
                        }

                    response.status shouldBe HttpStatusCode.BadRequest
                    val body = json.decodeFromString<ErrorResponse>(response.bodyAsText())
                    body.error.isNotBlank() shouldBe true
                }
            } finally {
                harness.stop()
            }
        }

        test("POST /api/ltr/lightning with a malformed preimageHex returns 400, not a crash") {
            val harness = LightningTestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }

                    val response =
                        client.post("/api/ltr/lightning") {
                            contentType(ContentType.Application.Json)
                            setBody(
                                json.encodeToString(
                                    NewLightningLtrRequest(
                                        cid = testCid(1).toString(),
                                        viewIdHex =
                                            Secp256k1KeyPair
                                                .generate()
                                                .publicKey.bytes
                                                .toHexString(),
                                        preimageHex = "not-hex",
                                        signedInvoice = "lnbc1x",
                                    ),
                                ),
                            )
                        }

                    response.status shouldBe HttpStatusCode.BadRequest
                }
            } finally {
                harness.stop()
            }
        }
    })
