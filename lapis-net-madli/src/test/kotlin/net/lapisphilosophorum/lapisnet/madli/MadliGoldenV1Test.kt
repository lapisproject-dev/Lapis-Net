package net.lapisphilosophorum.lapisnet.madli

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerId
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair

private const val GOLDEN_V1_HEX =
    "4c4e4d56010284bf7562262bbd6940085748f3be6afa52ae317155181ece31b66351ccffa4b0002207070707070707070707" +
        "0707070707070707070707070707070707070707070707070000000000004e200007a120000000000098968000000032000d" +
        "bba0000aae600000000a01ce8aa510e60e08378e495e096e79902a88fa5e5f6fac1bd6345d629d33ac2a4a16eb30f7c99483" +
        "46f06a94bf4d9c6241949add83f0fb1a046fa9fbd4e4db35"
private const val GOLDEN_V1_CID = "c593cee6f1d9ef99e8de06ee8def8cfb1136b21d3c898683d62f9a31c4fccee9"

private fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }

/**
 * Golden regression test for the v1 wire format. The hex was generated on master (v0.10.1) BEFORE
 * the v2 codec change; the v1 encoding must remain byte-identical forever, otherwise content ids of
 * persisted vectors and gossip deduplication break.
 */
class MadliGoldenV1Test :
    FunSpec({
        val keyPair = Secp256k1KeyPair.fromPrivateKeyBytes(ByteArray(32) { (it + 1).toByte() })
        val vector =
            MadliDailyVector.create(
                keyPair,
                PeerId(ByteArray(34) { 7 }),
                20_000L,
                MadliMetrics(500_000, 10_000_000L, 50, 900_000, 700_000, 10),
            )

        test("v1 encoding is byte-identical to the golden vector generated on v0.10.1") {
            MadliDailyVectorCodec.encode(vector).hex() shouldBe GOLDEN_V1_HEX
            vector.contentId().hex() shouldBe GOLDEN_V1_CID
        }

        test("the golden v1 bytes still decode and verify") {
            val bytes = GOLDEN_V1_HEX.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            val decoded = MadliDailyVectorCodec.decode(bytes)
            decoded shouldBe vector
            MadliDailyVector.verify(decoded) shouldBe true
        }
    })
