package net.lapisphilosophorum.lapisnet.browser

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.networking.config.AnonymityMode
import net.lapisphilosophorum.lapisnet.networking.config.NodeWiringOptions
import net.lapisphilosophorum.lapisnet.networking.dcutr.HolePunchMode
import java.nio.file.Files
import kotlin.time.Duration.Companion.seconds

/** Wave Q21: what `BrowserServer.start` wires for attachments over circuits. */
class AnonymousAttachmentWiringTest :
    FunSpec({
        test("normal mode: no attachment service and no fetcher exist").config(timeout = 90.seconds) {
            val server = startWiredTestServer()
            try {
                server.attachmentServerForTesting.shouldBeNull()
                server.anonymousAttachmentsForTesting.shouldBeNull()
            } finally {
                server.stop()
            }
        }

        test("anonymity mode: the service and the fetcher exist; the service is closed with the server").config(
            timeout = 120.seconds,
        ) {
            val config =
                BrowserConfig(NodeWiringOptions(anonymity = AnonymityMode.ON, holePunching = HolePunchMode.OFF))
            val server = startWiredTestServer(config = config, dataDirectory = Files.createTempDirectory("q21-anon"))
            val service =
                try {
                    server.anonymousAttachmentsForTesting.shouldNotBeNull()
                    server.attachmentServerForTesting.shouldNotBeNull()
                } finally {
                    server.stop()
                }
            service.stats().openStreams shouldBe 0
        }
    })
