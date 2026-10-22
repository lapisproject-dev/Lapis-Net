package net.lapisphilosophorum.lapisnet.onionwire

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.netty.buffer.ByteBuf
import io.netty.buffer.Unpooled
import io.netty.channel.embedded.EmbeddedChannel
import net.lapisphilosophorum.lapisnet.onion.OnionConstants.CELL_SIZE

class CellFrameDecoderTest :
    FunSpec({
        test("frames are cut at exactly 1024 bytes however the bytes arrive") {
            val ch = EmbeddedChannel(CellFrameDecoder(60_000))
            val data = ByteArray(CELL_SIZE * 3) { (it % 251).toByte() }
            // dribble in uneven pieces
            var off = 0
            val sizes = listOf(1, 1023, 1500, 7, 541)
            for (s in sizes) {
                ch.writeInbound(Unpooled.wrappedBuffer(data, off, s))
                off += s
            }
            val frames = generateSequence { ch.readInbound<ByteBuf>() }.toList()
            frames.size shouldBe 3
            frames.forEachIndexed { i, f ->
                val b = ByteArray(CELL_SIZE).also { f.readBytes(it) }
                b.contentEquals(data.copyOfRange(i * CELL_SIZE, (i + 1) * CELL_SIZE)) shouldBe true
                f.release()
            }
            ch.finishAndReleaseAll()
        }

        test("a started frame that does not complete closes the channel; a completed one does not") {
            val ch = EmbeddedChannel(CellFrameDecoder(100))
            ch.writeInbound(Unpooled.wrappedBuffer(ByteArray(10)))
            Thread.sleep(300)
            ch.runScheduledPendingTasks()
            ch.isOpen shouldBe false

            val ok = EmbeddedChannel(CellFrameDecoder(100))
            ok.writeInbound(Unpooled.wrappedBuffer(ByteArray(10)))
            ok.writeInbound(Unpooled.wrappedBuffer(ByteArray(CELL_SIZE - 10)))
            Thread.sleep(300)
            ok.runScheduledPendingTasks()
            ok.isOpen shouldBe true
            ok.finishAndReleaseAll()
        }
    })
