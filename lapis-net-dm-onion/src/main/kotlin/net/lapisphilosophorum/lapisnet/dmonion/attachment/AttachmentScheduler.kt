package net.lapisphilosophorum.lapisnet.dmonion.attachment

import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit

/** A scheduled task that can be cancelled. */
fun interface AttachmentTimer {
    fun cancel()
}

/**
 * The single timer thread of an attachment server or client, a seam so that tests drive time by hand. Tasks run one at a
 * time, in order of their due time. [schedule] returns `null` once the scheduler is shut down.
 */
interface AttachmentScheduler : AutoCloseable {
    fun nowMillis(): Long

    fun schedule(
        delayMillis: Long,
        task: () -> Unit,
    ): AttachmentTimer?

    companion object {
        /** The production scheduler: one daemon thread named [threadName], wall clock. */
        fun singleThread(threadName: String): AttachmentScheduler = ExecutorAttachmentScheduler(threadName)
    }
}

private class ExecutorAttachmentScheduler(
    threadName: String,
) : AttachmentScheduler {
    private val executor: ScheduledExecutorService =
        Executors.newSingleThreadScheduledExecutor { r -> Thread(r, threadName).apply { isDaemon = true } }

    override fun nowMillis(): Long = System.currentTimeMillis()

    override fun schedule(
        delayMillis: Long,
        task: () -> Unit,
    ): AttachmentTimer? =
        try {
            val future = executor.schedule({ runCatching(task) }, maxOf(0L, delayMillis), TimeUnit.MILLISECONDS)
            AttachmentTimer { future.cancel(false) }
        } catch (e: RejectedExecutionException) {
            null
        }

    override fun close() {
        executor.shutdownNow()
    }
}
