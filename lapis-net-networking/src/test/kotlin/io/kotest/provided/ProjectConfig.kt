package io.kotest.provided

import io.kotest.core.config.AbstractProjectConfig
import io.kotest.core.extensions.Extension
import io.kotest.core.listeners.AfterSpecListener
import io.kotest.core.listeners.BeforeSpecListener
import io.kotest.core.spec.Spec
import net.lapisphilosophorum.lapisnet.networking.diag
import java.lang.management.ManagementFactory

/**
 * Only does something with `-PlapisDiag=true` (see [diag]): between specs, records the number of live
 * threads, the process CPU time and the heap in use, so a leak that makes later specs slower (nodes that
 * were never stopped, forwarding or sampler threads that keep running) shows up as a number that
 * grows from spec to spec.
 */
private object DiagSpecListener : BeforeSpecListener, AfterSpecListener {
    private fun snapshot(): String {
        val runtime = Runtime.getRuntime()
        val cpuNanos =
            (ManagementFactory.getOperatingSystemMXBean() as? com.sun.management.OperatingSystemMXBean)
                ?.processCpuTime
        return "threads=${Thread.getAllStackTraces().size} processCpu=${cpuNanos?.div(1_000_000)} ms " +
            "heapUsed=${(runtime.totalMemory() - runtime.freeMemory()) shr 20} MiB heapMax=${runtime.maxMemory() shr 20} MiB"
    }

    override suspend fun beforeSpec(spec: Spec) = diag { "BEFORE ${spec::class.simpleName}: ${snapshot()}" }

    override suspend fun afterSpec(spec: Spec) = diag { "AFTER  ${spec::class.simpleName}: ${snapshot()}" }
}

/** Kotest picks this class up by its fixed fully-qualified name `io.kotest.provided.ProjectConfig`. */
class ProjectConfig : AbstractProjectConfig() {
    override val extensions: List<Extension> = listOf(DiagSpecListener)
}
