package net.lapisphilosophorum.lapisnet.networking.transport

import java.net.StandardSocketOptions
import java.nio.channels.ServerSocketChannel
import java.nio.channels.SocketChannel

/**
 * Whether the running JDK/OS can bind several sockets to one TCP port (`SO_REUSEPORT`), which the
 * hole-punching transport needs: the outgoing dial must leave from the very port the node listens
 * on, or the NAT mapping a relay observes is not the one a punch can use.
 *
 * Linux: supported. macOS: supported by the JDK, but not verified by this project. Windows: the JDK
 * does not offer the option, so hole punching is simply unavailable there.
 */
internal object ReusePortSupport {
    val available: Boolean by lazy {
        runCatching {
            SocketChannel.open().use { it.supportedOptions().contains(StandardSocketOptions.SO_REUSEPORT) } &&
                ServerSocketChannel.open().use { it.supportedOptions().contains(StandardSocketOptions.SO_REUSEPORT) }
        }.getOrDefault(false)
    }

    fun describeUnavailability(): String =
        "SO_REUSEPORT is not supported by this JDK/OS (os.name=${System.getProperty("os.name")})"
}
