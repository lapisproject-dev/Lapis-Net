package net.lapisphilosophorum.lapisnet.cli

import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.core.spec.style.FunSpec
import kotlin.time.Duration.Companion.seconds

class LapisNetCliTest :
    FunSpec({
        test("main runs the full identity/storage/multi-node demo without throwing").config(timeout = 120.seconds) {
            shouldNotThrowAny { main(emptyArray()) }
        }
    })
