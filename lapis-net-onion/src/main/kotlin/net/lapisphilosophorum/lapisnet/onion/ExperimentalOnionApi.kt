package net.lapisphilosophorum.lapisnet.onion

/**
 * Marks client-side circuit APIs and diagnostic hooks that must not be used by production code
 * until the path-selection and traffic policy of wave E exists. Using them anywhere (tests
 * included) requires an explicit `@OptIn(ExperimentalOnionApi::class)`, so no feature can start
 * sending user traffic over a hand-picked circuit by accident.
 */
@RequiresOptIn(
    message = "Experimental onion API: infrastructure only, no anonymity guarantees; see docs/anonymity.adoc",
    level = RequiresOptIn.Level.ERROR,
)
@Retention(AnnotationRetention.BINARY)
@Target(AnnotationTarget.CLASS, AnnotationTarget.FUNCTION, AnnotationTarget.PROPERTY, AnnotationTarget.CONSTRUCTOR)
annotation class ExperimentalOnionApi
