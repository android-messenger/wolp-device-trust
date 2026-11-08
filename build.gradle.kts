plugins {
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.android) apply false
    alias(libs.plugins.kotlin.compose) apply false
}

// S2 §15 п. 1: Firebase и Google Play Services не должны попасть в дерево зависимостей библиотеки.
tasks.register("checkForbiddenDependencies") {
    group = "verification"
    description = "Fails if Firebase or Google Play Services appear in :devicetrust runtime dependencies"
    val runtime = project(":devicetrust").configurations.named("releaseRuntimeClasspath")
    inputs.files(runtime)
    doLast {
        val forbidden = runtime.get().incoming.resolutionResult.allComponents
            .mapNotNull { it.moduleVersion }
            .filter { it.group.startsWith("com.google.firebase") || it.group.startsWith("com.google.android.gms") }
        check(forbidden.isEmpty()) { "Forbidden dependencies in :devicetrust: $forbidden" }
        logger.lifecycle("checkForbiddenDependencies: OK")
    }
}
