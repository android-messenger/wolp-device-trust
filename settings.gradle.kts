pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        // libsignal is published only here; nothing else may resolve from it
        maven("https://build-artifacts.signal.org/libraries/maven/") {
            content { includeGroup("org.signal") }
        }
    }
}
rootProject.name = "wolp-device-trust"
include(":devicetrust", ":sample", ":pilot")
