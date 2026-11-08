// Exports real attestation chains with known challenges for the gateway tests (S2 §13, S3 §6.5).
// Run with tools/export-testvectors.sh on each device of the matrix.
plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "org.wolpmessenger.testvectors"
    compileSdk = 36

    defaultConfig {
        applicationId = "org.wolpmessenger.testvectors"
        minSdk = 33
        targetSdk = 35
        versionCode = 10300
        versionName = "1.3.0-testvectors"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        optIn.add("org.wolpmessenger.devicetrust.InternalDeviceTrustApi")
    }
}

dependencies {
    implementation(project(":devicetrust"))
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.ext.junit)
}
