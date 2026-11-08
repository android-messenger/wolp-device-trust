// Demo and diagnostics app (S2 §2 `sample/`): precheck, attestation, Keystore/Vault measurements,
// test-vector export and a shareable report — runnable on any phone without the gateway.
plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "org.wolpmessenger.devicetrust.sample"
    compileSdk = 36

    defaultConfig {
        applicationId = "org.wolpmessenger.devicetrust.sample"
        minSdk = 33
        targetSdk = 35
        versionCode = 10300
        versionName = "1.3.0-sample"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
    buildFeatures { compose = true }
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
    implementation(libs.kotlinx.coroutines.android)
    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.material3)
    implementation(libs.activity.compose)

    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.ext.junit)
}
