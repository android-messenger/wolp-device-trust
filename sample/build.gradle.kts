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
    // without an NDK here native libraries ship unstripped: libsignal_jni.so is 125 MB per ABI
    ndkVersion = "28.2.13676358"

    defaultConfig {
        applicationId = "org.wolpmessenger.devicetrust.sample"
        minSdk = 33
        targetSdk = 35
        versionCode = 10300
        versionName = "1.3.0-sample"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
    buildFeatures { compose = true }
    // libsignal (specs/002, FR-035): its AAR requires desugaring; it also brings a test-only native
    // library and, in its jar, builds for Linux, macOS and Windows — tens of megabytes an APK does not need
    packaging {
        jniLibs.excludes += "**/libsignal_jni_testing.so"
        resources.excludes += listOf("libsignal_jni*.so", "libsignal_jni*.dylib", "signal_jni*.dll")
    }
    compileOptions {
        isCoreLibraryDesugaringEnabled = true
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
    coreLibraryDesugaring(libs.desugar.jdk.libs)
    implementation(libs.kotlinx.coroutines.android)
    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.material3)
    implementation(libs.activity.compose)

    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.ext.junit)
}
