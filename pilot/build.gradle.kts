// Pilot build reference (S2 §7.3, §14 stage 7): how the app (S1) has to be built around the
// library. Two flavors of ONE applicationId — pilot users update to the release in place:
//   product — buildKind RELEASE, versionCode MMmmpp with pp 00–89, dry run impossible;
//   pilot   — buildKind PILOT,   versionCode with pp 90–99 (below the next release), dry run on.
// Both release variants are R8-minified and signed with the RELEASE key (otherwise APK_SIGNATURE,
// APP_DEBUGGABLE and the attestation are not checked for real). verify<Variant>BuildKind runs
// before every release build and fails it when flavor, versionCode, dry run, debuggable or the
// signing key disagree with S2 §7.3.
//
// Signing: -Pwolp.signing.storeFile=… -Pwolp.signing.storePassword=… -Pwolp.signing.keyAlias=…
//          -Pwolp.signing.keyPassword=… (or ORG_GRADLE_PROJECT_wolp.signing.* in the environment).
// Expected signer: -Pwolp.expectedSigningDigests=<sha256 hex>[,<sha256 hex>] — pin it in S1; when
// absent it is taken from the signing keystore (convenient here, not a substitute for pinning).
import java.io.File
import java.security.KeyStore
import java.security.MessageDigest

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

/** One place for the S2 §7.3 parameters of each flavor; BuildConfig and the verification read it. */
data class Channel(val buildKind: String, val versionCode: Int, val dryRun: Boolean)

val channels = mapOf(
    "product" to Channel("RELEASE", (findProperty("wolp.productVersionCode") as String?)?.toInt() ?: 10300, dryRun = false),
    "pilot" to Channel("PILOT", (findProperty("wolp.pilotVersionCode") as String?)?.toInt() ?: 10290, dryRun = true),
)

val signingProps = listOf("storeFile", "storePassword", "keyAlias", "keyPassword").associateWith { findProperty("wolp.signing.$it") as String? }
val hasSigning = signingProps.values.all { it != null }

/** SHA-256 (hex) of the signing certificate in the keystore, as PackageManager reports it. */
fun signerDigest(): String? = if (!hasSigning) null else {
    val ks = KeyStore.getInstance(File(signingProps.getValue("storeFile")!!), signingProps.getValue("storePassword")!!.toCharArray())
    val cert = checkNotNull(ks.getCertificate(signingProps.getValue("keyAlias"))) { "no certificate '${signingProps["keyAlias"]}' in the keystore" }
    MessageDigest.getInstance("SHA-256").digest(cert.encoded).joinToString("") { "%02x".format(it) }
}

val expectedDigests: List<String> = ((findProperty("wolp.expectedSigningDigests") as String?)?.split(',')?.map { it.trim().lowercase().replace(":", "") }
    ?: listOfNotNull(signerDigest())).filter { it.isNotEmpty() }

// demo of the BLOCK path: a digest that cannot match → APK_SIGNATURE BLOCK (product) / dry-run REPORT (pilot)
val bakedDigests = if (findProperty("wolp.pilot.wrongDigest") == "true") listOf("00".repeat(32)) else expectedDigests

android {
    namespace = "org.wolpmessenger.devicetrust.pilot"
    compileSdk = 36
    // the app strips libwolpdt.so with ITS NDK: without an installed one the .so ships with debug info and symbols
    ndkVersion = "28.2.13676358"

    defaultConfig {
        applicationId = "org.wolpmessenger.devicetrust.pilot"
        minSdk = 33
        targetSdk = 35
        buildConfigField("String", "EXPECTED_SIGNING_DIGESTS", "\"${bakedDigests.joinToString(",")}\"")
    }
    buildFeatures { buildConfig = true }

    flavorDimensions += "channel"
    productFlavors {
        channels.forEach { (name, c) ->
            create(name) {
                dimension = "channel"
                versionCode = c.versionCode
                versionName = "%d.%d.%d".format(c.versionCode / 10000, c.versionCode / 100 % 100, c.versionCode % 100) + if (name == "pilot") "-pilot" else ""
                buildConfigField("String", "BUILD_KIND", "\"${c.buildKind}\"")
                buildConfigField("boolean", "RASP_DRY_RUN", c.dryRun.toString())
            }
        }
    }

    signingConfigs {
        if (hasSigning) create("release") {
            storeFile = File(signingProps.getValue("storeFile")!!)
            storePassword = signingProps.getValue("storePassword")
            keyAlias = signingProps.getValue("keyAlias")
            keyPassword = signingProps.getValue("keyPassword")
        }
    }
    buildTypes {
        release {
            isMinifyEnabled = true // the library's consumer rules must survive R8 (JNI class, workers)
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.findByName("release")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) }
}

dependencies {
    implementation(project(":devicetrust"))
    implementation(libs.kotlinx.coroutines.android)
}

// ------------------------------------------------------------------ S2 §7.3 build check
val releaseDebuggable = android.buildTypes.getByName("release").isDebuggable

androidComponents {
    onVariants(selector().withBuildType("release")) { variant ->
        val flavor = checkNotNull(variant.flavorName)
        val channel = channels.getValue(flavor)
        val versionCode = variant.outputs.single().versionCode
        val cap = variant.name.replaceFirstChar { it.uppercase() }
        val signer = signerDigest()
        val expected = expectedDigests
        val verify = tasks.register("verify${cap}BuildKind") {
            group = "verification"
            description = "S2 §7.3: build kind, versionCode range, dry run, debuggable and signer of ${variant.name}"
            doLast {
                val vc = checkNotNull(versionCode.orNull) { "no versionCode" }
                val pilotRange = vc % 100 >= 90
                val problems = buildList {
                    when (flavor) {
                        "product" -> {
                            if (channel.buildKind != "RELEASE") add("product must be buildKind RELEASE, is ${channel.buildKind}")
                            if (pilotRange) add("product versionCode $vc is in the pilot range (last two digits 90–99)")
                            if (channel.dryRun) add("product must not enable raspDryRun")
                        }
                        "pilot" -> {
                            if (channel.buildKind != "PILOT") add("pilot must be buildKind PILOT, is ${channel.buildKind}")
                            if (!pilotRange) add("pilot versionCode $vc is outside the pilot range (last two digits 90–99)")
                        }
                        else -> add("unknown flavor $flavor")
                    }
                    if (releaseDebuggable) add("release build type is debuggable")
                    if (signer == null) add("release signing not configured (wolp.signing.*): a pilot must be signed with the release key")
                    else if (signer !in expected) add("signing certificate $signer is not in expectedSigningDigests $expected")
                    if (expected.isEmpty()) add("expectedSigningDigests empty: init() rejects a non-debuggable app without them")
                }
                check(problems.isEmpty()) { "verify${cap}BuildKind:\n  " + problems.joinToString("\n  ") }
                logger.lifecycle("verify${cap}BuildKind: OK (${channel.buildKind}, versionCode $vc, dryRun ${channel.dryRun}, signer ${signer?.take(16)}…)")
            }
        }
        tasks.configureEach { if (name == "pre${cap}Build") dependsOn(verify) }
    }
}
