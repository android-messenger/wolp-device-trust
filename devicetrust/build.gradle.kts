import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.util.zip.ZipFile

plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
}

// ------------------------------------------------------------------ encrypted native strings (S2 §7.5)
val nativeStringsFile = rootProject.file("devicetrust-native/strings.txt")
val nativeGenDir = layout.buildDirectory.dir("generated/wolpdt")

val generateNativeStrings = tasks.register("generateNativeStrings") {
    group = "build"
    description = "devicetrust-native/strings.txt → wolpdt_strings.h (encrypted string table)"
    val src = nativeStringsFile
    val seedProp = providers.gradleProperty("wolpdt.obfSeed")
    val out = nativeGenDir.map { it.file("wolpdt_strings.h") }
    inputs.file(src)
    inputs.property("seed", seedProp.orElse(""))
    outputs.file(out)
    doLast {
        out.get().asFile.apply { parentFile.mkdirs() }.writeText(NativeStrings.header(src.readBytes(), seedProp.orNull))
    }
}

// the CMake configure/build tasks read the generated header
tasks.configureEach {
    if (name.startsWith("configureCMake") || name.startsWith("buildCMake")) dependsOn(generateNativeStrings)
}

/** No value of strings.txt (4+ bytes) may appear in clear text in a packaged libwolpdt.so. */
val checkNativeStrings = tasks.register("checkNativeStrings") {
    group = "verification"
    description = "Fails if a string of devicetrust-native/strings.txt is readable in the release AAR's libwolpdt.so"
    val src = nativeStringsFile
    val aar = tasks.named("bundleReleaseAar").map { it.outputs.files.singleFile }
    inputs.file(src)
    inputs.file(aar)
    doLast {
        val values = NativeStrings.parse(src.readText()).map { it.second }.filter { it.size >= 4 }.distinctBy { String(it, Charsets.ISO_8859_1) }
        var libs = 0
        ZipFile(aar.get()).use { zip ->
            for (e in zip.entries().asSequence().filter { it.name.startsWith("jni/") && it.name.endsWith("/libwolpdt.so") }) {
                libs++
                val so = String(zip.getInputStream(e).readBytes(), Charsets.ISO_8859_1)
                val leaked = values.map { String(it, Charsets.ISO_8859_1) }.filter { it in so }
                check(leaked.isEmpty()) { "${e.name}: plain-text strings ${leaked.map { it.replace("\u0000", "\\0") }}" }
            }
        }
        check(libs > 0) { "no libwolpdt.so in $aar" }
        logger.lifecycle("checkNativeStrings: OK (${values.size} strings, $libs ABIs)")
    }
}

/** Parser and encryptor for strings.txt; the keystream must match obf_dec in devicetrust-native/src/obf.h. */
object NativeStrings {
    fun parse(text: String): List<Pair<String, ByteArray>> = text.lines().mapNotNull { raw ->
        val line = raw.trimEnd()
        if (line.isBlank() || line.trimStart().startsWith("#")) return@mapNotNull null
        val name = line.substringBefore(' ')
        val value = line.substringAfter(' ').trimStart()
        require(name.isNotEmpty() && value.isNotEmpty() && name.trimEnd('[', ']').all { it.isLetterOrDigit() || it == '_' }) { "strings.txt: bad line '$line'" }
        name to unescape(value)
    }

    private fun unescape(s: String): ByteArray {
        val out = ByteArrayOutputStream()
        var i = 0
        while (i < s.length) {
            val c = s[i++]
            if (c != '\\') { out.write(c.toString().toByteArray()); continue }
            require(i < s.length) { "strings.txt: trailing backslash in '$s'" }
            out.write(when (val e = s[i++]) { '0' -> 0; 'r' -> 13; 'n' -> 10; 't' -> 9; '\\' -> 92; else -> error("strings.txt: bad escape \\$e") })
        }
        return out.toByteArray()
    }

    fun header(src: ByteArray, seedProp: String?): String {
        val entries = parse(String(src, Charsets.UTF_8))
        val seed = seedProp?.toByteArray() ?: MessageDigest.getInstance("SHA-256").digest(src)
        val max = entries.maxOf { it.second.size } + 1
        val sb = StringBuilder()
        sb.appendLine("// GENERATED from devicetrust-native/strings.txt by :devicetrust:generateNativeStrings — do not edit.")
        sb.appendLine("#pragma once")
        sb.appendLine("#define OBF_MAX $max")
        sb.appendLine("#include \"obf.h\"")
        val keys = entries.indices.map { i ->
            val d = MessageDigest.getInstance("SHA-256").apply { update(seed); update(i.toString().toByteArray()) }.digest()
            val k = ((d[0].toInt() and 0xff) shl 24) or ((d[1].toInt() and 0xff) shl 16) or ((d[2].toInt() and 0xff) shl 8) or (d[3].toInt() and 0xff)
            if (k == 0) 1 else k
        }
        entries.forEachIndexed { i, (_, v) ->
            var x = keys[i]
            val enc = v.map { b ->
                x = x xor (x shl 13); x = x xor (x ushr 17); x = x xor (x shl 5)
                ((b.toInt() and 0xff) xor ((x ushr 11) and 0xff))
            }
            sb.appendLine("__attribute__((unused)) static const uint8_t obf_d$i[] = {${enc.joinToString(",") { "0x%02x".format(it) }}};")
        }
        sb.appendLine("__attribute__((unused)) static const obf_t obf_tab[] = {")
        entries.forEachIndexed { i, (_, v) -> sb.appendLine("    {obf_d$i, ${v.size}, 0x%08xu},".format(keys[i])) }
        sb.appendLine("};")
        val arrays = linkedMapOf<String, MutableList<Int>>()
        entries.forEachIndexed { i, (name, _) ->
            if (name.endsWith("[]")) arrays.getOrPut(name.removeSuffix("[]")) { mutableListOf() } += i
            else sb.appendLine("#define OBF_$name (&obf_tab[$i])")
        }
        for ((name, idx) in arrays) {
            sb.appendLine("__attribute__((unused)) static const obf_t *const OBF_$name[] = {${idx.joinToString(", ") { "&obf_tab[$it]" }}};")
            sb.appendLine("#define OBF_${name}_N ${idx.size}")
        }
        return sb.toString()
    }
}

android {
    namespace = "org.wolpmessenger.devicetrust"
    compileSdk = 36
    ndkVersion = "28.2.13676358"

    defaultConfig {
        minSdk = 33
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
        externalNativeBuild {
            cmake { arguments += listOf("-DANDROID_STL=none", "-DWOLPDT_GEN_DIR=${nativeGenDir.get().asFile.absolutePath}") }
        }
    }
    // native RASP checks (S2 §7.1, §7.5) live in ../devicetrust-native (S2 §2)
    externalNativeBuild {
        cmake {
            path = file("../devicetrust-native/CMakeLists.txt")
            version = "3.22.1"
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    testOptions {
        unitTests.isReturnDefaultValues = false
    }
    // TLS tests run on the JVM (JDK provider) and on devices (Conscrypt): session caches differ.
    sourceSets["test"].kotlin.srcDir("src/sharedTest/kotlin")
    sourceSets["androidTest"].kotlin.srcDir("src/sharedTest/kotlin")
}

kotlin {
    explicitApi()
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        optIn.add("org.wolpmessenger.devicetrust.InternalDeviceTrustApi")
    }
}

dependencies {
    implementation(libs.kotlinx.coroutines.android)
    api(libs.okhttp) // okHttpClient() is part of the public API (S2 §4)
    implementation(libs.work.runtime) // RenewWorker (S2 §6.5)
    implementation(libs.lifecycle.process) // RASP on coming to the foreground (S2 §7.2)

    testImplementation(libs.junit)
    // real org.json for JVM tests (android.jar has only stubs)
    testImplementation(libs.org.json)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.okhttp.mockwebserver)
    testImplementation(libs.okhttp.tls)

    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.kotlinx.coroutines.test)
    androidTestImplementation(libs.okhttp.mockwebserver)
    androidTestImplementation(libs.okhttp.tls)
}
