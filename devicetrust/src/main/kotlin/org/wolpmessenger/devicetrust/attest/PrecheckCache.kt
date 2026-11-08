package org.wolpmessenger.devicetrust.attest

import org.wolpmessenger.devicetrust.api.SecurityLevel
import org.wolpmessenger.devicetrust.io.AtomicFiles
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.Properties

/**
 * Keystore level measured by the precheck, valid for one boot and one app version
 * (S2 §6.1 п. 2): the level cannot change while the device runs.
 */
internal data class CachedKeystoreLevel(
    val bootCount: Int,
    val versionCode: Long,
    val level: SecurityLevel,
    val strongBoxFallback: Boolean,
)

internal interface PrecheckCache {
    fun load(): CachedKeystoreLevel?
    fun save(value: CachedKeystoreLevel)
}

/**
 * File-backed cache in `noBackupFilesDir/dt/precheck.properties`. S2 §11 keeps it in
 * `state.json`; it moves there when the state store arrives (stage 3).
 */
internal class FilePrecheckCache(private val file: File) : PrecheckCache {
    override fun load(): CachedKeystoreLevel? = runCatching {
        if (!file.exists()) return null
        val p = Properties().apply { file.inputStream().use(::load) }
        CachedKeystoreLevel(
            bootCount = p.getProperty("bootCount").toInt(),
            versionCode = p.getProperty("versionCode").toLong(),
            level = SecurityLevel.valueOf(p.getProperty("level")),
            strongBoxFallback = p.getProperty("strongBoxFallback").toBooleanStrict(),
        )
    }.getOrNull()

    override fun save(value: CachedKeystoreLevel) {
        val p = Properties().apply {
            setProperty("bootCount", value.bootCount.toString())
            setProperty("versionCode", value.versionCode.toString())
            setProperty("level", value.level.name)
            setProperty("strongBoxFallback", value.strongBoxFallback.toString())
        }
        val out = ByteArrayOutputStream()
        p.store(out, null)
        AtomicFiles.write(file, out.toByteArray())
    }
}
