package org.wolpmessenger.devicetrust.store

import org.json.JSONArray
import org.json.JSONObject
import org.wolpmessenger.devicetrust.clock.ClockAnchor
import org.wolpmessenger.devicetrust.io.AtomicFiles
import java.io.ByteArrayInputStream
import java.io.File
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.Instant
import java.util.Base64

/** Persistent phase; the observable [org.wolpmessenger.devicetrust.api.TrustState] is derived from it and the clock. */
internal enum class Phase { NOT_ENROLLED, ENROLLED, RE_ENROLL_REQUIRED, UPDATE_REQUIRED, BLOCKED, UNENROLLING }

/** The certificate in use. Its chain lives in `certs/<keyNumber>.pem`. */
internal data class ActiveCert(
    val alias: String,
    val serialHex: String,
    val notBefore: Instant,
    val notAfter: Instant,
    val renewAfter: Instant,
)

/** Written before `enroll/finish` so a lost response can be replayed (S2 §6.2 п. 6, §6.6 п. 2a). */
internal class Enrolling(
    val enrollmentId: String,
    val alias: String,
    val csr: ByteArray,
    val chain: List<ByteArray>,
    val createdAt: Instant,
)

internal data class UpdateRequiredInfo(val kind: String, val reason: String, val versionCode: Long, val securityPatch: String)

/** Contents of `noBackupFilesDir/dt/state.json` (S2 §11). No secrets inside. */
internal data class StoredState(
    val phase: Phase = Phase.NOT_ENROLLED,
    val deviceId: String? = null,
    val active: ActiveCert? = null,
    val enrolling: Enrolling? = null,
    val credentialsVersion: Long = 0,
    val clock: ClockAnchor? = null,
    val updateRequired: UpdateRequiredInfo? = null,
    val blockReason: String? = null,
)

/**
 * `state.json` + `certs/<N>.pem` under `noBackupFilesDir/dt/` (S2 §11). Every write is atomic
 * (temp → fsync → rename); a certificate file is written before the state that points at it.
 */
internal class TrustStore(dir: File) {
    private val stateFile = File(dir, "state.json")
    private val certsDir = File(dir, "certs")

    private val lock = Any()

    fun load(): StoredState = synchronized(lock) {
        if (!stateFile.exists()) return StoredState()
        fromJson(JSONObject(stateFile.readText()))
    }

    fun save(state: StoredState): Unit = synchronized(lock) {
        AtomicFiles.write(stateFile, toJson(state).toString().toByteArray())
    }

    /** Read-modify-write under one lock, so concurrent writers (clock anchor, enrollment) never lose updates. */
    fun update(transform: (StoredState) -> StoredState): StoredState = synchronized(lock) {
        transform(load()).also(::save)
    }

    fun writeChain(keyNumber: Int, chain: List<X509Certificate>) {
        val enc = Base64.getMimeEncoder(64, "\n".toByteArray())
        val pem = chain.joinToString("") { c ->
            "-----BEGIN CERTIFICATE-----\n" + enc.encodeToString(c.encoded) + "\n-----END CERTIFICATE-----\n"
        }
        AtomicFiles.write(File(certsDir, "$keyNumber.pem"), pem.toByteArray())
    }

    fun readChain(keyNumber: Int): List<X509Certificate>? {
        val f = File(certsDir, "$keyNumber.pem")
        if (!f.exists()) return null
        return CertificateFactory.getInstance("X.509")
            .generateCertificates(ByteArrayInputStream(f.readBytes()))
            .map { it as X509Certificate }
    }

    fun deleteChainsExcept(keep: Set<Int>) {
        certsDir.listFiles()?.forEach { f ->
            val n = f.name.removeSuffix(".pem").toIntOrNull()
            if (n == null || n !in keep) f.delete()
        }
    }

    private companion object {
        val b64: Base64.Encoder = Base64.getEncoder()
        val unb64: Base64.Decoder = Base64.getDecoder()

        fun toJson(s: StoredState): JSONObject = JSONObject()
            .put("v", 1)
            .put("phase", s.phase.name)
            .putOpt("deviceId", s.deviceId)
            .put("credentialsVersion", s.credentialsVersion)
            .putOpt("blockReason", s.blockReason)
            .putOpt("active", s.active?.let {
                JSONObject().put("alias", it.alias).put("serial", it.serialHex).put("notBefore", it.notBefore.toString())
                    .put("notAfter", it.notAfter.toString()).put("renewAfter", it.renewAfter.toString())
            })
            .putOpt("enrolling", s.enrolling?.let {
                JSONObject().put("enrollmentId", it.enrollmentId).put("alias", it.alias).put("csr", b64.encodeToString(it.csr))
                    .put("chain", JSONArray(it.chain.map(b64::encodeToString))).put("createdAt", it.createdAt.toString())
            })
            .putOpt("clock", s.clock?.let {
                JSONObject().put("serverEpochMs", it.serverEpochMs).put("elapsedAtReceipt", it.elapsedAtReceipt).put("bootCount", it.bootCount)
            })
            .putOpt("updateRequired", s.updateRequired?.let {
                JSONObject().put("kind", it.kind).put("reason", it.reason).put("versionCode", it.versionCode).put("securityPatch", it.securityPatch)
            })

        fun fromJson(j: JSONObject): StoredState = StoredState(
            phase = Phase.valueOf(j.getString("phase")),
            deviceId = j.optString("deviceId").ifEmpty { null },
            credentialsVersion = j.optLong("credentialsVersion"),
            blockReason = j.optString("blockReason").ifEmpty { null },
            active = j.optJSONObject("active")?.let {
                ActiveCert(
                    it.getString("alias"), it.getString("serial"), Instant.parse(it.getString("notBefore")),
                    Instant.parse(it.getString("notAfter")), Instant.parse(it.getString("renewAfter")),
                )
            },
            enrolling = j.optJSONObject("enrolling")?.let {
                val chain = it.getJSONArray("chain")
                Enrolling(
                    it.getString("enrollmentId"), it.getString("alias"), unb64.decode(it.getString("csr")),
                    List(chain.length()) { i -> unb64.decode(chain.getString(i)) }, Instant.parse(it.getString("createdAt")),
                )
            },
            clock = j.optJSONObject("clock")?.let {
                ClockAnchor(it.getLong("serverEpochMs"), it.getLong("elapsedAtReceipt"), it.getInt("bootCount"))
            },
            updateRequired = j.optJSONObject("updateRequired")?.let {
                UpdateRequiredInfo(it.getString("kind"), it.getString("reason"), it.getLong("versionCode"), it.getString("securityPatch"))
            },
        )
    }
}
