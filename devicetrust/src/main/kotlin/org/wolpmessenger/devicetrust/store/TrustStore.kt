package org.wolpmessenger.devicetrust.store

import org.json.JSONArray
import org.json.JSONObject
import org.wolpmessenger.devicetrust.Journal
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

/** Renewed certificate received but not yet switched to (S2 §6.3 п. 5–6). Its chain is in `certs/<N>.pem`. */
internal typealias PendingCert = ActiveCert

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
    val pending: PendingCert? = null,
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

    /** Last state read or written, with the (mtime, length) of the file it belongs to. */
    private var cached: Pair<Pair<Long, Long>, StoredState>? = null
    private val chains = HashMap<Int, Pair<Pair<Long, Long>, List<X509Certificate>>>()

    private fun stamp(f: File): Pair<Long, Long> = f.lastModified() to f.length()

    /**
     * A file that cannot be parsed (writes are atomic, so this means damage from outside) is set
     * aside as `state.json.corrupt` and the device starts over as `NOT_ENROLLED`: the start-up
     * reconciliation then removes the device keys nothing points at, and the user enrolls again.
     * Throwing here instead would crash the app on every start. A read error (IOException) is not
     * damage and still propagates.
     */
    fun load(): StoredState = synchronized(lock) {
        if (!stateFile.exists()) {
            cached = null
            return StoredState()
        }
        // `load` runs on every TLS handshake and state query: answer from memory while the file is
        // the one this instance last read or wrote (FR-021); a stat is all that is left on that path
        val stamp = stamp(stateFile)
        cached?.takeIf { it.first == stamp }?.let { return it.second }
        try {
            fromJson(JSONObject(stateFile.readText())).also { cached = stamp to it }
        } catch (e: org.json.JSONException) {
            setAside(e)
        } catch (e: IllegalArgumentException) { // unknown Phase, bad base64
            setAside(e)
        } catch (e: java.time.format.DateTimeParseException) {
            setAside(e)
        }
    }

    private fun setAside(e: Exception): StoredState {
        cached = null
        Journal.event("state_corrupt", e.javaClass.simpleName)
        val aside = File(stateFile.parentFile, stateFile.name + ".corrupt")
        aside.delete()
        if (!stateFile.renameTo(aside)) stateFile.delete()
        return StoredState()
    }

    fun save(state: StoredState): Unit = synchronized(lock) {
        AtomicFiles.write(stateFile, toJson(state).toString().toByteArray())
        cached = stamp(stateFile) to state
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
        synchronized(lock) {
            if (!f.exists()) {
                chains.remove(keyNumber)
                return null
            }
            val stamp = stamp(f)
            chains[keyNumber]?.takeIf { it.first == stamp }?.let { return it.second }
            return CertificateFactory.getInstance("X.509")
                .generateCertificates(ByteArrayInputStream(f.readBytes()))
                .map { it as X509Certificate }
                .also { chains[keyNumber] = stamp to it }
        }
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
            .putOpt("active", s.active?.let(::certJson))
            .putOpt("pending", s.pending?.let(::certJson))
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

        fun certJson(c: ActiveCert): JSONObject = JSONObject().put("alias", c.alias).put("serial", c.serialHex)
            .put("notBefore", c.notBefore.toString()).put("notAfter", c.notAfter.toString()).put("renewAfter", c.renewAfter.toString())

        fun certFromJson(j: JSONObject) = ActiveCert(
            j.getString("alias"), j.getString("serial"), Instant.parse(j.getString("notBefore")),
            Instant.parse(j.getString("notAfter")), Instant.parse(j.getString("renewAfter")),
        )

        fun fromJson(j: JSONObject): StoredState = StoredState(
            phase = Phase.valueOf(j.getString("phase")),
            deviceId = j.optString("deviceId").ifEmpty { null },
            credentialsVersion = j.optLong("credentialsVersion"),
            blockReason = j.optString("blockReason").ifEmpty { null },
            active = j.optJSONObject("active")?.let(::certFromJson),
            pending = j.optJSONObject("pending")?.let(::certFromJson),
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
