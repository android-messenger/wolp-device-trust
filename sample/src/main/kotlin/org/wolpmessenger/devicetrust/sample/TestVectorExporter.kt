package org.wolpmessenger.devicetrust.sample

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import org.wolpmessenger.devicetrust.asn1.Csr
import org.wolpmessenger.devicetrust.attest.AttestationChain
import org.wolpmessenger.devicetrust.keys.KeystoreKeys
import java.security.MessageDigest
import java.time.Instant

/**
 * Attestation test vectors for the gateway tests (S2 §13, S3 §6.5; format: testvectors/README.md).
 * Challenges are deterministic — SHA-256("wolp-testvector/<case>") — so the gateway test can
 * assert `attestationChallenge == nonce`; every vector carries a CSR signed by the attested key.
 */
class TestVectorExporter(private val context: Context) {
    private val keys = KeystoreKeys.android()

    private class Case(val name: String, val strongBox: Boolean, val withChallenge: Boolean)

    /** case name → vector JSON. */
    fun export(): Map<String, JSONObject> {
        val cases = buildList {
            add(Case("tee-challenge", strongBox = false, withChallenge = true))
            add(Case("tee-no-challenge", strongBox = false, withChallenge = false))
            if (DeviceFacts.hasStrongBox(context)) add(Case("strongbox-challenge", strongBox = true, withChallenge = true))
        }
        return cases.associate { it.name to exportCase(it) }
    }

    private fun exportCase(c: Case): JSONObject {
        val challenge = if (c.withChallenge) sha256("wolp-testvector/${c.name}".toByteArray()) else null
        val alias = keys.nextDeviceAlias()
        try {
            val key = keys.generateUnchecked(alias, challenge, c.strongBox)
            val chain = AttestationChain(key.chain)
            val csr = Csr.build(chain.leaf.publicKey, keys.privateKey(alias)!!)
            return JSONObject()
                .put("schema", 1)
                .put("case", c.name)
                .put("exportedAt", Instant.now().toString())
                .put("device", DeviceFacts.json(context))
                .put("app", app())
                .put("key", JSONObject()
                    .put("requestedStrongBox", c.strongBox)
                    .put("securityLevel", key.level.name)
                    .put("hardwareConfirmed", key.level.isHardwareConfirmed))
                .put("challengeB64", challenge?.let(::b64) ?: JSONObject.NULL)
                .put("chainType", chain.chainType.name.lowercase())
                .put("hasKeyDescription", chain.hasKeyDescription)
                .put("chainB64", JSONArray(chain.encoded().map(::b64)))
                .put("csrB64", b64(csr))
        } finally {
            keys.delete(alias)
        }
    }

    /** What S3 compares with tag 709 (attestationApplicationId). */
    private fun app(): JSONObject {
        val info = context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        val digests = info.signingInfo!!.apkContentsSigners.map { sha256(it.toByteArray()).toHex() }
        return JSONObject()
            .put("packageName", context.packageName)
            .put("versionCode", info.longVersionCode)
            .put("signingDigestsSha256", JSONArray(digests))
    }

    private fun sha256(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b)
    private fun b64(b: ByteArray) = Base64.encodeToString(b, Base64.NO_WRAP)
    private fun ByteArray.toHex() = joinToString("") { "%02x".format(it) }

    companion object {
        fun modelDir(): String = "${Build.MANUFACTURER}-${Build.MODEL}-api${Build.VERSION.SDK_INT}".replace(Regex("[^A-Za-z0-9._-]"), "_")
    }
}
