package org.wolpmessenger.testvectors

import android.content.pm.PackageManager
import android.os.Build
import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Test
import org.junit.runner.RunWith
import org.wolpmessenger.devicetrust.attest.AttestationChain
import org.wolpmessenger.devicetrust.keys.KeystoreKeys
import java.io.File
import java.security.MessageDigest
import java.time.Instant

/**
 * Writes `files/testvectors/<model>/<case>.json` (format: testvectors/README.md).
 * Challenges are deterministic — SHA-256("wolp-testvector/<case>") — so the gateway test
 * can assert `attestationChallenge == nonce`.
 */
@RunWith(AndroidJUnit4::class)
class ExportTestVectors {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val keys = KeystoreKeys.android()

    private class Case(val name: String, val strongBox: Boolean, val withChallenge: Boolean)

    @Test
    fun export() {
        val cases = buildList {
            add(Case("tee-challenge", strongBox = false, withChallenge = true))
            add(Case("tee-no-challenge", strongBox = false, withChallenge = false))
            if (context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)) {
                add(Case("strongbox-challenge", strongBox = true, withChallenge = true))
            }
        }
        val dir = File(context.getExternalFilesDir("testvectors"), modelDir())
        dir.deleteRecursively()
        dir.mkdirs()
        for (c in cases) {
            val json = exportCase(c)
            File(dir, "${c.name}.json").writeText(json.toString(2) + "\n")
            println("DT-TESTVECTOR ${dir.name}/${c.name}.json level=${json.getJSONObject("key").getString("securityLevel")}")
        }
    }

    private fun exportCase(c: Case): JSONObject {
        val challenge = if (c.withChallenge) sha256("wolp-testvector/${c.name}".toByteArray()) else null
        val alias = keys.nextDeviceAlias()
        try {
            val key = keys.generateUnchecked(alias, challenge, c.strongBox)
            val chain = AttestationChain(key.chain)
            return JSONObject()
                .put("schema", 1)
                .put("case", c.name)
                .put("exportedAt", Instant.now().toString())
                .put("device", device())
                .put("app", app())
                .put("key", JSONObject()
                    .put("requestedStrongBox", c.strongBox)
                    .put("securityLevel", key.level.name)
                    .put("hardwareConfirmed", key.level.isHardwareConfirmed))
                .put("challengeB64", challenge?.let(::b64) ?: JSONObject.NULL)
                .put("chainType", chain.chainType.name.lowercase())
                .put("hasKeyDescription", chain.hasKeyDescription)
                .put("chainB64", JSONArray(chain.encoded().map(::b64)))
        } finally {
            keys.delete(alias)
        }
    }

    private fun device() = JSONObject()
        .put("manufacturer", Build.MANUFACTURER)
        .put("brand", Build.BRAND)
        .put("model", Build.MODEL)
        .put("device", Build.DEVICE)
        .put("sdkInt", Build.VERSION.SDK_INT)
        .put("release", Build.VERSION.RELEASE)
        .put("securityPatch", Build.VERSION.SECURITY_PATCH)
        .put("strongBoxFeature", context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE))

    /** What S3 compares with tag 709 (attestationApplicationId). */
    private fun app(): JSONObject {
        val info = context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        val digests = info.signingInfo!!.apkContentsSigners.map { sha256(it.toByteArray()).toHex() }
        return JSONObject()
            .put("packageName", context.packageName)
            .put("versionCode", info.longVersionCode)
            .put("signingDigestsSha256", JSONArray(digests))
    }

    private fun modelDir() = "${Build.MANUFACTURER}-${Build.MODEL}-api${Build.VERSION.SDK_INT}".replace(Regex("[^A-Za-z0-9._-]"), "_")
    private fun sha256(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b)
    private fun b64(b: ByteArray) = Base64.encodeToString(b, Base64.NO_WRAP)
    private fun ByteArray.toHex() = joinToString("") { "%02x".format(it) }
}
