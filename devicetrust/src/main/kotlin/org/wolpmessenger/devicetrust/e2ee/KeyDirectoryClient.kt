package org.wolpmessenger.devicetrust.e2ee

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.HttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import org.wolpmessenger.devicetrust.api.E2eeException
import org.wolpmessenger.devicetrust.api.E2eeFailure
import java.io.IOException
import java.util.Base64

/**
 * The key directory over HTTP (specs/002, story 3; formats — `key-directory/docs/API.md`):
 * `<app host>/key-directory/v1/…` through the library's own channel — the device certificate and
 * the pinned server key ([client]) — with the Kratos session of the account ([cookie]). The web
 * app takes no part in it (FR-021).
 *
 * Whatever is not a usable answer — no network, no session, a refusal, a malformed body — is
 * `NO_NETWORK`: the caller can only try again later.
 */
internal class KeyDirectoryClient(
    private val client: () -> OkHttpClient,
    private val appBase: HttpUrl,
    private val cookie: () -> String?,
) : KeyDirectory, OwnRecord {

    override suspend fun fetch(user: String): PeerKeys {
        val (code, body) = call(get("keys", checked(user)))
        if (code == 404) throw E2eeException(E2eeFailure.NO_DEVICE)
        val devices = parse(code, body) { it.getJSONArray("devices") }
        if (devices.length() == 0) throw E2eeException(E2eeFailure.NO_DEVICE)
        if (devices.length() > 1) throw E2eeException(E2eeFailure.MULTI_DEVICE) // FR-026
        return parse(code, body) {
            val d = devices.getJSONObject(0)
            // a record without the post-quantum key was published by a browser or an older app
            val pq = d.optJSONObject("pqPreKey") ?: throw E2eeException(E2eeFailure.NO_PASSPORT)
            if (!d.has("registrationId")) throw E2eeException(E2eeFailure.NO_PASSPORT)
            PeerKeys(
                identityKey = unb64(d.getString("identityKey")),
                registrationId = d.getInt("registrationId"),
                signedPreKey = signed(d.getJSONObject("signedPreKey")),
                pqPreKey = signed(pq),
                oneTimePreKey = d.optJSONObject("oneTimePreKey")?.let { OneTimeKey(it.getInt("id"), unb64(it.getString("publicKey"))) },
                passport = d.optJSONObject("passport")?.let(::passport),
            )
        }
    }

    override suspend fun record(user: String): DirectoryRecord? {
        val (code, body) = call(get("keys", checked(user), "identity"))
        if (code == 404) return null
        return parse(code, body) {
            DirectoryRecord(it.getString("deviceId"), unb64(it.getString("identityKey")), it.optJSONObject("passport")?.let(::passport)?.certificates?.first())
        }
    }

    override suspend fun count(deviceId: String): Int? {
        val url = url("keys", "self", "count").newBuilder().addQueryParameter("deviceId", deviceId).build()
        val (code, body) = call(Request.Builder().url(url).get())
        if (code == 404) return null
        return parse(code, body) { it.getInt("oneTimePreKeysRemaining") }
    }

    override suspend fun publish(deviceId: String, keys: OwnKeys, passport: Passport) {
        val body = JSONObject()
            .put("deviceId", deviceId)
            .put("identityKey", b64(keys.identityKey))
            .put("signedPreKey", json(keys.signedPreKey))
            .put("oneTimePreKeys", json(keys.oneTimePreKeys))
            .put("pqPreKey", json(keys.pqPreKey))
            .put("registrationId", keys.registrationId)
            .put("passport", JSONObject().put("signature", b64(passport.signature)).put("certificates", JSONArray(passport.certificates.map(::b64))))
        val (code, _) = call(post(body, "keys"))
        if (code != 200) throw unusable(code)
    }

    override suspend fun replenish(deviceId: String, keys: List<OneTimeKey>): Boolean {
        val (code, _) = call(post(JSONObject().put("deviceId", deviceId).put("oneTimePreKeys", json(keys)), "keys", "one-time"))
        if (code == 404) return false
        if (code != 200) throw unusable(code)
        return true
    }

    override suspend fun remove(deviceId: String) {
        val (code, _) = call(Request.Builder().url(url("keys", "self", deviceId)).delete())
        if (code != 204 && code != 404) throw unusable(code)
    }

    // ---------------------------------------------------------------- plumbing

    private fun url(vararg segments: String): HttpUrl =
        appBase.newBuilder().addPathSegments("key-directory/v1").apply { segments.forEach { addPathSegment(it) } }.build()

    private fun get(vararg segments: String) = Request.Builder().url(url(*segments)).get()

    private fun post(body: JSONObject, vararg segments: String) = Request.Builder().url(url(*segments)).post(body.toString().toByteArray().toRequestBody(JSON))

    private suspend fun call(request: Request.Builder): Pair<Int, String> = withContext(Dispatchers.IO) {
        try {
            cookie()?.let { request.header("Cookie", it) }
            client().newCall(request.build()).execute().use { it.code to it.body?.string().orEmpty() }
        } catch (e: IOException) {
            throw E2eeException(E2eeFailure.NO_NETWORK, e)
        }
    }

    private fun <T> parse(code: Int, body: String, read: (JSONObject) -> T): T {
        if (code != 200) throw unusable(code)
        return try {
            read(JSONObject(body))
        } catch (e: JSONException) {
            throw E2eeException(E2eeFailure.NO_NETWORK, e)
        } catch (e: IllegalArgumentException) { // base64
            throw E2eeException(E2eeFailure.NO_NETWORK, e)
        }
    }

    /** The status only: a body of the directory never goes into a message or the log. */
    private fun unusable(code: Int) = E2eeException(E2eeFailure.NO_NETWORK, IOException("key directory answered $code"))

    /** The directory's own rule for an account id; anything else has no record there. */
    private fun checked(user: String): String = if (USER.matches(user)) user else throw E2eeException(E2eeFailure.NO_DEVICE)

    private fun signed(j: JSONObject) = SignedKey(j.getInt("id"), unb64(j.getString("publicKey")), unb64(j.getString("signature")))

    private fun passport(j: JSONObject): Passport {
        val certs = j.getJSONArray("certificates")
        require(certs.length() in 1..Passport.MAX_CERTIFICATES) { "certificate count" }
        return Passport(unb64(j.getString("signature")), List(certs.length()) { unb64(certs.getString(it)) })
    }

    private fun json(k: SignedKey) = JSONObject().put("id", k.id).put("publicKey", b64(k.publicKey)).put("signature", b64(k.signature))

    private fun json(keys: List<OneTimeKey>) = JSONArray(keys.map { JSONObject().put("id", it.id).put("publicKey", b64(it.publicKey)) })

    private companion object {
        val JSON = "application/json".toMediaType()
        val USER = Regex("^[A-Za-z0-9._-]{1,64}$")
        fun b64(b: ByteArray): String = Base64.getEncoder().encodeToString(b)
        fun unb64(s: String): ByteArray = Base64.getDecoder().decode(s)
    }
}
