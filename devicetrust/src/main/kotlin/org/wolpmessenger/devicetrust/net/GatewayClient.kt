package org.wolpmessenger.devicetrust.net

import okhttp3.HttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.IOException
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.Instant
import java.time.format.DateTimeParseException
import java.util.Base64

/** Outcome of one gateway call. */
internal sealed interface GatewayResult<out T> {
    data class Ok<T>(val value: T) : GatewayResult<T>
    data class Refused(val error: GatewayError) : GatewayResult<Nothing>

    /** Network failure, timeout, pinning failure, malformed success body. */
    data class Failed(val cause: IOException) : GatewayResult<Nothing>
}

/** `200` of `enroll/start`, `renew/challenge`, `reattest/challenge`. */
internal class Challenge(val nonce: ByteArray, val expiresAt: Instant, val enrollmentId: String? = null)

/** `200` of `whoami` (S3 §5.8c). */
internal class Whoami(val deviceId: String, val session: String)

/** A certificate issued by `enroll/finish`, `renew` or `reattest/finish` (S3 §5.2). Chain: leaf first. */
internal class IssuedCert(
    val deviceId: String?,
    val certChain: List<X509Certificate>,
    val notBefore: Instant,
    val notAfter: Instant,
    val renewAfter: Instant,
)

/**
 * Gateway API client (S3 §5). [pinned] is the pinned client without a client certificate
 * (enroll host); mTLS calls take a client built for a specific key (HttpClients.mtls).
 * Every successful response's `Date` feeds [onServerDate] (TrustClock, S2 §5.2 — pinned channel only).
 */
internal class GatewayClient(
    private val pinned: OkHttpClient,
    private val enrollBase: HttpUrl,
    private val onServerDate: (String?) -> Unit,
    private val appBase: HttpUrl = enrollBase,
) {
    // --- enroll host, Kratos session (S3 §5.1–5.2) ---

    fun enrollStart(cookie: String, body: ByteArray): GatewayResult<Challenge> =
        call(pinned, post(enrollBase, "/v1/enroll/start", body).header("Cookie", cookie)) { j ->
            Challenge(unb64.decode(j.getString("nonce")), Instant.parse(j.getString("expiresAt")), j.getString("enrollmentId"))
        }

    fun enrollFinish(cookie: String, enrollmentId: String, csr: ByteArray, chain: List<ByteArray>): GatewayResult<IssuedCert> {
        val body = JSONObject().put("enrollmentId", enrollmentId).put("csr", b64.encodeToString(csr))
            .put("attestationChain", JSONArray(chain.map(b64::encodeToString)))
        return call(pinned, post(enrollBase, "/v1/enroll/finish", body.bytes()).header("Cookie", cookie), ::issued)
    }

    // --- app host, mTLS with the current key (S3 §5.3–5.5) ---

    fun renewChallenge(mtls: OkHttpClient): GatewayResult<Challenge> =
        call(mtls, Request.Builder().url(appBase.resolve("/v1/device/renew/challenge")!!).get(), ::challenge)

    fun renew(mtls: OkHttpClient, csr: ByteArray, chain: List<ByteArray>, continuitySig: ByteArray): GatewayResult<IssuedCert> {
        val body = JSONObject().put("csr", b64.encodeToString(csr)).put("attestationChain", JSONArray(chain.map(b64::encodeToString)))
            .put("continuitySig", b64.encodeToString(continuitySig))
        return call(mtls, post(appBase, "/v1/device/renew", body.bytes()), ::issued)
    }

    /** `204` → Ok(Unit). Sent with the **new** certificate. */
    fun renewConfirm(mtls: OkHttpClient): GatewayResult<Unit> =
        call(mtls, post(appBase, "/v1/device/renew/confirm", ByteArray(0))) { }

    // --- enroll host, recovery without mTLS (S3 §5.6) ---

    fun reattestChallenge(certSerialHex: String): GatewayResult<Challenge> =
        call(pinned, post(enrollBase, "/v1/device/reattest/challenge", JSONObject().put("certSerial", certSerialHex).bytes()), ::challenge)

    fun reattestFinish(certSerialHex: String, csr: ByteArray, chain: List<ByteArray>, continuitySig: ByteArray): GatewayResult<IssuedCert> {
        val body = JSONObject().put("certSerial", certSerialHex).put("csr", b64.encodeToString(csr))
            .put("attestationChain", JSONArray(chain.map(b64::encodeToString))).put("continuitySig", b64.encodeToString(continuitySig))
        return call(pinned, post(enrollBase, "/v1/device/reattest/finish", body.bytes()), ::issued)
    }

    // --- enroll host, no mTLS (S3 §5.7) ---

    /** `202` → Ok. [cookie] only for unsigned messages (the gateway attributes them to the session). */
    fun alert(body: ByteArray, cookie: String?): GatewayResult<Unit> =
        call(pinned, post(enrollBase, "/v1/device/alert", body).apply { cookie?.let { header("Cookie", it) } }) { }

    // --- app host, mTLS with the current certificate: DeviceTrust.okHttpClient() (S3 §5.8a, §5.8c) ---

    /** `204` → Ok(true if `X-Device-Renew: 1`). No Kratos session needed. */
    fun ping(app: OkHttpClient): GatewayResult<Boolean> =
        call(app, Request.Builder().url(appBase.resolve("/v1/device/ping")!!).get()) { _, r -> r.header("X-Device-Renew")?.trim() == "1" }

    /** `200 {"deviceId","session":"none|match|mismatch"}`. */
    fun whoami(app: OkHttpClient, cookie: String): GatewayResult<Whoami> =
        call(app, Request.Builder().url(appBase.resolve("/v1/device/whoami")!!).get().header("Cookie", cookie)) { j, _ ->
            Whoami(j.getString("deviceId"), j.getString("session"))
        }

    // --- plumbing ---

    private fun post(base: HttpUrl, path: String, body: ByteArray) =
        Request.Builder().url(base.resolve(path)!!).post(body.toRequestBody(JSON))

    private fun <T> call(client: OkHttpClient, request: Request.Builder, parse: (JSONObject) -> T): GatewayResult<T> =
        call(client, request) { j, _ -> parse(j) }

    private fun <T> call(client: OkHttpClient, request: Request.Builder, parse: (JSONObject, Response) -> T): GatewayResult<T> = try {
        client.newCall(request.build()).execute().use { handle(it, parse) }
    } catch (e: IOException) {
        GatewayResult.Failed(e)
    }

    private fun <T> handle(response: Response, parse: (JSONObject, Response) -> T): GatewayResult<T> {
        val text = response.body?.string()
        if (!response.isSuccessful) {
            return GatewayResult.Refused(
                GatewayError.parse(response.code, text, response.header("X-Device-Deny"), response.header("Retry-After"), response.header("X-Request-Id")),
            )
        }
        onServerDate(response.header("Date"))
        return try {
            GatewayResult.Ok(parse(if (text.isNullOrBlank()) JSONObject() else JSONObject(text), response))
        } catch (e: JSONException) {
            malformed(e)
        } catch (e: DateTimeParseException) {
            malformed(e)
        } catch (e: IllegalArgumentException) { // bad base64
            malformed(e)
        } catch (e: CertificateException) {
            malformed(e)
        }
    }

    private fun malformed(e: Exception) = GatewayResult.Failed(IOException("malformed gateway response", e))

    private fun challenge(j: JSONObject) = Challenge(unb64.decode(j.getString("nonce")), Instant.parse(j.getString("expiresAt")))

    private fun issued(j: JSONObject): IssuedCert {
        val certs = j.getJSONArray("certChain")
        val cf = CertificateFactory.getInstance("X.509")
        return IssuedCert(
            deviceId = j.optString("deviceId").ifEmpty { null },
            certChain = List(certs.length()) { i -> cf.generateCertificate(ByteArrayInputStream(unb64.decode(certs.getString(i)))) as X509Certificate },
            notBefore = Instant.parse(j.getString("notBefore")),
            notAfter = Instant.parse(j.getString("notAfter")),
            renewAfter = Instant.parse(j.getString("renewAfter")),
        )
    }

    private fun JSONObject.bytes() = toString().toByteArray()

    private companion object {
        val JSON = "application/json".toMediaType()
        val b64: Base64.Encoder = Base64.getEncoder()
        val unb64: Base64.Decoder = Base64.getDecoder()
    }
}
