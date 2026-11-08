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

/** `200` of `enroll/start` (S3 §5.1). */
internal class EnrollStarted(val enrollmentId: String, val nonce: ByteArray, val expiresAt: Instant)

/** `200` of `enroll/finish` (S3 §5.2). Chain: leaf first. */
internal class EnrollFinished(
    val deviceId: String,
    val certChain: List<X509Certificate>,
    val notBefore: Instant,
    val notAfter: Instant,
    val renewAfter: Instant,
)

/**
 * Gateway API client (S3 §5). [http] is the pinned client (S2 §10); every successful response's
 * `Date` header feeds [onServerDate] for TrustClock (S2 §5.2 — pinned channel only).
 */
internal class GatewayClient(
    private val http: OkHttpClient,
    private val enrollBase: HttpUrl,
    private val onServerDate: (String?) -> Unit,
) {
    fun enrollStart(cookie: String, body: ByteArray): GatewayResult<EnrollStarted> =
        post(enrollBase.resolve("/v1/enroll/start")!!, cookie, body) { j ->
            EnrollStarted(j.getString("enrollmentId"), unb64.decode(j.getString("nonce")), Instant.parse(j.getString("expiresAt")))
        }

    fun enrollFinish(cookie: String, enrollmentId: String, csr: ByteArray, chain: List<ByteArray>): GatewayResult<EnrollFinished> {
        val body = JSONObject()
            .put("enrollmentId", enrollmentId)
            .put("csr", b64.encodeToString(csr))
            .put("attestationChain", JSONArray(chain.map(b64::encodeToString)))
            .toString().toByteArray()
        return post(enrollBase.resolve("/v1/enroll/finish")!!, cookie, body) { j ->
            val certs = j.getJSONArray("certChain")
            val cf = CertificateFactory.getInstance("X.509")
            EnrollFinished(
                deviceId = j.getString("deviceId"),
                certChain = List(certs.length()) { i ->
                    cf.generateCertificate(ByteArrayInputStream(unb64.decode(certs.getString(i)))) as X509Certificate
                },
                notBefore = Instant.parse(j.getString("notBefore")),
                notAfter = Instant.parse(j.getString("notAfter")),
                renewAfter = Instant.parse(j.getString("renewAfter")),
            )
        }
    }

    private fun <T> post(url: HttpUrl, cookie: String, body: ByteArray, parse: (JSONObject) -> T): GatewayResult<T> {
        val request = Request.Builder()
            .url(url)
            .header("Cookie", cookie)
            .post(body.toRequestBody(JSON))
            .build()
        return try {
            http.newCall(request).execute().use { handle(it, parse) }
        } catch (e: IOException) {
            GatewayResult.Failed(e)
        }
    }

    private fun <T> handle(response: Response, parse: (JSONObject) -> T): GatewayResult<T> {
        val text = response.body?.string()
        if (!response.isSuccessful) {
            return GatewayResult.Refused(
                GatewayError.parse(
                    response.code, text, response.header("X-Device-Deny"),
                    response.header("Retry-After"), response.header("X-Request-Id"),
                ),
            )
        }
        onServerDate(response.header("Date"))
        return try {
            GatewayResult.Ok(parse(JSONObject(text ?: "")))
        } catch (e: JSONException) {
            GatewayResult.Failed(IOException("malformed gateway response", e))
        } catch (e: DateTimeParseException) {
            GatewayResult.Failed(IOException("malformed gateway response", e))
        } catch (e: IllegalArgumentException) { // bad base64
            GatewayResult.Failed(IOException("malformed gateway response", e))
        } catch (e: CertificateException) {
            GatewayResult.Failed(IOException("malformed certificate in gateway response", e))
        }
    }

    private companion object {
        val JSON = "application/json".toMediaType()
        val b64: Base64.Encoder = Base64.getEncoder()
        val unb64: Base64.Decoder = Base64.getDecoder()
    }
}
