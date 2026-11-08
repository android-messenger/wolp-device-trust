package org.wolpmessenger.devicetrust.net

import org.json.JSONException
import org.json.JSONObject
import org.wolpmessenger.devicetrust.InternalDeviceTrustApi
import org.wolpmessenger.devicetrust.api.GatewayCode
import java.time.Duration

/** A refusal from the gateway: body `{"error":"<CODE>", ...}` and/or header `X-Device-Deny` (S3 §5, §10). */
@InternalDeviceTrustApi
public data class GatewayError(
    val httpStatus: Int,
    val code: GatewayCode,
    /** `WRONG_PASSWORD` only; always ≥ 1 (S2 §6.2 п. 3). */
    val attemptsLeft: Int? = null,
    /** `POLICY_REJECTED`, `UPDATE_REQUIRED`, `DEVICE_POLICY`. */
    val reason: String? = null,
    /** `Retry-After` in seconds (`RATE_LIMITED`, 503). */
    val retryAfter: Duration? = null,
    val requestId: String? = null,
) {
    public companion object {
        /**
         * Parses an error response. The body code wins; `X-Device-Deny` is the fallback
         * (nginx `auth_request` denials carry only the header).
         */
        public fun parse(httpStatus: Int, body: String?, denyHeader: String?, retryAfter: String?, requestId: String?): GatewayError {
            val json = body?.takeIf { it.isNotBlank() }?.let {
                try {
                    JSONObject(it)
                } catch (e: JSONException) {
                    null
                }
            }
            val code = GatewayCode.parse(json?.optString("error")?.takeIf(String::isNotEmpty) ?: denyHeader?.trim())
            return GatewayError(
                httpStatus = httpStatus,
                code = code,
                attemptsLeft = json?.takeIf { it.has("attemptsLeft") }?.optInt("attemptsLeft"),
                reason = json?.optString("reason")?.takeIf(String::isNotEmpty),
                retryAfter = retryAfter?.trim()?.toLongOrNull()?.takeIf { it >= 0 }?.let(Duration::ofSeconds),
                requestId = requestId,
            )
        }
    }
}
