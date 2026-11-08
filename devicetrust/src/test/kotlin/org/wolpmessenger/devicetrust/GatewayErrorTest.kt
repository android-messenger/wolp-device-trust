package org.wolpmessenger.devicetrust

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.wolpmessenger.devicetrust.api.GatewayCode
import org.wolpmessenger.devicetrust.net.GatewayError
import java.time.Duration

class GatewayErrorTest {
    @Test
    fun `body code with extra fields`() {
        val e = GatewayError.parse(403, """{"error":"WRONG_PASSWORD","attemptsLeft":2}""", null, null, "req-1")
        assertEquals(GatewayCode.WRONG_PASSWORD, e.code)
        assertEquals(2, e.attemptsLeft)
        assertEquals("req-1", e.requestId)

        val p = GatewayError.parse(403, """{"error":"POLICY_REJECTED","reason":"BOOTLOADER_UNLOCKED"}""", null, null, null)
        assertEquals(GatewayCode.POLICY_REJECTED, p.code)
        assertEquals("BOOTLOADER_UNLOCKED", p.reason)
        assertNull(p.attemptsLeft)
    }

    @Test
    fun `X-Device-Deny is the fallback for auth_request denials`() {
        assertEquals(GatewayCode.DEVICE_REPLACED, GatewayError.parse(403, "<html>403</html>", "DEVICE_REPLACED", null, null).code)
        assertEquals(GatewayCode.CERT_EXPIRED, GatewayError.parse(401, "", " CERT_EXPIRED ", null, null).code)
        assertEquals("body wins", GatewayCode.NO_SESSION, GatewayError.parse(401, """{"error":"NO_SESSION"}""", "CERT_EXPIRED", null, null).code)
    }

    @Test
    fun `unknown codes and Retry-After`() {
        assertEquals(GatewayCode.UNKNOWN, GatewayError.parse(500, """{"error":"SOMETHING_NEW"}""", null, null, null).code)
        assertEquals(GatewayCode.UNKNOWN, GatewayError.parse(500, null, null, null, null).code)
        assertEquals(GatewayCode.UNKNOWN, GatewayCode.parse("UNKNOWN"))
        val rl = GatewayError.parse(429, """{"error":"RATE_LIMITED"}""", null, "120", null)
        assertEquals(Duration.ofSeconds(120), rl.retryAfter)
        assertNull(GatewayError.parse(429, null, null, "Wed, 21 Oct 2026 07:28:00 GMT", null).retryAfter)
    }
}
