package org.wolpmessenger.devicetrust

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test
import org.wolpmessenger.devicetrust.enroll.EnrollStartBody
import org.wolpmessenger.devicetrust.enroll.PrecheckSummary

class EnrollStartBodyTest {
    private val precheck = PrecheckSummary("TEE", strongBox = false, sdkInt = 34, securityPatch = "2026-09-05")

    @Test
    fun `matches the S3 §5_1 schema`() {
        val json = JSONObject(String(EnrollStartBody.encode("K7M2-QX9P-4T".toCharArray(), 10203, precheck), Charsets.UTF_8))
        assertEquals("K7M2-QX9P-4T", json.getString("onboardingPassword"))
        assertEquals(10203L, json.getLong("appVersionCode"))
        val p = json.getJSONObject("precheck")
        assertEquals("TEE", p.getString("securityLevel"))
        assertEquals(false, p.getBoolean("strongBox"))
        assertEquals(34, p.getInt("sdkInt"))
        assertEquals("2026-09-05", p.getString("securityPatch"))
    }

    @Test
    fun `passwords with quotes, backslashes, control chars and non-ASCII survive escaping`() {
        for (pw in listOf("a\"b", "c\\d", "tab\there\n", "пароль-✓", "\u0001")) {
            val json = JSONObject(String(EnrollStartBody.encode(pw.toCharArray(), 1, precheck), Charsets.UTF_8))
            assertEquals(pw, json.getString("onboardingPassword"))
        }
    }

    @Test
    fun `the caller's password array is not modified`() {
        val pw = "secret".toCharArray()
        EnrollStartBody.encode(pw, 1, precheck)
        assertEquals("secret", String(pw))
    }
}
