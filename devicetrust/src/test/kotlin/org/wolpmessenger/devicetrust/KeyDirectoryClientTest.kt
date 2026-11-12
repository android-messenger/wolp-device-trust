package org.wolpmessenger.devicetrust

import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.wolpmessenger.devicetrust.api.E2eeException
import org.wolpmessenger.devicetrust.api.E2eeFailure
import org.wolpmessenger.devicetrust.e2ee.KeyDirectoryClient
import org.wolpmessenger.devicetrust.e2ee.OneTimeKey
import org.wolpmessenger.devicetrust.e2ee.OwnKeys
import org.wolpmessenger.devicetrust.e2ee.Passport
import org.wolpmessenger.devicetrust.e2ee.SignedKey
import java.util.Base64
import java.util.concurrent.TimeUnit

/** specs/002, story 3: the key directory over HTTP — formats of `key-directory/docs/API.md` and what each answer means. */
class KeyDirectoryClientTest {
    private val server = MockWebServer().apply { start() }
    private var cookie: String? = "ory_kratos_session=abc"
    private val client = KeyDirectoryClient({ OkHttpClient() }, server.url("/"), { cookie })

    @After
    fun stop() = server.shutdown()

    private fun b64(vararg b: Int) = Base64.getEncoder().encodeToString(ByteArray(b.size) { b[it].toByte() })
    private fun json(body: String) = MockResponse().setResponseCode(200).setBody(body)
    private fun take() = server.takeRequest(1, TimeUnit.SECONDS)!!

    private suspend fun refused(expected: E2eeFailure, block: suspend () -> Unit) {
        try {
            block()
            fail("expected $expected")
        } catch (e: E2eeException) {
            assertEquals(expected, e.failure)
        }
    }

    private fun device(extra: String = """, "pqPreKey": {"id": 7, "publicKey": "${b64(7, 7)}", "signature": "${b64(8)}"}, "registrationId": 4242""") = """
        {"deviceId": "d1", "identityKey": "${b64(1, 2, 3)}",
         "signedPreKey": {"id": 5, "publicKey": "${b64(4)}", "signature": "${b64(5, 6)}"},
         "oneTimePreKey": {"id": 100, "publicKey": "${b64(9)}"}, "oneTimePreKeyIsLastResort": false, "oneTimePreKeysRemaining": 19,
         "passport": {"signature": "${b64(10)}", "certificates": ["${b64(11)}", "${b64(12)}"]},
         "somethingNew": true $extra}"""

    @Test
    fun `fetch reads the peer's record with the passport and the post-quantum key`() = runTest {
        server.enqueue(json("""{"userId": "bob", "devices": [${device()}]}"""))
        val keys = client.fetch("bob")

        val request = take()
        assertEquals("GET", request.method)
        assertEquals("/key-directory/v1/keys/bob", request.path)
        assertEquals("the session of the account goes with every call", "ory_kratos_session=abc", request.getHeader("Cookie"))

        assertArrayEquals(byteArrayOf(1, 2, 3), keys.identityKey)
        assertEquals(4242, keys.registrationId)
        assertEquals(5, keys.signedPreKey.id)
        assertArrayEquals(byteArrayOf(5, 6), keys.signedPreKey.signature)
        assertEquals(7, keys.pqPreKey.id)
        assertArrayEquals(byteArrayOf(7, 7), keys.pqPreKey.publicKey)
        assertEquals(100, keys.oneTimePreKey!!.id)
        assertArrayEquals(byteArrayOf(10), keys.passport!!.signature)
        assertEquals(2, keys.passport!!.certificates.size)
    }

    @Test
    fun `fetch without a one-time key and without a passport still returns the record`() = runTest {
        val bare = device().replace(Regex(""""oneTimePreKey": \{[^}]*\}"""), """"oneTimePreKey": null""").replace(Regex(""""passport": \{[^}]*\},"""), "")
        server.enqueue(json("""{"userId": "bob", "devices": [$bare]}"""))
        val keys = client.fetch("bob")
        assertNull(keys.oneTimePreKey)
        assertNull("the protocol code refuses it as no_passport", keys.passport)
    }

    @Test
    fun `s3-6 - more than one device is refused`() = runTest {
        server.enqueue(json("""{"userId": "bob", "devices": [${device()}, ${device()}]}"""))
        refused(E2eeFailure.MULTI_DEVICE) { client.fetch("bob") }
    }

    @Test
    fun `s3-7 - no record means the peer has no device`() = runTest {
        server.enqueue(MockResponse().setResponseCode(404).setBody("""{"error":"no bundle"}"""))
        refused(E2eeFailure.NO_DEVICE) { client.fetch("bob") }
        server.enqueue(json("""{"userId": "bob", "devices": []}"""))
        refused(E2eeFailure.NO_DEVICE) { client.fetch("bob") }
        refused(E2eeFailure.NO_DEVICE) { client.fetch("../admin") } // never becomes a path
        assertEquals(2, server.requestCount)
    }

    @Test
    fun `a record without the post-quantum key was not published by the app`() = runTest {
        server.enqueue(json("""{"userId": "bob", "devices": [${device(extra = "")}]}"""))
        refused(E2eeFailure.NO_PASSPORT) { client.fetch("bob") }
    }

    @Test
    fun `s3-5 - no answer, a refusal or a malformed body is no_network`() = runTest {
        for (response in listOf(
            MockResponse().setResponseCode(401), MockResponse().setResponseCode(429), MockResponse().setResponseCode(503),
            json("not json"), json("""{"userId": "bob", "devices": [${device().replace(b64(1, 2, 3), "***")}]}"""),
        )) {
            server.enqueue(response)
            refused(E2eeFailure.NO_NETWORK) { client.fetch("bob") }
        }
        server.shutdown()
        refused(E2eeFailure.NO_NETWORK) { client.fetch("bob") }
        refused(E2eeFailure.NO_NETWORK) { client.record("bob") }
        refused(E2eeFailure.NO_NETWORK) { client.count("d1") }
    }

    @Test
    fun `publish sends the keys, the post-quantum key, the registration id and the passport`() = runTest {
        server.enqueue(json("""{"deviceId": "d1", "oneTimePreKeysRemaining": 2}"""))
        val keys = OwnKeys(byteArrayOf(1, 2, 3), 4242, SignedKey(5, byteArrayOf(4), byteArrayOf(5, 6)), SignedKey(7, byteArrayOf(7, 7), byteArrayOf(8)),
            listOf(OneTimeKey(100, byteArrayOf(9)), OneTimeKey(101, byteArrayOf(9, 9))))
        client.publish("d1", keys, Passport(byteArrayOf(10), listOf(byteArrayOf(11), byteArrayOf(12))))

        val request = take()
        assertEquals("POST", request.method)
        assertEquals("/key-directory/v1/keys", request.path)
        assertTrue(request.getHeader("Content-Type")!!.startsWith("application/json"))
        val body = JSONObject(request.body.readUtf8())
        assertEquals(setOf("deviceId", "identityKey", "signedPreKey", "oneTimePreKeys", "pqPreKey", "registrationId", "passport"), body.keys().asSequence().toSet())
        assertEquals("d1", body.getString("deviceId"))
        assertEquals(b64(1, 2, 3), body.getString("identityKey"))
        assertEquals(b64(5, 6), body.getJSONObject("signedPreKey").getString("signature"))
        assertEquals(7, body.getJSONObject("pqPreKey").getInt("id"))
        assertEquals(4242, body.getInt("registrationId"))
        assertEquals(101, body.getJSONArray("oneTimePreKeys").getJSONObject(1).getInt("id"))
        assertEquals(b64(10), body.getJSONObject("passport").getString("signature"))
        assertEquals(b64(12), body.getJSONObject("passport").getJSONArray("certificates").getString(1))

        server.enqueue(MockResponse().setResponseCode(409).setBody("""{"error":"the key record belongs to the user's phone"}"""))
        refused(E2eeFailure.NO_NETWORK) { client.publish("d1", keys, Passport(byteArrayOf(10), listOf(byteArrayOf(11)))) }
    }

    @Test
    fun `count, own record and replenishment`() = runTest {
        server.enqueue(json("""{"deviceId": "d1", "oneTimePreKeysRemaining": 17}"""))
        assertEquals(17, client.count("d1"))
        assertEquals("/key-directory/v1/keys/self/count?deviceId=d1", take().path)
        server.enqueue(MockResponse().setResponseCode(404))
        assertNull(client.count("d1"))
        take()

        server.enqueue(json("""{"userId": "alice", "deviceId": "d1", "identityKey": "${b64(1, 2, 3)}", "identityChangedAt": "2026-11-11T10:04:20Z",
            "passport": {"signature": "${b64(10)}", "certificates": ["${b64(11)}", "${b64(12)}"]}}"""))
        val record = client.record("alice")!!
        assertEquals("/key-directory/v1/keys/alice/identity", take().path)
        assertEquals("d1", record.deviceId)
        assertArrayEquals(byteArrayOf(1, 2, 3), record.identityKey)
        assertArrayEquals("the device certificate of the passport", byteArrayOf(11), record.passportCertificate)
        server.enqueue(MockResponse().setResponseCode(404))
        assertNull(client.record("alice"))
        take()

        server.enqueue(json("""{"deviceId": "d1", "oneTimePreKeysRemaining": 21}"""))
        assertTrue(client.replenish("d1", listOf(OneTimeKey(120, byteArrayOf(9)))))
        val request = take()
        assertEquals("/key-directory/v1/keys/one-time", request.path)
        assertEquals(120, JSONObject(request.body.readUtf8()).getJSONArray("oneTimePreKeys").getJSONObject(0).getInt("id"))
        server.enqueue(MockResponse().setResponseCode(404))
        assertFalse("the device is gone from the directory: publish instead", client.replenish("d1", emptyList()))
    }

    @Test
    fun `without a session the call still goes out and its refusal is no_network`() = runTest {
        cookie = null
        server.enqueue(MockResponse().setResponseCode(401))
        refused(E2eeFailure.NO_NETWORK) { client.count("d1") }
        assertNull(take().getHeader("Cookie"))
    }
}
