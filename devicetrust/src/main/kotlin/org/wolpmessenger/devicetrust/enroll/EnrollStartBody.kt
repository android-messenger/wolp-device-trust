package org.wolpmessenger.devicetrust.enroll

import org.wolpmessenger.devicetrust.InternalDeviceTrustApi
import java.io.ByteArrayOutputStream
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

/** `precheck` block of `enroll/start` — journal and metrics only (S3 §5.1). */
@InternalDeviceTrustApi
public data class PrecheckSummary(val securityLevel: String, val strongBox: Boolean, val sdkInt: Int, val securityPatch: String)

/**
 * Body of `POST /v1/enroll/start`, written straight into a `ByteArray` — the password never
 * becomes a `String` (S2 §6.2 п. 2). The caller zeroes the returned array after sending;
 * intermediate buffers are zeroed here.
 */
@InternalDeviceTrustApi
public object EnrollStartBody {
    public fun encode(password: CharArray, appVersionCode: Long, precheck: PrecheckSummary): ByteArray {
        val out = ZeroingBuffer()
        try {
            out.ascii("{\"onboardingPassword\":")
            out.jsonString(password)
            out.ascii(",\"appVersionCode\":$appVersionCode,\"precheck\":{\"securityLevel\":")
            out.jsonString(precheck.securityLevel.toCharArray())
            out.ascii(",\"strongBox\":${precheck.strongBox},\"sdkInt\":${precheck.sdkInt},\"securityPatch\":")
            out.jsonString(precheck.securityPatch.toCharArray())
            out.ascii("}}")
            return out.toByteArray()
        } finally {
            out.wipe()
        }
    }

    /**
     * ByteArrayOutputStream whose internal buffer can be zeroed. Sized so that a normal body
     * never grows it (growth would leave an unzeroed copy behind).
     */
    private class ZeroingBuffer : ByteArrayOutputStream(2048) {
        fun ascii(s: String) {
            for (ch in s) write(ch.code)
        }

        fun jsonString(chars: CharArray) {
            write('"'.code)
            val escaped = CharArray(chars.size * 6)
            var n = 0
            for (ch in chars) {
                val esc = when {
                    ch == '"' -> "\\\""
                    ch == '\\' -> "\\\\"
                    ch < ' ' -> "\\u%04x".format(ch.code)
                    else -> null
                }
                if (esc == null) escaped[n++] = ch else esc.forEach { escaped[n++] = it }
            }
            val encoder = StandardCharsets.UTF_8.newEncoder()
                .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
            val bytes = encoder.encode(CharBuffer.wrap(escaped, 0, n))
            val tmp = ByteArray(bytes.remaining()).also(bytes::get)
            write(tmp)
            tmp.fill(0)
            if (bytes.hasArray()) bytes.array().fill(0)
            escaped.fill('\u0000')
            write('"'.code)
        }

        fun wipe() {
            buf.fill(0)
            count = 0
        }
    }
}
