package org.wolpmessenger.devicetrust.rasp

import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** The JNI entry point; `scan` is registered by `JNI_OnLoad` (RegisterNatives), not exported. */
internal object NativeRasp {
    val loaded: Boolean by lazy { runCatching { System.loadLibrary("wolpdt") }.isSuccess }

    @JvmStatic
    external fun scan(key: ByteArray): ByteArray?
}

/** Native results, or why they are unusable. */
internal sealed interface NativeResult {
    data class Ok(val probes: Map<String, Probe>) : NativeResult

    /** Library missing, HMAC mismatch or malformed output: reported as HOOK_TAMPER. */
    data class Tampered(val why: String) : NativeResult
}

/**
 * Native side of the checks (S2 §7.5): the result travels through JNI with an HMAC-SHA256 under a
 * per-process session key, so a hook that simply replaces the returned value is detected.
 */
internal class NativeChecks(private val call: (ByteArray) -> ByteArray? = { NativeRasp.takeIf { it.loaded }?.scan(it) }) {
    private val key = ByteArray(32).also(SecureRandom()::nextBytes)

    fun scan(): NativeResult {
        val raw = try {
            call(key)
        } catch (e: Throwable) { // UnsatisfiedLinkError and friends
            null
        } ?: return NativeResult.Tampered("native unavailable")
        return parse(raw, key)
    }

    internal companion object {
        fun parse(raw: ByteArray, key: ByteArray): NativeResult {
            if (raw.size < 32) return NativeResult.Tampered("short")
            val body = raw.copyOfRange(0, raw.size - 32)
            val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(key, "HmacSHA256")) }.doFinal(body)
            if (!MessageDigest.isEqual(mac, raw.copyOfRange(raw.size - 32, raw.size))) return NativeResult.Tampered("jni hmac")
            val probes = mutableMapOf<String, Probe>()
            for (line in String(body, Charsets.UTF_8).split('\n')) {
                if (line.isEmpty()) continue
                val parts = line.split('|', limit = 3)
                val state = parts.getOrNull(1)?.singleOrNull()?.let(ProbeState::of)
                if (parts.size != 3 || state == null) return NativeResult.Tampered("malformed")
                probes[parts[0]] = Probe(state, parts[2])
            }
            return NativeResult.Ok(probes)
        }
    }
}
