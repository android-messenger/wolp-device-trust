package org.wolpmessenger.devicetrust.api

/** Where S1 saw a gateway denial (S2 §5.3, R3). */
public enum class DenySource {
    /** A response to `DeviceTrust.okHttpClient()`: server key pinned, R7 already applied. */
    PINNED_CLIENT,

    /** `X-Device-Deny` seen in the WebView: not pinned on every WebView, so destructive codes only trigger a check. */
    WEBVIEW,
}
