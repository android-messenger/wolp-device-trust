package org.wolpmessenger.devicetrust.api

/** Why `checkSessionBinding` could not answer. S1 never offers unenroll on these (S2 §4, D15). */
public enum class BindingFailure {
    /** No valid client certificate (state is not Active / RenewalDue). */
    NO_CREDENTIALS,

    /** Network, timeout or server-key pinning failure. */
    NETWORK,

    /** The gateway refused the device itself; the code was handled as a pinned denial (S2 §5.3). */
    DENIED,
}

/** Is the Kratos session in the WebView the device owner's? (`GET /v1/device/whoami`, S3 §5.8c). */
public sealed interface SessionBinding {
    public data object Match : SessionBinding

    /** Confirmed over the pinned channel: S1 logs out of Kratos and shows "contact your administrator". */
    public data object Mismatch : SessionBinding
    public data object NoSession : SessionBinding
    public data class Failed(val cause: BindingFailure, val code: GatewayCode? = null) : SessionBinding
}
