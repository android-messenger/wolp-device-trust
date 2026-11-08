package org.wolpmessenger.devicetrust.attest

import org.wolpmessenger.devicetrust.InternalDeviceTrustApi
import java.security.cert.X509Certificate

/** Kind of attestation chain, as the gateway labels it (S3 §6.1 п. 6). */
@InternalDeviceTrustApi
public enum class ChainType {
    /** Remotely provisioned keys: a certificate carries the provisioning-info extension. */
    RKP,

    /** No provisioning info: factory-provisioned keys (or a non-Google chain, e.g. an emulator — only S3 can tell). */
    FACTORY,
}

/**
 * Key attestation chain, leaf first. The client does not validate it — the gateway does
 * (S3 §6, R2). The client only ships it and labels it for diagnostics and test vectors.
 */
@InternalDeviceTrustApi
public class AttestationChain(public val certificates: List<X509Certificate>) {
    init {
        require(certificates.isNotEmpty()) { "empty attestation chain" }
    }

    public val leaf: X509Certificate get() = certificates.first()

    /** The leaf carries the KeyDescription extension (absent for keys generated without a challenge). */
    public val hasKeyDescription: Boolean get() = leaf.getExtensionValue(OID_KEY_DESCRIPTION) != null

    public val chainType: ChainType
        get() = if (certificates.any { it.getExtensionValue(OID_PROVISIONING_INFO) != null }) ChainType.RKP else ChainType.FACTORY

    /** DER of every certificate, leaf first — the wire form for `enroll/finish` (S3 §5.2). */
    public fun encoded(): List<ByteArray> = certificates.map { it.encoded }

    public companion object {
        public const val OID_KEY_DESCRIPTION: String = "1.3.6.1.4.1.11129.2.1.17"
        public const val OID_PROVISIONING_INFO: String = "1.3.6.1.4.1.11129.2.1.30"
    }
}
