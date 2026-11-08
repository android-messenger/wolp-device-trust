package org.wolpmessenger.devicetrust.asn1

import org.wolpmessenger.devicetrust.InternalDeviceTrustApi
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature

/**
 * PKCS#10 certification request for the device key (S2 §6.2 п. 5):
 * empty subject, the key's SubjectPublicKeyInfo, no attributes, `ecdsa-with-SHA256`.
 * The gateway ignores the subject and takes identity from the session (S3 §5.2).
 */
@InternalDeviceTrustApi
public object Csr {
    public const val OID_ECDSA_WITH_SHA256: String = "1.2.840.10045.4.3.2"

    /** DER of the signed request. [sign] returns a DER ECDSA signature over its input. */
    public fun build(publicKey: PublicKey, sign: (ByteArray) -> ByteArray): ByteArray {
        require(publicKey.format == "X.509") { "public key must encode as SubjectPublicKeyInfo" }
        val info = Der.sequence(
            Der.integer(0),                 // version v1
            Der.sequence(),                 // subject: empty Name
            publicKey.encoded,              // SubjectPublicKeyInfo, already DER
            Der.contextConstructed(0),      // attributes: empty
        )
        return Der.sequence(info, Der.sequence(Der.oid(OID_ECDSA_WITH_SHA256)), Der.bitString(sign(info)))
    }

    /** Signs with a Keystore (or any) EC private key via `SHA256withECDSA`. */
    public fun build(publicKey: PublicKey, privateKey: PrivateKey): ByteArray = build(publicKey) { info ->
        Signature.getInstance("SHA256withECDSA").run {
            initSign(privateKey)
            update(info)
            sign()
        }
    }
}
