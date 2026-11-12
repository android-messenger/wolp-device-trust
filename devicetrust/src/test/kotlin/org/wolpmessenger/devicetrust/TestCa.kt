package org.wolpmessenger.devicetrust

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.wolpmessenger.devicetrust.e2ee.PassportTrust
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.util.Date

/**
 * Test certificate authority with the gateway's device profile (gate `signer/profile.go`): root →
 * intermediate → device certificate with `urn:wolp:device:` and `urn:wolp:user:` names, clientAuth,
 * CA:false. Every deviation a passport check must catch is a parameter of [device].
 */
internal class TestCa(private val name: String = "test", private val at: Instant = Instant.ofEpochMilli(1_800_000_000_000L)) {
    val rootKey = ecKey()
    val root = certificate("CN=$name root", rootKey, "CN=$name root", rootKey, ca = true)
    val issuerKey = ecKey()
    val issuer = certificate("CN=$name devices", issuerKey, "CN=$name root", rootKey, ca = true)

    /** Trusts this root and this issuer only. */
    val trust = PassportTrust(listOf(root), listOf(spkiSha256(issuer)))

    fun device(
        user: String,
        deviceId: String = "01JCZ8K3W9D5V7H2Q4N6M8P0RT",
        key: KeyPair = ecKey(),
        notBefore: Instant = at.minusSeconds(300),
        notAfter: Instant = at.plusSeconds(24 * 3600),
        ca: Boolean = false,
        clientAuth: Boolean = true,
        names: List<String> = listOf("urn:wolp:device:$deviceId", "urn:wolp:user:$user"),
    ): X509Certificate = certificate("CN=$deviceId", key, "CN=$name devices", issuerKey, ca, clientAuth, names, notBefore, notAfter)

    private fun certificate(
        subject: String, key: KeyPair, issuerName: String, signer: KeyPair, ca: Boolean,
        clientAuth: Boolean = false, names: List<String> = emptyList(),
        notBefore: Instant = at.minusSeconds(365L * 24 * 3600), notAfter: Instant = at.plusSeconds(365L * 24 * 3600),
    ): X509Certificate {
        val b = JcaX509v3CertificateBuilder(X500Name(issuerName), BigInteger(120, SecureRandom()), Date.from(notBefore), Date.from(notAfter), X500Name(subject), key.public)
        b.addExtension(Extension.basicConstraints, true, BasicConstraints(ca))
        b.addExtension(Extension.keyUsage, true, KeyUsage(if (ca) KeyUsage.keyCertSign or KeyUsage.cRLSign else KeyUsage.digitalSignature))
        if (clientAuth) b.addExtension(Extension.extendedKeyUsage, false, ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth))
        if (names.isNotEmpty()) {
            b.addExtension(Extension.subjectAlternativeName, false, GeneralNames(names.map { GeneralName(GeneralName.uniformResourceIdentifier, it) }.toTypedArray()))
        }
        return JcaX509CertificateConverter().getCertificate(b.build(JcaContentSignerBuilder("SHA256withECDSA").build(signer.private)))
    }

    companion object {
        fun ecKey(): KeyPair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

        fun spkiSha256(c: X509Certificate): String = MessageDigest.getInstance("SHA-256").digest(c.publicKey.encoded).joinToString("") { "%02x".format(it) }
    }
}
