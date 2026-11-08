package org.wolpmessenger.devicetrust.api

import java.security.PrivateKey
import java.security.cert.X509Certificate

/**
 * Client certificate for mTLS (S2 §10): the AndroidKeyStore key handle (non-extractable) and
 * `[leaf, intermediate]`. S1 passes them to `ClientCertRequest.proceed`.
 */
public class ClientCredentials(public val privateKey: PrivateKey, public val chain: Array<X509Certificate>)
