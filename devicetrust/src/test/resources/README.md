Self-signed EC certificates for JVM tests of `AttestationChain` (not real attestation):
- `plain.pem` — no Android extensions;
- `with-key-description.pem` — empty KeyDescription extension (OID 1.3.6.1.4.1.11129.2.1.17);
- `with-provisioning-info.pem` — empty provisioning-info extension (OID 1.3.6.1.4.1.11129.2.1.30).

Regenerate: `openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj /CN=… -addext "<oid>=DER:3000" …`.
