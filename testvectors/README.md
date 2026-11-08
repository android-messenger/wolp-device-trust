# Attestation test vectors

Real Android Key Attestation chains exported from each device of the S2 §13 matrix by
`tools/export-testvectors.sh` (or inside the sample app's "Share report" — the `testvectors` object). Consumer: the gateway attestation verifier (S3 §6.5).

Layout: `testvectors/<manufacturer>-<model>-api<sdk>/<case>.json`.

| Case | Key | Challenge |
|---|---|---|
| `tee-challenge` | TEE (no StrongBox requested) | `SHA-256("wolp-testvector/tee-challenge")` |
| `tee-no-challenge` | TEE | none → leaf has no KeyDescription |
| `strongbox-challenge` | StrongBox (only on devices declaring it) | `SHA-256("wolp-testvector/strongbox-challenge")` |

## Format (`schema: 1`)

```jsonc
{
  "schema": 1,
  "case": "tee-challenge",
  "exportedAt": "2026-11-08T19:08:53Z",
  "device": { "manufacturer", "brand", "model", "device", "sdkInt", "release", "securityPatch", "strongBoxFeature" },
  "app": {                       // what S3 compares with tag 709 (attestationApplicationId)
    "packageName": "org.wolpmessenger.devicetrust.sample",
    "versionCode": 10300,
    "signingDigestsSha256": ["<hex>"]  // debug signing key of the exporting build
  },
  "key": { "requestedStrongBox", "securityLevel", "hardwareConfirmed" },  // KeyInfo as the client saw it
  "challengeB64": "<base64>" | null,
  "chainType": "rkp" | "factory",     // client hint by extension presence; S3 decides by roots
  "hasKeyDescription": true,
  "chainB64": ["<DER leaf>", "...", "<DER root>"],
  "csrB64": "<DER PKCS#10>"            // signed by the attested key; SPKI == leaf SPKI (S3 §5.2 п. 2)
}
```

The gateway test runs its policy with `DEVICES_APP_PACKAGE` / `DEVICES_APP_SIGNING_DIGESTS` /
`DEVICES_MIN_APP_VERSION_CODE` taken from `app`, so the vectors stay valid although they are
not signed by the production key.

## Exported so far

| Directory | Level | Expected S3 verdict |
|---|---|---|
| `Google-sdk_gphone64_x86_64-api34` (emulator, System image 2023-09) | `SOFTWARE`; chain to *Droid Unregistered Device CA, Google Test LLC* | **reject**: `ROOT_UNTRUSTED` (untrusted root), and `SECURITY_LEVEL_SOFTWARE` if the root check were bypassed |

Hardware vectors (Pixel 8+, Samsung Knox Vault, Samsung A, a factory-chain device) are pending
devices — see S2 §13.

## `continuity/continuity-v1.json` — `continuitySig` (S3 §5.4, §5.6)

Generated independently (Python `cryptography`) and checked by the library's JVM tests, so the
Kotlin signer and the Go verifier agree byte for byte. Per vector: inputs (`prefix`
`wolp-renew-v1` / `wolp-reattest-v1`, `deviceId`, `certSerialHex` — high bit set on purpose, the
serial is encoded big-endian **without** a sign byte, `nonceB64`, `newKeySpkiB64`,
`attestationChainB64`), the exact signed `payloadHex`, the old key `oldKeySpkiB64` and a valid
`continuitySigB64` (DER ECDSA P-256/SHA-256).
