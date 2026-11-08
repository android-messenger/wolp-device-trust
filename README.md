# wolp-device-trust

Android device-trust library for the Wolp messenger app (`org.wolpmessenger`): Keystore keys,
key attestation, mTLS certificates, RASP, Vault. Specification: `android-messenger/docs` →
`specs/S2-device-trust-lib.md` (gateway contracts: `specs/S3-gateway.md`).

## Status — stages 1–3 of S2 §14

| Done | Where |
|---|---|
| Keystore keys: EC P-256 signing key with attestation challenge, StrongBox → TEE fallback (S2 §3), hardware-level check (`SOFTWARE`/`UNKNOWN*` rejected and deleted), alias numbering, orphan cleanup | `devicetrust/…/keys/` |
| Attestation chain wrapper (DER for `enroll/finish`, RKP/factory label) | `devicetrust/…/attest/AttestationChain.kt` |
| Precheck (S2 §6.1): RASP hook → Keystore level (cached per boot + app version) → patch age → screen lock as REPORT | `devicetrust/…/attest/Precheck.kt` |
| Test-vector export for S3 | `testvectors-export/`, `tools/export-testvectors.sh`, `testvectors/` |
| TEE vs StrongBox measurements (keygen, signature latency, concurrent signing) | `devicetrust/src/androidTest/…/KeyBenchmarkTest.kt`, `tools/bench.sh` |
| Vault (S2 §9): KEK `dt.vault` in Keystore wraps only the DEK (`dt/dek.bin`, one Keystore call per process); `wrap`/`unwrap` = software AES-256-GCM with authenticated header and purpose; `KeyGone` / `Locked` / `Corrupt`; `provision`, `wipe`, partial-state detection for §6.6 | `devicetrust/…/vault/`, `api/Vault.kt` |
| Vault measurements (DEK unwrap, wrap/unwrap 4 KiB) | `VaultDeviceTest#measure`, `tools/bench.sh` |
| DER encoder + PKCS#10 CSR (empty subject, SPKI, `ecdsa-with-SHA256`), verified by OpenSSL in JVM tests and on-device with a Keystore key; CSR in every test vector | `devicetrust/…/asn1/` |
| `TrustClock` (S2 §5.2): server `Date` from the pinned channel + `elapsedRealtime`, per-boot anchor, `trustNow()` null until known | `devicetrust/…/clock/` |
| Gateway errors: `GatewayCode` (S3 §5.9), body `{"error",…}` with `X-Device-Deny` fallback, `Retry-After` | `api/GatewayCode.kt`, `net/GatewayError.kt` |
| `enroll/start` body encoded straight to bytes — the password never becomes a `String` (S2 §6.2 п. 2) | `enroll/EnrollStartBody.kt` |
| State store: `state.json` + `certs/<N>.pem`, atomic writes, single-lock read-modify-write | `store/TrustStore.kt` |
| Gateway client over the pinned OkHttp client (`enroll/start`, `enroll/finish`), clock fed only by successful pinned responses | `net/GatewayClient.kt`, `net/HttpClients.kt` |
| Enrollment S2 §6.2: precheck → start → key bound to nonce → CSR → persisted intent → finish → Vault → `ENROLLED`; every S3 §5.1–5.2 answer mapped (wrong/burned/expired password, policy vs soft rejection, `NONCE_INVALID` retry once, lost response keeps the intent for replay) | `enroll/Enroller.kt` |
| `DeviceTrust` facade (stage-3 surface: `init`, `state`, `credentialsVersion`, `trustNow`, `precheck`, `enroll`, `clientCredentials`, `vault`, `deviceInfo`); `TrustState` derived from phase + clock | `DeviceTrust.kt`, `DeviceTrustCore.kt` |

The `DeviceTrust` facade (S2 §4) grows with each stage: renewal/recovery and the full init
reconciliation (stage 4), mTLS clients (stage 5), RASP/BLOCK/unenroll (stage 6). Building blocks
are public only behind the `@InternalDeviceTrustApi` opt-in.

**Open in stages 1–2:** measurements and hardware test vectors need the S2 §13 device matrix
(Pixel 8+, Samsung with Knox Vault, Samsung A, a factory-chain device). On the emulator the
Keystore is software: precheck → `Unsupported(SOFTWARE_KEYSTORE)` (S2 §15 п. 2, verified).
Emulator Vault numbers (software KEK, not representative): wrap/unwrap 4 KiB p95 0.22 ms, DEK unwrap p95 1.8 ms
(targets: 1 ms / 50 ms on the matrix).

## Build

Gradle 8.14 needs JDK 17–21 (`JAVA_HOME=/opt/jdk-21.0.2` here; the tools pick one automatically).

```bash
./gradlew :devicetrust:testDebugUnitTest          # JVM tests
./gradlew :devicetrust:connectedDebugAndroidTest  # on a device/emulator: real Keystore
./gradlew checkForbiddenDependencies              # no Firebase / Play Services (S2 §15 п. 1)
tools/bench.sh [-s serial]                        # → bench/<model>.json, bench/vault-<model>.json
tools/export-testvectors.sh [-s serial]           # → testvectors/<model>/*.json
```
