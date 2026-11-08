# wolp-device-trust

Android device-trust library for the Wolp messenger app (`org.wolpmessenger`): Keystore keys,
key attestation, mTLS certificates, RASP, Vault. Specification: `android-messenger/docs` →
`specs/S2-device-trust-lib.md` (gateway contracts: `specs/S3-gateway.md`).

## Status — stage 1 of S2 §14

| Done | Where |
|---|---|
| Keystore keys: EC P-256 signing key with attestation challenge, StrongBox → TEE fallback (S2 §3), hardware-level check (`SOFTWARE`/`UNKNOWN*` rejected and deleted), alias numbering, orphan cleanup | `devicetrust/…/keys/` |
| Attestation chain wrapper (DER for `enroll/finish`, RKP/factory label) | `devicetrust/…/attest/AttestationChain.kt` |
| Precheck (S2 §6.1): RASP hook → Keystore level (cached per boot + app version) → patch age → screen lock as REPORT | `devicetrust/…/attest/Precheck.kt` |
| Test-vector export for S3 | `testvectors-export/`, `tools/export-testvectors.sh`, `testvectors/` |
| TEE vs StrongBox measurements (keygen, signature latency, concurrent signing) | `devicetrust/src/androidTest/…/KeyBenchmarkTest.kt`, `tools/bench.sh` |

The public `DeviceTrust` facade (S2 §4) arrives with the state store (stage 3). Until then the
building blocks are public only behind the `@InternalDeviceTrustApi` opt-in.

**Open in stage 1:** measurements and hardware test vectors need the S2 §13 device matrix
(Pixel 8+, Samsung with Knox Vault, Samsung A, a factory-chain device). On the emulator the
Keystore is software: precheck → `Unsupported(SOFTWARE_KEYSTORE)` (S2 §15 п. 2, verified).

## Build

Gradle 8.14 needs JDK 17–21 (`JAVA_HOME=/opt/jdk-21.0.2` here; the tools pick one automatically).

```bash
./gradlew :devicetrust:testDebugUnitTest          # JVM tests
./gradlew :devicetrust:connectedDebugAndroidTest  # on a device/emulator: real Keystore
./gradlew checkForbiddenDependencies              # no Firebase / Play Services (S2 §15 п. 1)
tools/bench.sh [-s serial]                        # → bench/<model>.json
tools/export-testvectors.sh [-s serial]           # → testvectors/<model>/*.json
```
