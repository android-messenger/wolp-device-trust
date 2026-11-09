# wolp-device-trust

Android device-trust library for the Wolp messenger app (`org.wolpmessenger`): Keystore keys,
key attestation, mTLS certificates, RASP, Vault. Specification: `android-messenger/docs` →
`specs/S2-device-trust-lib.md` (gateway contracts: `specs/S3-gateway.md`).

## Status — stages 1–6 and 7a of S2 §14

| Done | Where |
|---|---|
| Keystore keys: EC P-256 signing key with attestation challenge, StrongBox → TEE fallback (S2 §3), hardware-level check (`SOFTWARE`/`UNKNOWN*` rejected and deleted), alias numbering, orphan cleanup | `devicetrust/…/keys/` |
| Attestation chain wrapper (DER for `enroll/finish`, RKP/factory label) | `devicetrust/…/attest/AttestationChain.kt` |
| Precheck (S2 §6.1): RASP hook → Keystore level (cached per boot + app version) → patch age → screen lock as REPORT | `devicetrust/…/attest/Precheck.kt` |
| Test-vector export for S3 | `sample/…/TestVectorExporter.kt`, `tools/export-testvectors.sh`, `testvectors/` |
| TEE vs StrongBox measurements (keygen, signature latency, concurrent signing) | `sample/…/Diagnostics.kt`, `tools/bench.sh` |
| Vault (S2 §9): KEK `dt.vault` in Keystore wraps only the DEK (`dt/dek.bin`, one Keystore call per process); `wrap`/`unwrap` = software AES-256-GCM with authenticated header and purpose; `KeyGone` / `Locked` / `Corrupt`; `provision`, `wipe`, partial-state detection for §6.6 | `devicetrust/…/vault/`, `api/Vault.kt` |
| Vault measurements (DEK unwrap, wrap/unwrap 4 KiB) | `sample/…/Diagnostics.kt`, `tools/bench.sh` |
| DER encoder + PKCS#10 CSR (empty subject, SPKI, `ecdsa-with-SHA256`), verified by OpenSSL in JVM tests and on-device with a Keystore key; CSR in every test vector | `devicetrust/…/asn1/` |
| `TrustClock` (S2 §5.2): server `Date` from the pinned channel + `elapsedRealtime`, per-boot anchor, `trustNow()` null until known | `devicetrust/…/clock/` |
| Gateway errors: `GatewayCode` (S3 §5.9), body `{"error",…}` with `X-Device-Deny` fallback, `Retry-After` | `api/GatewayCode.kt`, `net/GatewayError.kt` |
| `enroll/start` body encoded straight to bytes — the password never becomes a `String` (S2 §6.2 п. 2) | `enroll/EnrollStartBody.kt` |
| State store: `state.json` + `certs/<N>.pem`, atomic writes, single-lock read-modify-write | `store/TrustStore.kt` |
| Gateway client over the pinned OkHttp client (`enroll/start`, `enroll/finish`), clock fed only by successful pinned responses | `net/GatewayClient.kt`, `net/HttpClients.kt` |
| Enrollment S2 §6.2: precheck → start → key bound to nonce → CSR → persisted intent → finish → Vault → `ENROLLED`; every S3 §5.1–5.2 answer mapped (wrong/burned/expired password, policy vs soft rejection, `NONCE_INVALID` retry once, lost response keeps the intent for replay) | `enroll/Enroller.kt` |
| `DeviceTrust` facade (`init`, `state`, `credentialsVersion`, `events`, `trustNow`, `precheck`, `enroll`, `ensureFresh`, `unenroll`, `clientCredentials`, `okHttpClient`, `updateHttpClient`, `vault`, `deviceInfo`); `TrustState` derived from phase + clock | `DeviceTrust.kt`, `DeviceTrustCore.kt` |
| Renewal S2 §6.3 over mTLS with the current key (`renew/challenge` → new key bound to the nonce → `renew` with `continuitySig` → `pending` → switch, `credentialsVersion++`, pool evicted → `confirm` with the new key) | `cert/CertManager.kt`, `tls/FixedKeyManager.kt` |
| Recovery S2 §6.4 (`reattest/*`): after expiry within grace and after a lost renewal response (`CERT_SUPERSEDED`); `REATTEST_NOT_ALLOWED` → `ReEnrollRequired` with the Vault kept | `cert/CertManager.kt` |
| `continuitySig` (S3 §5.4) checked against independent vectors shared with the gateway | `cert/ContinuitySig.kt`, `testvectors/continuity/` |
| Gateway denials on the pinned channel: `UPDATE_REQUIRED`, destructive codes → local BLOCK (intent first, everything wiped, `Blocked` event; no message, S2 §8) | `cert/CertManager.kt` |
| Alerts (S2 §8, §7.4, S3 §5.7): RASP BLOCK in the strict order (message signed by the current key **before** the wipe → persisted → intent → wipe → event → sender); unsigned before enrollment, sent with the Kratos cookie read at send time; REPORT rate limit per (id, detail) per 24 h, batches of 20, queue of 100; `AlertWorker` (WorkManager, network, backoff, 7-day lifetime; `400` dropped) | `alert/` |
| `onGatewayDenied(code, source)` (S2 §5.3, R3): `PINNED_CLIENT` acted upon (R7 already applied by the client); `WEBVIEW` only triggers `GET /v1/device/ping` over the pinned channel (≤ 1 per 30 s) and the action follows the ping's code; a failed ping (network, pinning) deletes nothing — tested over real TLS with a fake server whose CA is trusted but whose key is not pinned (S2 §15 п. 7) | `DeviceTrustCore.kt`, `cert/CertManager.kt` |
| `checkSessionBinding(cookie)` → `GET /v1/device/whoami` (S3 §5.8c): `Match` / `Mismatch` / `NoSession` / `Failed(NO_CREDENTIALS\|NETWORK\|DENIED)` | `DeviceTrustCore.kt`, `api/SessionBinding.kt` |
| Instrumented: full mTLS handshake (TLS 1.3 and 1.2) with a **Keystore** key through `DeviceHttp` against a client-auth server — fails without `DIGEST_NONE` (verified on the A37) | `androidTest/…/KeystoreMtlsDeviceTest.kt` |
| RASP (S2 §7): Kotlin checks (`android.system.Os` syscalls) + native `libwolpdt.so` (`devicetrust-native/`, C; only `JNI_OnLoad` exported, `RegisterNatives`, result HMAC-SHA256 under a per-process key); ROOT_SU / DEBUGGER / EMULATOR in both, compared → `HOOK_TAMPER`; Magisk, props, Frida maps/threads/port natively; Xposed, signature, debuggable, software Keystore, settings in Kotlin | `rasp/`, `devicetrust-native/` |
| Policy S2 §7.3 at runtime: effective build kind (debuggable / pilot `versionCode` / else RELEASE), downgrades ignored in RELEASE, dry run → `dryRun;BLOCK;…` REPORT; runs at init, on foreground + every 5 min, before enroll/renew/recover, `checkIntegrity()` | `rasp/RaspEngine.kt`, `DeviceTrust.kt` |
| Real RASP pass on the A37: Kotlin = native, HMAC verifies, no false BLOCK | `androidTest/…/RaspDeviceTest.kt` |
| **7a** native hardening (S2 §7.5): every string literal of `libwolpdt.so` (paths, tokens, properties, check ids, JNI names) lives in `devicetrust-native/strings.txt`, is encrypted at build time (`generateNativeStrings` → `wolpdt_strings.h`) and decrypted onto the stack only while used; `checkNativeStrings` fails the build if any of them is readable in the packaged `.so` | `devicetrust-native/`, `devicetrust/build.gradle.kts` |
| **7a** native `APK_SIGNATURE`: the installed `base.apk` (found in `/proc/self/maps`, not via PackageManager) → APK Signing Block v3.1 / v3 (by SDK) / v2 → SHA-256 of the signer certificates; dual with the Kotlin (PackageManager) check → a PackageManager hook is `HOOK_TAMPER`. Host tests on APKs signed by `apksigner` (v2, v3, v1-only, v3.1 rotation) + fuzzing; on the A37 native = Kotlin | `devicetrust-native/src/apksig.c`, `devicetrust-native/test/` |
| `unenroll()` (S2 §6.5a): signed `UNENROLL` queued first (only with a key), intent `UNENROLLING`, everything wiped, `NotEnrolled`; completes in every state (R5) | `cert/CertManager.kt` |
| Start-up reconciliation S2 §6.6: sticky BLOCK / unenrolling, `pending` switch, `enroll/finish` replay, orphans, `VaultReset`, lifting `UpdateRequired` after an update | `cert/CertManager.kt` |
| `ensureFresh` (serialised), deadline timer, `RenewWorker` (WorkManager, network, exponential backoff) | `DeviceTrust.kt`, `cert/RenewWorker.kt` |
| `okHttpClient()`: mTLS + pinning, certificate resolved at handshake time; on `credentialsVersion` change the pool is evicted **and** new connections use a fresh SSLContext (otherwise TLS session resumption keeps the old client identity — Conscrypt cannot invalidate client sessions); R7 built in (denial for a superseded serial → one retry on a fresh connection, HTTP/2-safe); successful responses feed the clock. `updateHttpClient()`: system CAs only. Tests run on the JVM **and** on the phone (`src/sharedTest`) | `tls/DeviceHttp.kt` |

Every `suspend` function of the `DeviceTrust` facade is main-safe (runs on `Dispatchers.IO`).
Next (stage 7): pilot build, API docs. Building blocks
are public only behind the `@InternalDeviceTrustApi` opt-in.

**Open in stages 1–2:** measurements and hardware test vectors need the S2 §13 device matrix
(Pixel 8+, Samsung with Knox Vault, Samsung A, a factory-chain device). On the emulator the
Keystore is software: precheck → `Unsupported(SOFTWARE_KEYSTORE)` (S2 §15 п. 2, verified).
Emulator Vault numbers (software KEK, not representative): wrap/unwrap 4 KiB p95 0.22 ms, DEK unwrap p95 1.8 ms
(targets: 1 ms / 50 ms on the matrix).

## Sample app (try it on a phone)

`sample/` — Compose app, no gateway needed: device facts, precheck, key attestation (TEE and
StrongBox, chain shown), Keystore/Vault measurements against the S2 targets, and **Share report** —
one JSON with all results plus fresh attestation test vectors, sent via the system share sheet.

```bash
./gradlew :sample:assembleDebug
adb install -r sample/build/outputs/apk/debug/sample-debug.apk   # or copy the APK to the phone
```
CI also publishes the APK as the `sample-debug-apk` artifact of every run.

## Build

Gradle 8.14 needs JDK 17–21 (`JAVA_HOME=/opt/jdk-21.0.2` here; the tools pick one automatically).

```bash
./gradlew :devicetrust:testDebugUnitTest          # JVM tests
./gradlew :devicetrust:connectedDebugAndroidTest  # on a device/emulator: real Keystore
./gradlew checkForbiddenDependencies              # no Firebase / Play Services (S2 §15 п. 1)
devicetrust-native/test/run.sh <apk>             # native host tests (ASan/UBSan; needs cc, keytool, apksigner)
./gradlew :devicetrust:checkNativeStrings         # no plain-text check strings in libwolpdt.so
tools/bench.sh [-s serial]                        # → bench/<model>.json (Keystore + Vault)
tools/export-testvectors.sh [-s serial]           # → testvectors/<model>/*.json
```
