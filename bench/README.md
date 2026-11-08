# Device measurements (S2 §3, §9, §15 п. 8)

Produced by `tools/bench.sh` or the sample app's "Measurements" card. Milliseconds.

| Device | Key | Keygen p50 | Sign p50 / p95 | 6 threads × 20 signs: p95 / wall | Vault DEK unwrap p95 (≤ 50) | wrap / unwrap 4 KiB p95 (≤ 1) |
|---|---|---|---|---|---|---|
| Galaxy A37 5G `SM-A376B`, Android 16, 2026-11-08 | TEE (no StrongBox) | 48 | 4.6 / 5.4 | 52 / 483 | **8.7** ✓ | **0.11 / 0.09** ✓ |

Reading: a full mTLS handshake costs one signature ≈ 5 ms in TEE; a WebView cold start with
6 parallel connections serialises in the TEE (≈ 0.5 s for 120 signatures, i.e. ~6 handshakes ≈ 30 ms).
StrongBox numbers (Pixel 8+, Knox Vault) are still needed to decide `deviceKeyStrongBox` (S2 §3, R4).
