#!/usr/bin/env bash
# Export attestation test vectors from the connected device into testvectors/<model>/ (S2 §13, S3 §6.5).
# Usage: tools/export-testvectors.sh [-s <serial>]
set -euo pipefail
source "$(dirname "$0")/adb-env.sh"
[ "${1:-}" = "-s" ] && ADB="$ADB -s $2"
run_sample_test exportTestVectors testvectors testvectors
