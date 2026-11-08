#!/usr/bin/env bash
# Keystore (TEE vs StrongBox) and Vault measurements on the connected device → bench/<model>.json (S2 §3, §9).
# The same numbers are shown by the sample app's "Measurements" card.
# Usage: tools/bench.sh [-s <serial>]
set -euo pipefail
source "$(dirname "$0")/adb-env.sh"
[ "${1:-}" = "-s" ] && ADB="$ADB -s $2"
run_sample_test measure bench bench
