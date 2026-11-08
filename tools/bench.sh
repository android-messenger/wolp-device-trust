#!/usr/bin/env bash
# Stage-1 Keystore measurements (TEE vs StrongBox) on the connected device → bench/<model>.json (S2 §3).
# Usage: tools/bench.sh [-s <serial>]
set -euo pipefail
source "$(dirname "$0")/adb-env.sh"
[ "${1:-}" = "-s" ] && ADB="$ADB -s $2"
PKG=org.wolpmessenger.devicetrust.test

cd "$ROOT"
./gradlew -q :devicetrust:assembleDebugAndroidTest
$ADB install -r -t devicetrust/build/outputs/apk/androidTest/debug/devicetrust-debug-androidTest.apk >/dev/null
$ADB shell am instrument -w -e class org.wolpmessenger.devicetrust.KeyBenchmarkTest,org.wolpmessenger.devicetrust.VaultDeviceTest#measure $PKG/androidx.test.runner.AndroidJUnitRunner | tee /dev/stderr | grep -q '^OK '
mkdir -p bench
$ADB pull /sdcard/Android/data/$PKG/files/bench/. bench/ >/dev/null
$ADB uninstall $PKG >/dev/null
ls -1 bench/
