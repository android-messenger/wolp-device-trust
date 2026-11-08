#!/usr/bin/env bash
# Export attestation test vectors from the connected device into testvectors/<model>/ (S2 §13, S3 §6.5).
# Usage: tools/export-testvectors.sh [-s <serial>]
set -euo pipefail
source "$(dirname "$0")/adb-env.sh"
[ "${1:-}" = "-s" ] && ADB="$ADB -s $2"
PKG=org.wolpmessenger.testvectors

cd "$ROOT"
./gradlew -q :testvectors-export:assembleDebug :testvectors-export:assembleDebugAndroidTest
$ADB install -r -t testvectors-export/build/outputs/apk/debug/testvectors-export-debug.apk >/dev/null
$ADB install -r -t testvectors-export/build/outputs/apk/androidTest/debug/testvectors-export-debug-androidTest.apk >/dev/null
$ADB shell am instrument -w -e class $PKG.ExportTestVectors $PKG.test/androidx.test.runner.AndroidJUnitRunner | tee /dev/stderr | grep -q '^OK '
mkdir -p testvectors
$ADB pull /sdcard/Android/data/$PKG/files/testvectors/. testvectors/ >/dev/null
$ADB uninstall $PKG.test >/dev/null; $ADB uninstall $PKG >/dev/null
echo "exported:"; find testvectors -name '*.json' -newer "$0" -o -name '*.json' -mmin -5 | sort -u
