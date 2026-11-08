# Sourced by tools/*.sh: locate the SDK, adb and a JDK for Gradle 8.14 (needs ≤ 21).
SDK="${ANDROID_HOME:-$HOME/Android/Sdk}"
ADB="$SDK/platform-tools/adb"
if [ -z "${JAVA_HOME:-}" ] || ! "$JAVA_HOME/bin/java" -version 2>&1 | grep -qE '"(17|21)'; then
  for j in /opt/jdk-21* /usr/lib/jvm/*21* /opt/jdk-17* /usr/lib/jvm/*17*; do [ -x "$j/bin/java" ] && export JAVA_HOME="$j" && break; done
fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

PKG=org.wolpmessenger.devicetrust.sample

# run_sample_test <test method> <device files subdir> <local dir>: builds and installs the sample app and
# its test APK, runs one DeviceExportTest method, pulls the produced files and leaves the app installed.
run_sample_test() {
  local method="$1" remote="$2" local_dir="$3"
  cd "$ROOT"
  ./gradlew -q :sample:assembleDebug :sample:assembleDebugAndroidTest
  $ADB install -r -t sample/build/outputs/apk/debug/sample-debug.apk >/dev/null
  $ADB install -r -t sample/build/outputs/apk/androidTest/debug/sample-debug-androidTest.apk >/dev/null
  $ADB shell am instrument -w -e class "$PKG.DeviceExportTest#$method" "$PKG.test/androidx.test.runner.AndroidJUnitRunner" \
    | tee /dev/stderr | grep -q '^OK '
  mkdir -p "$local_dir"
  $ADB pull "/sdcard/Android/data/$PKG/files/$remote/." "$local_dir/" >/dev/null
  $ADB uninstall "$PKG.test" >/dev/null
  echo "pulled into $local_dir/:"; find "$local_dir" -name '*.json' -mmin -10 | sort
}
