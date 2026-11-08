# Sourced by tools/*.sh: locate the SDK, adb and a JDK for Gradle 8.14 (needs ≤ 21).
SDK="${ANDROID_HOME:-$HOME/Android/Sdk}"
ADB="$SDK/platform-tools/adb"
if [ -z "${JAVA_HOME:-}" ] || ! "$JAVA_HOME/bin/java" -version 2>&1 | grep -qE '"(17|21)'; then
  for j in /opt/jdk-21* /usr/lib/jvm/*21* /opt/jdk-17* /usr/lib/jvm/*17*; do [ -x "$j/bin/java" ] && export JAVA_HOME="$j" && break; done
fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
