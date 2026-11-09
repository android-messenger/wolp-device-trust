#!/usr/bin/env bash
# Host tests of the native part (S2 §7.5): string table round trip, APK Signing Block reader on
# APKs signed by apksigner itself (v2 only, v3 only, v3.1 key rotation, v1 only), fuzzing.
# Built with ASan/UBSan. Needs: cc, keytool (JDK), Android build-tools (apksigner).
#   devicetrust-native/test/run.sh <any.apk>      (e.g. sample/build/outputs/apk/debug/sample-debug.apk)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
in=${1:?usage: run.sh <apk to re-sign>}
gen="$root/devicetrust/build/generated/wolpdt"
[[ -f $gen/wolpdt_strings.h ]] || (cd "$root" && ./gradlew -q :devicetrust:generateNativeStrings)

sdk=${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}}
apksigner=$(ls -d "$sdk"/build-tools/*/apksigner | sort -V | tail -1)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# ASan cannot run when /etc/ld.so.preload injects a library (endpoint-protection agents): UBSan only then
sanitize=address,undefined
echo 'int main(void){return 0;}' > "$work/probe.c"
if ! { cc -fsanitize=address "$work/probe.c" -o "$work/probe" && "$work/probe"; } >/dev/null 2>&1; then
  echo "note: ASan unavailable here, testing with UBSan only"
  sanitize=undefined
fi
cc -std=c11 -O1 -g -Wall -Wextra -Werror -fsanitize=$sanitize -fno-sanitize-recover=all \
  -I "$root/devicetrust-native/src" -I "$gen" \
  "$here/apksig_test.c" "$root/devicetrust-native/src/apksig.c" "$root/devicetrust-native/src/sha256.c" -o "$work/t"
t="$work/t"

"$t" strings

key() { # name → keystore + its certificate SHA-256 (lowercase hex)
  keytool -genkeypair -keystore "$work/$1.p12" -storetype PKCS12 -storepass pass123 -keypass pass123 -alias "$1" \
    -keyalg EC -groupname secp256r1 -sigalg SHA256withECDSA -dname "CN=$1" -validity 3650 >/dev/null 2>&1
  keytool -list -v -keystore "$work/$1.p12" -storepass pass123 -alias "$1" | sed -n 's/.*SHA256: *//p' | tr -d ':' | tr 'A-F' 'a-f'
}
a=$(key a)
b=$(key b)
ks() { echo --ks "$work/$1.p12" --ks-pass pass:pass123 --ks-key-alias "$1"; }

# shellcheck disable=SC2046
"$apksigner" sign $(ks a) --min-sdk-version 33 --v1-signing-enabled false --v2-signing-enabled true --v3-signing-enabled false --out "$work/v2.apk" "$in"
# shellcheck disable=SC2046
"$apksigner" sign $(ks a) --min-sdk-version 33 --v1-signing-enabled false --v2-signing-enabled false --v3-signing-enabled true --out "$work/v3.apk" "$in"
# shellcheck disable=SC2046
"$apksigner" sign $(ks a) --min-sdk-version 24 --v1-signing-enabled true --v2-signing-enabled false --v3-signing-enabled false --out "$work/v1.apk" "$in"
# key rotation a → b from SDK 33: v3.1 block with b, v3 block with a for older platforms
# shellcheck disable=SC2046
"$apksigner" rotate --out "$work/lineage" --old-signer $(ks a) --new-signer $(ks b)
# shellcheck disable=SC2046
"$apksigner" sign $(ks a) --next-signer $(ks b) --lineage "$work/lineage" --rotation-min-sdk-version 33 --min-sdk-version 28 \
  --v1-signing-enabled false --v2-signing-enabled true --v3-signing-enabled true --out "$work/rot.apk" "$in"

fail=0
expect() { # apk sdk wanted
  local got
  got=$("$t" signers "$work/$1" "$2")
  if [[ $got == "$3" ]]; then echo "ok   $1 sdk=$2 → $got"; else echo "FAIL $1 sdk=$2: got '$got', want '$3'"; fail=1; fi
}
expect v2.apk 34 "2 $a"
expect v3.apk 34 "3 $a"
expect v1.apk 34 "error -1"
expect rot.apk 36 "31 $b"
expect rot.apk 33 "31 $b"
expect rot.apk 32 "3 $a"
"$t" fuzz "$work/rot.apk"
"$t" fuzz "$work/v2.apk"
exit $fail
