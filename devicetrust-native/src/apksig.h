// APK Signing Block reader for the native APK_SIGNATURE check (S2 §7.1, §7.5). Pure parsing over
// a memory buffer — no platform calls — so it is unit-tested on the build host (test/apksig_test.c).
#pragma once
#include <stddef.h>
#include <stdint.h>

#define APKSIG_MAX_SIGNERS 8

enum {
    APKSIG_OK = 0,
    APKSIG_NO_BLOCK = -1,  // no ZIP end record, or no APK Signing Block (v1-only APK)
    APKSIG_MALFORMED = -2, // a block is there but does not parse
};

/**
 * SHA-256 of the first certificate of every signer that applies on [sdk], from the newest scheme
 * present that has one: v3.1, then v3 (signers filtered by their minSdk/maxSdk), then v2. This is
 * what PackageManager reports as `SigningInfo.apkContentsSigners` (with v3 rotation: the current
 * signer). Returns APKSIG_OK with *count = 0 when blocks exist but no signer applies.
 * [scheme] (optional) receives 31, 3 or 2.
 */
int apksig_signers(const uint8_t *apk, size_t len, int sdk, uint8_t out[APKSIG_MAX_SIGNERS][32], int *count, int *scheme);
