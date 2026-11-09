// APK Signing Block (https://source.android.com/docs/security/features/apksigning/v2,
// .../v3): ZIP end record → central directory offset → the block right before it
// ("APK Sig Block 42") → id/value pairs → signers → first certificate of each signer.
// Every length is checked against the enclosing slice; nothing is trusted.
#include "apksig.h"
#include <string.h>
#include "sha256.h"
#include "wolpdt_strings.h"

#define ID_V2 0x7109871au
#define ID_V3 0xf05368c0u
#define ID_V31 0x1b93ad61u

typedef struct { const uint8_t *p; size_t n; } slice_t;

static uint32_t le32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static uint64_t le64(const uint8_t *p) { return (uint64_t)le32(p) | (uint64_t)le32(p + 4) << 32; }

static int take_u32(slice_t *s, uint32_t *v) {
    if (s->n < 4) return -1;
    *v = le32(s->p);
    s->p += 4; s->n -= 4;
    return 0;
}

/** A uint32-length-prefixed sub-slice. */
static int take_lp(slice_t *s, slice_t *out) {
    uint32_t l;
    if (take_u32(s, &l) || l > s->n) return -1;
    out->p = s->p; out->n = l;
    s->p += l; s->n -= l;
    return 0;
}

/** Signers of one v2/v3/v3.1 value; returns -1 if malformed. */
static int parse_signers(slice_t value, int v3, int sdk, uint8_t out[APKSIG_MAX_SIGNERS][32], int *count) {
    slice_t seq, signer, signed_data, certs, cert;
    if (take_lp(&value, &seq)) return -1;
    while (seq.n) {
        if (take_lp(&seq, &signer) || take_lp(&signer, &signed_data)) return -1;
        if (v3) {
            uint32_t min_sdk, max_sdk;
            if (take_u32(&signer, &min_sdk) || take_u32(&signer, &max_sdk)) return -1;
            if ((int64_t)sdk < (int64_t)min_sdk || (int64_t)sdk > (int64_t)max_sdk) continue;
        }
        slice_t digests;
        if (take_lp(&signed_data, &digests) || take_lp(&signed_data, &certs) || take_lp(&certs, &cert) || cert.n == 0) return -1;
        if (*count >= APKSIG_MAX_SIGNERS) return -1;
        sha256_ctx c;
        sha256_init(&c);
        sha256_update(&c, cert.p, cert.n);
        sha256_final(&c, out[(*count)++]);
    }
    return 0;
}

int apksig_signers(const uint8_t *apk, size_t len, int sdk, uint8_t out[APKSIG_MAX_SIGNERS][32], int *count, int *scheme) {
    *count = 0;
    if (scheme) *scheme = 0;
    // ZIP end of central directory: 22 bytes + comment (≤ 65535), searched backwards
    if (len < 22) return APKSIG_NO_BLOCK;
    size_t eocd = (size_t)-1;
    size_t lowest = len - 22 > 65535 ? len - 22 - 65535 : 0;
    for (size_t i = len - 22 + 1; i-- > lowest;) {
        if (le32(apk + i) == 0x06054b50u && i + 22 + (size_t)(apk[i + 20] | apk[i + 21] << 8) == len) { eocd = i; break; }
    }
    if (eocd == (size_t)-1) return APKSIG_NO_BLOCK;
    uint64_t cd = le32(apk + eocd + 16);
    if (cd > eocd || cd < 32) return APKSIG_NO_BLOCK;

    DEC(magic, OBF_APK_SIG_MAGIC);
    if (memcmp(apk + cd - 16, magic, 16) != 0) return APKSIG_NO_BLOCK;
    uint64_t size = le64(apk + cd - 24); // excludes the leading size field itself
    if (size < 24 || size > cd - 8) return APKSIG_MALFORMED;
    size_t start = (size_t)(cd - size - 8);
    if (le64(apk + start) != size) return APKSIG_MALFORMED;

    slice_t found[3] = {{0}}; // v3.1, v3, v2
    int have[3] = {0};
    const uint8_t *p = apk + start + 8, *end = apk + cd - 24;
    while (p < end) {
        if ((size_t)(end - p) < 8) return APKSIG_MALFORMED;
        uint64_t plen = le64(p);
        p += 8;
        if (plen < 4 || plen > (uint64_t)(end - p)) return APKSIG_MALFORMED;
        uint32_t id = le32(p);
        slice_t v = {p + 4, (size_t)plen - 4};
        int slot = id == ID_V31 ? 0 : id == ID_V3 ? 1 : id == ID_V2 ? 2 : -1;
        if (slot >= 0 && !have[slot]) { found[slot] = v; have[slot] = 1; }
        p += plen;
    }
    if (!have[0] && !have[1] && !have[2]) return APKSIG_NO_BLOCK;

    static const int schemes[3] = {31, 3, 2};
    for (int i = 0; i < 3; i++) {
        if (!have[i]) continue;
        *count = 0;
        if (parse_signers(found[i], i < 2, sdk, out, count)) { *count = 0; return APKSIG_MALFORMED; }
        if (*count > 0) {
            if (scheme) *scheme = schemes[i];
            return APKSIG_OK;
        }
    }
    return APKSIG_OK;
}
