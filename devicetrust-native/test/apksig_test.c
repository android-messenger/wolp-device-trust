// Host test of apksig.c and of the string table (run.sh builds it with ASan/UBSan).
//   apksig_test strings                      — the generated table decrypts to strings.txt values
//   apksig_test signers <apk> <sdk>          — prints "<scheme> <sha256 hex>…" of the applying signers
//   apksig_test fuzz <apk>                   — truncations and bit flips must never crash
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "apksig.h"
#include "wolpdt_strings.h"

static uint8_t *slurp(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); exit(2); }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *b = malloc((size_t)n);
    if (!b || fread(b, 1, (size_t)n, f) != (size_t)n) { perror("read"); exit(2); }
    fclose(f);
    *len = (size_t)n;
    return b;
}

static int strings_test(void) {
    struct { const obf_t *s; const char *want; size_t len; } cases[] = {
        {OBF_ID_ROOT_SU, "ROOT_SU", 7},
        {OBF_SU_PATHS[OBF_SU_PATHS_N - 1], "/debug_ramdisk/su", 17},
        {OBF_APK_SIG_MAGIC, "APK Sig Block 42", 16},
        {OBF_JNI_SCAN_SIG, "([B[B)[B", 8},
        {OBF_DBUS_AUTH, "\0AUTH\r\n", 7},
    };
    for (size_t i = 0; i < sizeof cases / sizeof *cases; i++) {
        DEC(v, cases[i].s);
        if (OBF_LEN(cases[i].s) != cases[i].len || memcmp(v, cases[i].want, cases[i].len) != 0) {
            fprintf(stderr, "string %zu decrypts wrong\n", i);
            return 1;
        }
    }
    if (OBF_SU_PATHS_N != 12 || OBF_EMU_PATHS_N != 6) { fprintf(stderr, "array sizes\n"); return 1; }
    puts("strings OK");
    return 0;
}

static int signers(const char *path, int sdk) {
    size_t len;
    uint8_t *apk = slurp(path, &len);
    uint8_t out[APKSIG_MAX_SIGNERS][32];
    int count, scheme;
    int rc = apksig_signers(apk, len, sdk, out, &count, &scheme);
    free(apk);
    if (rc != APKSIG_OK) { printf("error %d\n", rc); return 0; }
    printf("%d", scheme);
    for (int i = 0; i < count; i++) {
        printf(" ");
        for (int j = 0; j < 32; j++) printf("%02x", out[i][j]);
    }
    printf("\n");
    return 0;
}

static int fuzz(const char *path) {
    size_t len;
    uint8_t *apk = slurp(path, &len);
    uint8_t out[APKSIG_MAX_SIGNERS][32];
    int count, scheme;
    // truncations: 400 cut points, each a fresh exact-size heap copy so ASan sees any over-read
    for (size_t i = 0; i <= 400; i++) {
        size_t cut = i < 200 ? len * i / 200 : len - (400 - i) * 97; // spread + dense near the end
        if (cut > len) continue;
        uint8_t *b = malloc(cut ? cut : 1);
        memcpy(b, apk, cut);
        apksig_signers(b, cut, 34, out, &count, &scheme);
        free(b);
    }
    // bit flips over the tail (signing block + central directory + end record), in place
    size_t from = len > 16384 ? len - 16384 : 0;
    srand(1);
    for (int i = 0; i < 50000; i++) {
        size_t pos[4];
        uint8_t bit[4];
        int k = 1 + i % 4;
        for (int j = 0; j < k; j++) { pos[j] = from + (size_t)rand() % (len - from); bit[j] = (uint8_t)(1u << (rand() % 8)); apk[pos[j]] ^= bit[j]; }
        apksig_signers(apk, len, 34, out, &count, &scheme);
        for (int j = k - 1; j >= 0; j--) apk[pos[j]] ^= bit[j];
    }
    free(apk);
    puts("fuzz OK");
    return 0;
}

int main(int argc, char **argv) {
    if (argc >= 2 && !strcmp(argv[1], "strings")) return strings_test();
    if (argc >= 4 && !strcmp(argv[1], "signers")) return signers(argv[2], atoi(argv[3]));
    if (argc >= 3 && !strcmp(argv[1], "fuzz")) return fuzz(argv[2]);
    fprintf(stderr, "usage: apksig_test strings | signers <apk> <sdk> | fuzz <apk>\n");
    return 2;
}
