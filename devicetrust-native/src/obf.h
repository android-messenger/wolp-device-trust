// Encrypted string literals (S2 §7.5). The table comes from strings.txt via the generated
// wolpdt_strings.h, which defines OBF_MAX (longest value + 1) before including this file.
//
// This is obfuscation, not secrecy: the keys are in the binary. It keeps the check list out of
// `strings libwolpdt.so` and out of simple byte-pattern patches. Values live in clear text only on
// the stack, only while used (DEC wipes them at the end of the scope).
#pragma once
#include <stddef.h>
#include <stdint.h>

#ifndef OBF_MAX
#error "include wolpdt_strings.h, not obf.h"
#endif

typedef struct {
    const uint8_t *data;
    uint16_t len;
    uint32_t key;
} obf_t;

/**
 * Decrypts [s] into [out] (OBF_MAX bytes, NUL-terminated); returns [out]. Not inlined and reading
 * the cipher text through a volatile pointer, so the compiler cannot fold it back to a literal.
 */
__attribute__((noinline, unused)) static char *obf_dec(const obf_t *s, char out[OBF_MAX]) {
    const volatile uint8_t *d = s->data;
    uint32_t x = s->key;
    size_t n = s->len < OBF_MAX ? s->len : OBF_MAX - 1;
    for (size_t i = 0; i < n; i++) {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        out[i] = (char)(d[i] ^ (uint8_t)(x >> 11));
    }
    out[n] = 0;
    return out;
}

__attribute__((unused)) static void obf_wipe(char (*p)[OBF_MAX]) {
    volatile char *v = *p;
    for (size_t i = 0; i < OBF_MAX; i++) v[i] = 0;
}

/** `DEC(name, OBF_X)` — a stack buffer holding the plain value, wiped when the scope ends. */
#define DEC(var, s) char var[OBF_MAX] __attribute__((cleanup(obf_wipe))); obf_dec((s), var)

/** Length of an encrypted value (e.g. for values with an embedded NUL such as OBF_DBUS_AUTH). */
#define OBF_LEN(s) ((size_t)(s)->len)
