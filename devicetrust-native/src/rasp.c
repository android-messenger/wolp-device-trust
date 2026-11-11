// Native RASP checks (S2 §7.1). Result lines "ID|S|detail\n", S = F (found) | C (clean) |
// D (access denied / unreadable: a separate result, never "found"), followed by
// HMAC-SHA256(sessionKey, lines) (S2 §7.5). Checks that also exist in Kotlin (ROOT_SU, DEBUGGER,
// EMULATOR, APK_SIGNATURE) use the same inputs so that a mismatch means tampering — keep the
// lists in strings.txt in sync with rasp/Checks.kt.
//
// Every string literal lives encrypted in strings.txt → wolpdt_strings.h (S2 §7.5); DEC() puts
// the plain value on the stack for the duration of a scope.
#include <jni.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include "apksig.h"
#include "sha256.h"
#include "wolpdt_strings.h"

typedef struct { char *buf; size_t len, cap; } out_t;

static int out_put(out_t *o, const char *s, size_t n) {
    if (o->len + n + 1 > o->cap) {
        size_t cap = (o->cap ? o->cap * 2 : 1024);
        while (cap < o->len + n + 1) cap *= 2;
        char *b = realloc(o->buf, cap);
        if (!b) return -1;
        o->buf = b; o->cap = cap;
    }
    memcpy(o->buf + o->len, s, n);
    o->len += n;
    o->buf[o->len] = 0;
    return 0;
}

static void out_line(out_t *o, const obf_t *id_s, char state, const char *detail) {
    DEC(id, id_s);
    char line[320];
    int n = snprintf(line, sizeof line, "%s|%c|%.256s", id, state, detail ? detail : "");
    if (n < 0) return;
    if ((size_t)n >= sizeof line) n = sizeof line - 1;
    for (int i = (int)strlen(id) + 3; i < n; i++) if (line[i] == '\n' || line[i] == '|') line[i] = ' ';
    out_put(o, line, (size_t)n);
    out_put(o, "\n", 1);
}

/** detail = decrypted [prefix] + [rest]. */
static const char *join(char out[256], const obf_t *prefix, const char *rest) {
    DEC(p, prefix);
    snprintf(out, 256, "%s%s", p, rest);
    return out;
}

/** F if the path exists, D on EACCES/EPERM, C otherwise. */
static char stat_state(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) return 'F';
    return (errno == EACCES || errno == EPERM) ? 'D' : 'C';
}

/** Whole file via open/read (as Kotlin's Os.open/Os.read); NULL + errno on failure. */
static char *read_all(const char *path, size_t limit, size_t *out_len) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return NULL;
    size_t cap = 8192, len = 0;
    char *b = malloc(cap + 1);
    if (!b) { close(fd); errno = ENOMEM; return NULL; }
    for (;;) {
        if (len == cap) {
            if (cap >= limit) break;
            cap *= 2;
            char *nb = realloc(b, cap + 1);
            if (!nb) { free(b); close(fd); errno = ENOMEM; return NULL; }
            b = nb;
        }
        ssize_t r = read(fd, b + len, cap - len);
        if (r < 0) { if (errno == EINTR) continue; int e = errno; free(b); close(fd); errno = e; return NULL; }
        if (r == 0) break;
        len += (size_t)r;
    }
    close(fd);
    b[len] = 0;
    if (out_len) *out_len = len;
    return b;
}

static char *read_obf(const obf_t *path, size_t limit) {
    DEC(p, path);
    return read_all(p, limit, NULL);
}

static void prop(const obf_t *name, char value[PROP_VALUE_MAX]) {
    DEC(n, name);
    value[0] = 0;
    __system_property_get(n, value);
}

static int denied(void) { return errno == EACCES || errno == EPERM; }

/** stat over a list: first F wins, else first D, else C; [detail] gets the path. */
static char first_hit(const obf_t *const *paths, size_t n, char detail[256]) {
    char state = 'C';
    for (size_t i = 0; i < n && state != 'F'; i++) {
        DEC(p, paths[i]);
        char s = stat_state(p);
        if (s == 'F' || (s == 'D' && state == 'C')) { state = s; snprintf(detail, 256, "%s", p); }
    }
    return state;
}

// ------------------------------------------------------------------ dual checks (also in Kotlin)

/** Fixed paths, then "<dir>/su" for every PATH entry. First F wins, else first D, else C. */
static void check_su(out_t *o) {
    char detail[256] = "";
    char state = first_hit(OBF_SU_PATHS, OBF_SU_PATHS_N, detail);
    DEC(path_name, OBF_ENV_PATH);
    const char *env = getenv(path_name);
    if (env && state != 'F') {
        DEC(suffix, OBF_SUFFIX_SU);
        char *copy = strdup(env), *save = NULL;
        for (char *dir = copy ? strtok_r(copy, ":", &save) : NULL; dir && state != 'F'; dir = strtok_r(NULL, ":", &save)) {
            if (!*dir) continue;
            char path[256];
            snprintf(path, sizeof path, "%s%s", dir, suffix);
            char s = stat_state(path);
            if (s == 'F' || (s == 'D' && state == 'C')) { state = s; snprintf(detail, sizeof detail, "%s", path); }
        }
        free(copy);
    }
    out_line(o, OBF_ID_ROOT_SU, state, detail);
}

/** TracerPid in /proc/self/status (the JDWP part of DEBUGGER is Kotlin-only). */
static void check_tracer(out_t *o) {
    char detail[256];
    char *s = read_obf(OBF_PROC_STATUS, 1 << 16);
    if (!s) {
        char state = denied() ? 'D' : 'C'; // before anything else can touch errno
        out_line(o, OBF_ID_DEBUGGER, state, join(detail, OBF_STATUS_UNREADABLE, ""));
        return;
    }
    long pid = 0;
    DEC(tag, OBF_TRACER_PID);
    char *t = strstr(s, tag);
    if (t) pid = strtol(t + strlen(tag), NULL, 10);
    free(s);
    char num[24];
    snprintf(num, sizeof num, "%ld", pid);
    out_line(o, OBF_ID_DEBUGGER, pid != 0 ? 'F' : 'C', pid != 0 ? join(detail, OBF_TRACER_EQ, num) : "");
}

/** ro.hardware (= Build.HARDWARE), ro.build.fingerprint (= Build.FINGERPRINT), then paths. */
static void check_emulator(out_t *o) {
    char hw[PROP_VALUE_MAX], fp[PROP_VALUE_MAX], detail[256];
    prop(OBF_PROP_HARDWARE, hw);
    prop(OBF_PROP_FINGERPRINT, fp);
    for (size_t i = 0; i < OBF_EMU_HARDWARE_N; i++) {
        DEC(h, OBF_EMU_HARDWARE[i]);
        if (!strcmp(hw, h)) { out_line(o, OBF_ID_EMULATOR, 'F', join(detail, OBF_HARDWARE_EQ, hw)); return; }
    }
    DEC(generic, OBF_FP_GENERIC);
    DEC(emulator, OBF_FP_EMULATOR);
    DEC(gphone, OBF_FP_SDK_GPHONE);
    if (!strncmp(fp, generic, strlen(generic)) || strstr(fp, emulator) || strstr(fp, gphone)) {
        out_line(o, OBF_ID_EMULATOR, 'F', join(detail, OBF_FINGERPRINT_EQ, fp));
        return;
    }
    detail[0] = 0;
    char state = first_hit(OBF_EMU_PATHS, OBF_EMU_PATHS_N, detail);
    out_line(o, OBF_ID_EMULATOR, state, detail);
}

/** "/<pkg>-" of the process (cmdline up to NUL or ':'), or "" if unknown. */
static void package_needle(char out[256]) {
    out[0] = 0;
    char *cmd = read_obf(OBF_PROC_CMDLINE, 4096);
    if (!cmd) return;
    size_t n = strcspn(cmd, ":");
    if (n > 0 && n < 250) snprintf(out, 256, "/%.*s-", (int)n, cmd);
    free(cmd);
}

/**
 * The installed base.apk of this package, found in /proc/self/maps (not from PackageManager — a
 * hook there is exactly what this twin of the Kotlin check is for). Returns 0 and fills [path].
 */
static int find_base_apk(char path[512]) {
    char needle[256];
    package_needle(needle);
    if (!needle[0]) return -1;
    char *m = read_obf(OBF_PROC_MAPS, 32 << 20);
    if (!m) return -1;
    DEC(base, OBF_BASE_APK);
    size_t bl = strlen(base);
    int rc = -1;
    for (char *line = m, *next; line && *line; line = next) {
        next = strchr(line, '\n');
        if (next) *next++ = 0;
        char *p = strchr(line, '/');
        if (!p) continue;
        size_t l = strlen(p);
        if (l > bl && l < 512 && !strcmp(p + l - bl, base) && strstr(p, needle)) {
            memcpy(path, p, l + 1);
            rc = 0;
            break;
        }
    }
    free(m);
    return rc;
}

static void hex(const uint8_t d[32], char out[65]) {
    static const char digits[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) { out[2 * i] = digits[d[i] >> 4]; out[2 * i + 1] = digits[d[i] & 15]; }
    out[64] = 0;
}

/**
 * APK_SIGNATURE twin of the Kotlin check: every current signer (APK Signing Block of the installed
 * file, apksig.c) must be one of [expected] (n × 32 raw bytes). Nothing expected → no line (as in Kotlin).
 */
static void check_apk_signature(out_t *o, const uint8_t *expected, size_t n_expected) {
    if (n_expected == 0) return;
    char detail[256], path[512];
    if (find_base_apk(path)) { out_line(o, OBF_ID_APK_SIGNATURE, 'D', join(detail, OBF_APK_NOT_FOUND, "")); return; }
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) || st.st_size <= 0) {
        if (fd >= 0) close(fd);
        out_line(o, OBF_ID_APK_SIGNATURE, 'D', join(detail, OBF_APK_UNREADABLE, ""));
        return;
    }
    void *map = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (map == MAP_FAILED) { out_line(o, OBF_ID_APK_SIGNATURE, 'D', join(detail, OBF_APK_UNREADABLE, "")); return; }
    char sdk_s[PROP_VALUE_MAX];
    prop(OBF_PROP_SDK, sdk_s);
    uint8_t signers[APKSIG_MAX_SIGNERS][32];
    int count = 0;
    int rc = apksig_signers(map, (size_t)st.st_size, atoi(sdk_s), signers, &count, NULL);
    munmap(map, (size_t)st.st_size);
    if (rc == APKSIG_NO_BLOCK) { out_line(o, OBF_ID_APK_SIGNATURE, 'D', join(detail, OBF_NO_SIGNING_BLOCK, "")); return; }
    if (rc != APKSIG_OK) { out_line(o, OBF_ID_APK_SIGNATURE, 'D', join(detail, OBF_APK_MALFORMED, "")); return; }
    if (count == 0) { out_line(o, OBF_ID_APK_SIGNATURE, 'F', join(detail, OBF_NO_SIGNERS, "")); return; }
    for (int i = 0; i < count; i++) {
        int ok = 0;
        for (size_t j = 0; j < n_expected && !ok; j++) ok = !memcmp(signers[i], expected + 32 * j, 32);
        if (!ok) {
            char h[65];
            hex(signers[i], h);
            out_line(o, OBF_ID_APK_SIGNATURE, 'F', join(detail, OBF_UNEXPECTED_EQ, h));
            return;
        }
    }
    out_line(o, OBF_ID_APK_SIGNATURE, 'C', "");
}

// ------------------------------------------------------------------ native-only checks

/**
 * [token] as a whole space-delimited field of some line of [text] (mountinfo: the mount source of
 * KernelSU / APatch overlays is exactly that word). A plain strstr would also hit any path that
 * merely contains the letters.
 */
static int has_field(const char *text, const char *token) {
    size_t n = strlen(token);
    for (const char *p = text; (p = strstr(p, token)); p += n) {
        int start_ok = p == text || p[-1] == ' ' || p[-1] == '\n';
        int end_ok = p[n] == 0 || p[n] == ' ' || p[n] == '\n';
        if (start_ok && end_ok) return 1;
    }
    return 0;
}

static void check_magisk(out_t *o) {
    char detail[256];
    for (size_t i = 0; i < OBF_MAGISK_PATHS_N; i++) {
        DEC(p, OBF_MAGISK_PATHS[i]);
        if (stat_state(p) == 'F') { out_line(o, OBF_ID_ROOT_MAGISK, 'F', p); return; }
    }
    char *m = read_obf(OBF_PROC_MOUNTINFO, 4 << 20);
    if (!m) {
        char state = denied() ? 'D' : 'C';
        out_line(o, OBF_ID_ROOT_MAGISK, state, join(detail, OBF_MOUNTINFO_UNREADABLE, ""));
        return;
    }
    for (size_t i = 0; i < OBF_MAGISK_MOUNT_TOKENS_N; i++) {
        DEC(t, OBF_MAGISK_MOUNT_TOKENS[i]);
        if (strstr(m, t)) {
            free(m);
            out_line(o, OBF_ID_ROOT_MAGISK, 'F', join(detail, OBF_MOUNTINFO_PREFIX, t));
            return;
        }
    }
    for (size_t i = 0; i < OBF_MAGISK_MOUNT_FIELDS_N; i++) {
        DEC(t, OBF_MAGISK_MOUNT_FIELDS[i]);
        if (has_field(m, t)) {
            free(m);
            out_line(o, OBF_ID_ROOT_MAGISK, 'F', join(detail, OBF_MOUNTINFO_PREFIX, t));
            return;
        }
    }
    free(m);
    out_line(o, OBF_ID_ROOT_MAGISK, 'C', "");
}

static void check_props(out_t *o) {
    char v[PROP_VALUE_MAX], detail[256];
    prop(OBF_PROP_DEBUGGABLE, v);
    if (!strcmp(v, "1")) { out_line(o, OBF_ID_ROOT_PROPS, 'F', join(detail, OBF_DETAIL_DEBUGGABLE, "")); return; }
    prop(OBF_PROP_SECURE, v);
    if (!strcmp(v, "0")) { out_line(o, OBF_ID_ROOT_PROPS, 'F', join(detail, OBF_DETAIL_SECURE, "")); return; }
    out_line(o, OBF_ID_ROOT_PROPS, 'C', "");
}

/** `test-keys` alone is weak (stock firmware of some vendors carries it): its own id, REPORT by default. */
static void check_test_keys(out_t *o) {
    char v[PROP_VALUE_MAX], detail[256];
    prop(OBF_PROP_BUILD_TAGS, v);
    DEC(tk, OBF_TEST_KEYS);
    int found = strstr(v, tk) != NULL;
    out_line(o, OBF_ID_ROOT_TEST_KEYS, found ? 'F' : 'C', found ? join(detail, OBF_DETAIL_TEST_KEYS, "") : "");
}

static void check_frida_maps(out_t *o) {
    char detail[256];
    char *m = read_obf(OBF_PROC_MAPS, 32 << 20);
    int maps_readable = m != NULL;
    if (m) {
        for (size_t i = 0; i < OBF_FRIDA_MAP_TOKENS_N; i++) {
            DEC(t, OBF_FRIDA_MAP_TOKENS[i]);
            if (strstr(m, t)) {
                free(m);
                out_line(o, OBF_ID_HOOK_FRIDA_MAPS, 'F', join(detail, OBF_MAPS_PREFIX, t));
                return;
            }
        }
        free(m);
    }
    DEC(task, OBF_PROC_TASK);
    DIR *d = opendir(task);
    if (d) {
        DEC(prefix, OBF_PROC_TASK_PREFIX);
        DEC(suffix, OBF_SUFFIX_COMM);
        struct dirent *e;
        while ((e = readdir(d))) {
            if (e->d_name[0] == '.') continue;
            char path[96];
            snprintf(path, sizeof path, "%s%.16s%s", prefix, e->d_name, suffix);
            char *comm = read_all(path, 64, NULL);
            if (!comm) continue;
            for (size_t i = 0; i < OBF_FRIDA_THREAD_TOKENS_N; i++) {
                DEC(t, OBF_FRIDA_THREAD_TOKENS[i]);
                if (strstr(comm, t)) {
                    free(comm);
                    closedir(d);
                    out_line(o, OBF_ID_HOOK_FRIDA_MAPS, 'F', join(detail, OBF_THREAD_PREFIX, t));
                    return;
                }
            }
            free(comm);
        }
        closedir(d);
    }
    out_line(o, OBF_ID_HOOK_FRIDA_MAPS, maps_readable ? 'C' : 'D', maps_readable ? "" : join(detail, OBF_MAPS_UNREADABLE, ""));
}

/** 1 = frida (D-Bus AUTH answered with REJECTED), 0 = no, -1 = socket not allowed. */
static int probe_frida_port(int port) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return denied() ? -1 : 0;
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port)};
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int found = 0;
    if (connect(fd, (struct sockaddr *)&a, sizeof a) == 0 || errno == EINPROGRESS) {
        struct pollfd p = {.fd = fd, .events = POLLOUT};
        int err = 0;
        socklen_t el = sizeof err;
        if (poll(&p, 1, 150) == 1 && getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) == 0 && err == 0) {
            DEC(auth, OBF_DBUS_AUTH);
            size_t al = OBF_LEN(OBF_DBUS_AUTH);
            if (send(fd, auth, al, MSG_NOSIGNAL) == (ssize_t)al) {
                p.events = POLLIN;
                char reply[64] = {0};
                DEC(rejected, OBF_DBUS_REJECTED);
                if (poll(&p, 1, 300) == 1 && recv(fd, reply, sizeof reply - 1, 0) > 0 && !strncmp(reply, rejected, strlen(rejected))) found = 1;
            }
        }
    }
    close(fd);
    return found;
}

static void check_frida_port(out_t *o) {
    static const int ports[] = {27042, 27043};
    char detail[256];
    int was_denied = 0;
    for (size_t i = 0; i < 2; i++) {
        int r = probe_frida_port(ports[i]);
        if (r == 1) {
            char num[8];
            snprintf(num, sizeof num, "%d", ports[i]);
            out_line(o, OBF_ID_HOOK_FRIDA_PORT, 'F', join(detail, OBF_PORT_EQ, num));
            return;
        }
        if (r < 0) was_denied = 1;
    }
    out_line(o, OBF_ID_HOOK_FRIDA_PORT, was_denied ? 'D' : 'C', was_denied ? join(detail, OBF_SOCKET_DENIED, "") : "");
}

// ------------------------------------------------------------------ JNI

/** scan(sessionKey, expectedSigningDigests: n × 32 bytes) → lines + HMAC (S2 §7.5). */
static jbyteArray scan(JNIEnv *env, jclass cls, jbyteArray key, jbyteArray expected) {
    (void)cls;
    if (!key) return NULL;
    out_t o = {0};
    check_su(&o);
    check_tracer(&o);
    check_emulator(&o);
    if (expected) {
        jsize n = (*env)->GetArrayLength(env, expected);
        jbyte *e = n > 0 ? (*env)->GetByteArrayElements(env, expected, NULL) : NULL;
        if (e) {
            check_apk_signature(&o, (const uint8_t *)e, (size_t)n / 32);
            (*env)->ReleaseByteArrayElements(env, expected, e, JNI_ABORT);
        }
    }
    check_magisk(&o);
    check_props(&o);
    check_test_keys(&o);
    check_frida_maps(&o);
    check_frida_port(&o);
    if (!o.buf) return NULL;

    jsize klen = (*env)->GetArrayLength(env, key);
    jbyte *k = (*env)->GetByteArrayElements(env, key, NULL);
    if (!k) { free(o.buf); return NULL; }
    uint8_t mac[32];
    hmac_sha256((const uint8_t *)k, (size_t)klen, (const uint8_t *)o.buf, o.len, mac);
    (*env)->ReleaseByteArrayElements(env, key, k, JNI_ABORT);

    jbyteArray res = (*env)->NewByteArray(env, (jsize)(o.len + 32));
    if (res) {
        (*env)->SetByteArrayRegion(env, res, 0, (jsize)o.len, (const jbyte *)o.buf);
        (*env)->SetByteArrayRegion(env, res, (jsize)o.len, 32, (const jbyte *)mac);
    }
    free(o.buf);
    return res;
}

__attribute__((visibility("default"))) JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    JNIEnv *env;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    DEC(cls, OBF_JNI_CLASS);
    DEC(name, OBF_JNI_SCAN);
    DEC(sig, OBF_JNI_SCAN_SIG);
    jclass c = (*env)->FindClass(env, cls);
    if (!c) return JNI_ERR;
    const JNINativeMethod methods[] = {{name, sig, (void *)scan}};
    if ((*env)->RegisterNatives(env, c, methods, 1) != JNI_OK) return JNI_ERR;
    return JNI_VERSION_1_6;
}
