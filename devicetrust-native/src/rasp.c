// Native RASP checks (S2 §7.1). Result lines "ID|S|detail\n", S = F (found) | C (clean) |
// D (access denied: a separate result, never "found"), followed by HMAC-SHA256(sessionKey, lines)
// (S2 §7.5). Checks that also exist in Kotlin (ROOT_SU, DEBUGGER, EMULATOR) use exactly the same
// inputs and syscalls (stat, open/read, system properties) so that a mismatch means tampering —
// keep the lists in sync with rasp/Checks.kt.
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
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include "sha256.h"

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

static void out_line(out_t *o, const char *id, char state, const char *detail) {
    char line[320];
    int n = snprintf(line, sizeof line, "%s|%c|%.256s", id, state, detail ? detail : "");
    if (n < 0) return;
    if ((size_t)n >= sizeof line) n = sizeof line - 1;
    for (int i = (int)strlen(id) + 3; i < n; i++) if (line[i] == '\n' || line[i] == '|') line[i] = ' ';
    out_put(o, line, (size_t)n);
    out_put(o, "\n", 1);
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

static void prop(const char *name, char value[PROP_VALUE_MAX]) {
    value[0] = 0;
    __system_property_get(name, value);
}

// ------------------------------------------------------------------ dual checks (also in Kotlin)

static const char *const SU_PATHS[] = {
    "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su", "/data/local/su", "/data/local/bin/su",
    "/data/local/xbin/su", "/system/sd/xbin/su", "/vendor/bin/su", "/product/bin/su", "/odm/bin/su", "/debug_ramdisk/su",
};

/** Fixed paths, then "<dir>/su" for every PATH entry. First F wins, else first D, else C. */
static void check_su(out_t *o) {
    char state = 'C';
    char detail[256] = "";
    for (size_t i = 0; i < sizeof SU_PATHS / sizeof *SU_PATHS && state != 'F'; i++) {
        char s = stat_state(SU_PATHS[i]);
        if (s == 'F' || (s == 'D' && state == 'C')) { state = s; snprintf(detail, sizeof detail, "%s", SU_PATHS[i]); }
    }
    const char *env = getenv("PATH");
    if (env && state != 'F') {
        char *copy = strdup(env), *save = NULL;
        for (char *dir = copy ? strtok_r(copy, ":", &save) : NULL; dir && state != 'F'; dir = strtok_r(NULL, ":", &save)) {
            if (!*dir) continue;
            char path[256];
            snprintf(path, sizeof path, "%s/su", dir);
            char s = stat_state(path);
            if (s == 'F' || (s == 'D' && state == 'C')) { state = s; snprintf(detail, sizeof detail, "%s", path); }
        }
        free(copy);
    }
    out_line(o, "ROOT_SU", state, detail);
}

/** TracerPid in /proc/self/status (the JDWP part of DEBUGGER is Kotlin-only). */
static void check_tracer(out_t *o) {
    char *s = read_all("/proc/self/status", 1 << 16, NULL);
    if (!s) { out_line(o, "DEBUGGER", (errno == EACCES || errno == EPERM) ? 'D' : 'C', "status unreadable"); return; }
    long pid = 0;
    char *t = strstr(s, "TracerPid:");
    if (t) pid = strtol(t + 10, NULL, 10);
    free(s);
    char detail[32];
    snprintf(detail, sizeof detail, "tracer=%ld", pid);
    out_line(o, "DEBUGGER", pid != 0 ? 'F' : 'C', pid != 0 ? detail : "");
}

static const char *const EMU_PATHS[] = {
    "/dev/qemu_pipe", "/dev/goldfish_pipe", "/dev/socket/qemud", "/sys/qemu_trace", "/system/bin/qemu-props",
    "/system/lib/libc_malloc_debug_qemu.so",
};

/** ro.hardware (= Build.HARDWARE), ro.build.fingerprint (= Build.FINGERPRINT), then paths. */
static void check_emulator(out_t *o) {
    char hw[PROP_VALUE_MAX], fp[PROP_VALUE_MAX], detail[256];
    prop("ro.hardware", hw);
    prop("ro.build.fingerprint", fp);
    if (!strcmp(hw, "goldfish") || !strcmp(hw, "ranchu") || !strcmp(hw, "vbox86")) {
        snprintf(detail, sizeof detail, "hardware=%s", hw);
        out_line(o, "EMULATOR", 'F', detail);
        return;
    }
    if (!strncmp(fp, "generic", 7) || strstr(fp, "emulator") || strstr(fp, "sdk_gphone")) {
        snprintf(detail, sizeof detail, "fingerprint=%s", fp);
        out_line(o, "EMULATOR", 'F', detail);
        return;
    }
    char state = 'C';
    detail[0] = 0;
    for (size_t i = 0; i < sizeof EMU_PATHS / sizeof *EMU_PATHS && state != 'F'; i++) {
        char s = stat_state(EMU_PATHS[i]);
        if (s == 'F' || (s == 'D' && state == 'C')) { state = s; snprintf(detail, sizeof detail, "%s", EMU_PATHS[i]); }
    }
    out_line(o, "EMULATOR", state, detail);
}

// ------------------------------------------------------------------ native-only checks

static const char *const MAGISK_PATHS[] = {
    "/sbin/.magisk", "/debug_ramdisk/.magisk", "/data/adb/magisk", "/data/adb/ksu", "/data/adb/ap", "/data/adb/modules",
};
static const char *const MAGISK_MOUNT_TOKENS[] = {"magisk", "/data/adb/modules", "KSU", "APatch"};

static void check_magisk(out_t *o) {
    char detail[256];
    for (size_t i = 0; i < sizeof MAGISK_PATHS / sizeof *MAGISK_PATHS; i++) {
        if (stat_state(MAGISK_PATHS[i]) == 'F') { out_line(o, "ROOT_MAGISK", 'F', MAGISK_PATHS[i]); return; }
    }
    char *m = read_all("/proc/self/mountinfo", 4 << 20, NULL);
    if (!m) { out_line(o, "ROOT_MAGISK", (errno == EACCES || errno == EPERM) ? 'D' : 'C', "mountinfo unreadable"); return; }
    for (size_t i = 0; i < sizeof MAGISK_MOUNT_TOKENS / sizeof *MAGISK_MOUNT_TOKENS; i++) {
        if (strstr(m, MAGISK_MOUNT_TOKENS[i])) {
            snprintf(detail, sizeof detail, "mountinfo:%s", MAGISK_MOUNT_TOKENS[i]);
            free(m);
            out_line(o, "ROOT_MAGISK", 'F', detail);
            return;
        }
    }
    free(m);
    out_line(o, "ROOT_MAGISK", 'C', "");
}

static void check_props(out_t *o) {
    char v[PROP_VALUE_MAX];
    prop("ro.debuggable", v);
    if (!strcmp(v, "1")) { out_line(o, "ROOT_PROPS", 'F', "ro.debuggable=1"); return; }
    prop("ro.secure", v);
    if (!strcmp(v, "0")) { out_line(o, "ROOT_PROPS", 'F', "ro.secure=0"); return; }
    prop("ro.build.tags", v);
    if (strstr(v, "test-keys")) { out_line(o, "ROOT_PROPS", 'F', "ro.build.tags=test-keys"); return; }
    out_line(o, "ROOT_PROPS", 'C', "");
}

static const char *const FRIDA_MAP_TOKENS[] = {"frida", "gum-js", "gadget"};
static const char *const FRIDA_THREAD_TOKENS[] = {"gum-js-loop", "pool-frida", "frida"};

static void check_frida_maps(out_t *o) {
    char detail[256];
    char *m = read_all("/proc/self/maps", 32 << 20, NULL);
    int maps_readable = m != NULL;
    if (m) {
        for (size_t i = 0; i < sizeof FRIDA_MAP_TOKENS / sizeof *FRIDA_MAP_TOKENS; i++) {
            if (strstr(m, FRIDA_MAP_TOKENS[i])) {
                snprintf(detail, sizeof detail, "maps:%s", FRIDA_MAP_TOKENS[i]);
                free(m);
                out_line(o, "HOOK_FRIDA_MAPS", 'F', detail);
                return;
            }
        }
        free(m);
    }
    DIR *d = opendir("/proc/self/task");
    if (d) {
        struct dirent *e;
        while ((e = readdir(d))) {
            if (e->d_name[0] == '.') continue;
            char path[64];
            snprintf(path, sizeof path, "/proc/self/task/%.16s/comm", e->d_name);
            char *comm = read_all(path, 64, NULL);
            if (!comm) continue;
            for (size_t i = 0; i < sizeof FRIDA_THREAD_TOKENS / sizeof *FRIDA_THREAD_TOKENS; i++) {
                if (strstr(comm, FRIDA_THREAD_TOKENS[i])) {
                    snprintf(detail, sizeof detail, "thread:%s", FRIDA_THREAD_TOKENS[i]);
                    free(comm);
                    closedir(d);
                    out_line(o, "HOOK_FRIDA_MAPS", 'F', detail);
                    return;
                }
            }
            free(comm);
        }
        closedir(d);
    }
    out_line(o, "HOOK_FRIDA_MAPS", maps_readable ? 'C' : 'D', maps_readable ? "" : "maps unreadable");
}

/** 1 = frida (D-Bus AUTH answered with REJECTED), 0 = no, -1 = socket not allowed. */
static int probe_frida_port(int port) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return (errno == EACCES || errno == EPERM) ? -1 : 0;
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port)};
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int found = 0;
    if (connect(fd, (struct sockaddr *)&a, sizeof a) == 0 || errno == EINPROGRESS) {
        struct pollfd p = {.fd = fd, .events = POLLOUT};
        int err = 0;
        socklen_t el = sizeof err;
        if (poll(&p, 1, 150) == 1 && getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) == 0 && err == 0) {
            static const char auth[] = "\0AUTH\r\n";
            if (send(fd, auth, sizeof auth - 1, MSG_NOSIGNAL) == (ssize_t)(sizeof auth - 1)) {
                p.events = POLLIN;
                char reply[64] = {0};
                if (poll(&p, 1, 300) == 1 && recv(fd, reply, sizeof reply - 1, 0) > 0 && !strncmp(reply, "REJECTED", 8)) found = 1;
            }
        }
    }
    close(fd);
    return found;
}

static void check_frida_port(out_t *o) {
    static const int ports[] = {27042, 27043};
    int denied = 0;
    for (size_t i = 0; i < 2; i++) {
        int r = probe_frida_port(ports[i]);
        if (r == 1) {
            char detail[32];
            snprintf(detail, sizeof detail, "port=%d", ports[i]);
            out_line(o, "HOOK_FRIDA_PORT", 'F', detail);
            return;
        }
        if (r < 0) denied = 1;
    }
    out_line(o, "HOOK_FRIDA_PORT", denied ? 'D' : 'C', denied ? "socket denied" : "");
}

// ------------------------------------------------------------------ JNI

static jbyteArray scan(JNIEnv *env, jclass cls, jbyteArray key) {
    (void)cls;
    if (!key) return NULL;
    out_t o = {0};
    check_su(&o);
    check_tracer(&o);
    check_emulator(&o);
    check_magisk(&o);
    check_props(&o);
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
    jclass c = (*env)->FindClass(env, "org/wolpmessenger/devicetrust/rasp/NativeRasp");
    if (!c) return JNI_ERR;
    static const JNINativeMethod methods[] = {{"scan", "([B)[B", (void *)scan}};
    if ((*env)->RegisterNatives(env, c, methods, 1) != JNI_OK) return JNI_ERR;
    return JNI_VERSION_1_6;
}
