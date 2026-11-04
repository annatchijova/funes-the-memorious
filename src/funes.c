/* funes - host collector. See docs/spec/EVIDENCE-BUNDLE-v1.md (ADR-001).
 * Executes commands as argv vectors only; never builds shell strings from
 * user input. Evidence origin labels are never promoted by this tool. */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "sha256.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <dlfcn.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>

#define MAX_CAPTURE_BYTES (1024u * 1024u)
#define DEFAULT_TIMEOUT_SEC 120

static void die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "funes: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(1);
}

static void *xmalloc(size_t n) {
    void *p = malloc(n ? n : 1);
    if (!p) die("out of memory");
    return p;
}

static void *xrealloc(void *p, size_t n) {
    void *q = realloc(p, n ? n : 1);
    if (!q) die("out of memory");
    return q;
}

static char *xstrdup(const char *s) {
    char *p = strdup(s);
    if (!p) die("out of memory");
    return p;
}

/* Dynamic string buffer. */
typedef struct { char *buf; size_t len, cap; } strbuf;

static void sb_init(strbuf *s) { s->buf = xmalloc(256); s->len = 0; s->cap = 256; s->buf[0] = '\0'; }

static void sb_addn(strbuf *s, const char *p, size_t n) {
    if (s->len + n + 1 > s->cap) {
        while (s->len + n + 1 > s->cap) s->cap *= 2;
        s->buf = xrealloc(s->buf, s->cap);
    }
    memcpy(s->buf + s->len, p, n);
    s->len += n;
    s->buf[s->len] = '\0';
}

static void sb_add(strbuf *s, const char *p) { sb_addn(s, p, strlen(p)); }

static void sb_printf(strbuf *s, const char *fmt, ...) {
    char tmp[16384];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    sb_add(s, tmp);
}

static char *hex_encode(const char *s) {
    static const char H[] = "0123456789abcdef";
    size_t n = strlen(s);
    char *out = xmalloc(n * 2 + 1);
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        out[i * 2] = H[c >> 4];
        out[i * 2 + 1] = H[c & 0xf];
    }
    out[n * 2] = '\0';
    return out;
}

static bool is_hex64(const char *s) {
    if (strlen(s) != 64) return false;
    for (int i = 0; i < 64; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

/* List of manifest lines (without header), sorted before writing. */
typedef struct { char **lines; size_t count, cap; } linelist;

static void ll_init(linelist *l) { l->lines = NULL; l->count = 0; l->cap = 0; }

static void ll_add(linelist *l, const char *line) {
    if (l->count == l->cap) {
        l->cap = l->cap ? l->cap * 2 : 32;
        l->lines = xrealloc(l->lines, l->cap * sizeof(char *));
    }
    l->lines[l->count++] = xstrdup(line);
}

static void ll_printf(linelist *l, const char *fmt, ...) {
    char tmp[16384];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    ll_add(l, tmp);
}

static bool ll_has_prefix(linelist *l, const char *prefix) {
    size_t n = strlen(prefix);
    for (size_t i = 0; i < l->count; i++) {
        if (strncmp(l->lines[i], prefix, n) == 0) return true;
    }
    return false;
}

/* Blob lines are keyed by digest alone: identical bytes (e.g. empty stdout
 * and stderr) must produce one blob line, or the manifest has duplicate keys. */
static bool ll_has_blob(linelist *l, const char *digest) {
    char key[80];
    snprintf(key, sizeof(key), "blob.%s=", digest);
    return ll_has_prefix(l, key);
}

static void ll_add_blob(linelist *l, const char *digest, unsigned long long size, const char *role) {
    if (ll_has_blob(l, digest)) return;
    ll_printf(l, "blob.%s=%llu:%s", digest, size, role);
}

static int cmp_str(const void *a, const void *b) {
    return strcmp(*(char *const *)a, *(char *const *)b);
}

static void mkdirs_for_bundle(const char *bundle) {
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s", bundle);
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) die("cannot create bundle dir %s: %s", bundle, strerror(errno));
    snprintf(tmp, sizeof(tmp), "%s/blobs", bundle);
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) die("cannot create %s: %s", tmp, strerror(errno));
    snprintf(tmp, sizeof(tmp), "%s/blobs/sha256", bundle);
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) die("cannot create %s: %s", tmp, strerror(errno));
}

/* Hash a file by streaming. Returns 0 on success. */
static int hash_file(const char *path, char hex_out[65], uint64_t *size_out) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    funes_sha256_ctx ctx;
    funes_sha256_init(&ctx);
    uint8_t buf[8192];
    size_t n;
    uint64_t total = 0;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        funes_sha256_update(&ctx, buf, n);
        total += n;
    }
    if (ferror(f)) { fclose(f); return -1; }
    fclose(f);
    uint8_t hash[32];
    funes_sha256_final(&ctx, hash);
    funes_sha256_hex(hash, hex_out);
    if (size_out) *size_out = total;
    return 0;
}

static void hash_bytes(const uint8_t *data, size_t len, char hex_out[65]) {
    funes_sha256_ctx ctx;
    funes_sha256_init(&ctx);
    if (len) funes_sha256_update(&ctx, data, len);
    uint8_t hash[32];
    funes_sha256_final(&ctx, hash);
    funes_sha256_hex(hash, hex_out);
}

/* Store memory bytes as a content-addressed blob. */
static void store_blob_mem(const char *bundle, const uint8_t *data, size_t len, char hex_out[65]) {
    hash_bytes(data, len, hex_out);
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/blobs/sha256/%s", bundle, hex_out);
    if (access(path, F_OK) == 0) return;
    char tmppath[PATH_MAX + 64];
    snprintf(tmppath, sizeof(tmppath), "%s.tmp%ld", path, (long)getpid());
    FILE *f = fopen(tmppath, "wb");
    if (!f) die("cannot write blob %s: %s", tmppath, strerror(errno));
    if (len && fwrite(data, 1, len, f) != len) { fclose(f); die("short write on blob"); }
    if (fclose(f) != 0) die("cannot close blob: %s", strerror(errno));
    if (rename(tmppath, path) != 0) die("cannot seal blob %s: %s", path, strerror(errno));
}

/* Copy a file into the bundle as a blob while hashing it. */
static void store_blob_file(const char *bundle, const char *src, char hex_out[65], uint64_t *size_out) {
    char hex[65];
    uint64_t size = 0;
    if (hash_file(src, hex, &size) != 0) die("cannot read file %s: %s", src, strerror(errno));
    memcpy(hex_out, hex, 65);
    if (size_out) *size_out = size;
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/blobs/sha256/%s", bundle, hex);
    if (access(path, F_OK) == 0) return;
    char tmppath[PATH_MAX + 64];
    snprintf(tmppath, sizeof(tmppath), "%s.tmp%ld", path, (long)getpid());
    FILE *in = fopen(src, "rb");
    if (!in) die("cannot open %s: %s", src, strerror(errno));
    FILE *out = fopen(tmppath, "wb");
    if (!out) { fclose(in); die("cannot write blob %s: %s", tmppath, strerror(errno)); }
    uint8_t buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) { fclose(in); fclose(out); die("short write on blob copy"); }
    }
    fclose(in);
    if (fclose(out) != 0) die("cannot close blob copy: %s", strerror(errno));
    if (rename(tmppath, path) != 0) die("cannot seal blob %s: %s", path, strerror(errno));
}

/* Write manifest.txt (header + sorted lines) and SEAL.txt atomically-ish. */
static void seal_bundle(const char *bundle, linelist *lines) {
    qsort(lines->lines, lines->count, sizeof(char *), cmp_str);
    strbuf sb;
    sb_init(&sb);
    sb_add(&sb, "FUNES-BUNDLE-1\n");
    for (size_t i = 0; i < lines->count; i++) {
        sb_add(&sb, lines->lines[i]);
        sb_add(&sb, "\n");
    }
    char mpath[PATH_MAX], tpath[PATH_MAX + 64], spath[PATH_MAX];
    snprintf(mpath, sizeof(mpath), "%s/manifest.txt", bundle);
    snprintf(tpath, sizeof(tpath), "%s/manifest.txt.tmp%ld", bundle, (long)getpid());
    FILE *f = fopen(tpath, "wb");
    if (!f) die("cannot write manifest: %s", strerror(errno));
    if (fwrite(sb.buf, 1, sb.len, f) != sb.len) { fclose(f); die("short write on manifest"); }
    if (fclose(f) != 0) die("cannot close manifest: %s", strerror(errno));
    if (rename(tpath, mpath) != 0) die("cannot seal manifest: %s", strerror(errno));
    char hex[65];
    hash_bytes((const uint8_t *)sb.buf, sb.len, hex);
    snprintf(spath, sizeof(spath), "%s/SEAL.txt", bundle);
    {
        /* Temp + rename, like the manifest: never fopen a bundle path that
         * could be a pre-planted symlink (red-team round 1, RT-05 family). */
        char stmp[PATH_MAX + 64];
        snprintf(stmp, sizeof(stmp), "%s.tmp%ld", spath, (long)getpid());
        f = fopen(stmp, "wb");
        if (!f) die("cannot write SEAL.txt: %s", strerror(errno));
        fprintf(f, "%s  manifest.txt\n", hex);
        if (fclose(f) != 0) die("cannot close SEAL.txt: %s", strerror(errno));
        if (rename(stmp, spath) != 0) die("cannot seal SEAL.txt: %s", strerror(errno));
    }
    free(sb.buf);
    printf("sealed bundle at %s (manifest sha256 %s)\n", bundle, hex);
}

typedef struct {
    int exit_status;
    int signaled;
    int sig;
    long elapsed_ms;
    long long started_unix;
    uint8_t *out_buf;
    size_t out_len;
    uint64_t out_total;
    int out_trunc;
    uint8_t *err_buf;
    size_t err_len;
    uint64_t err_total;
    int err_trunc;
} capture_result;

static void buf_append(uint8_t **buf, size_t *len, const uint8_t *data, size_t n,
                       uint64_t *total, int *trunc) {
    *total += n;
    if (*len >= MAX_CAPTURE_BYTES) { *trunc = 1; return; }
    size_t room = MAX_CAPTURE_BYTES - *len;
    size_t take = n < room ? n : room;
    if (take < n) *trunc = 1;
    *buf = xrealloc(*buf, *len + take + 1);
    memcpy(*buf + *len, data, take);
    *len += take;
}

/* Supervised execution: argv only, no shell. Drains pipes past the cap. */
static void run_capture(char *const argv[], int timeout_sec, long long epoch_override,
                        capture_result *r) {
    memset(r, 0, sizeof(*r));
    int out_pipe[2], err_pipe[2];
    if (pipe(out_pipe) != 0 || pipe(err_pipe) != 0) die("pipe failed: %s", strerror(errno));
    struct timespec mono_start, wall;
    clock_gettime(CLOCK_MONOTONIC, &mono_start);
    clock_gettime(CLOCK_REALTIME, &wall);
    r->started_unix = epoch_override >= 0 ? epoch_override : (long long)wall.tv_sec;
    pid_t pid = fork();
    if (pid < 0) die("fork failed: %s", strerror(errno));
    if (pid == 0) {
        dup2(out_pipe[1], STDOUT_FILENO);
        dup2(err_pipe[1], STDERR_FILENO);
        close(out_pipe[0]); close(out_pipe[1]);
        close(err_pipe[0]); close(err_pipe[1]);
        execvp(argv[0], argv);
        fprintf(stderr, "funes: cannot execute %s: %s\n", argv[0], strerror(errno));
        _exit(127);
    }
    close(out_pipe[1]);
    close(err_pipe[1]);
    fcntl(out_pipe[0], F_SETFL, O_NONBLOCK);
    fcntl(err_pipe[0], F_SETFL, O_NONBLOCK);
    int open_out = 1, open_err = 1;
    int status = 0;
    while (open_out || open_err) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed = (long)((now.tv_sec - mono_start.tv_sec) * 1000 +
                              (now.tv_nsec - mono_start.tv_nsec) / 1000000);
        if (timeout_sec > 0 && elapsed > (long)timeout_sec * 1000) {
            kill(pid, SIGKILL);
            break;
        }
        struct pollfd fds[2];
        fds[0].fd = open_out ? out_pipe[0] : -1;
        fds[0].events = POLLIN;
        fds[1].fd = open_err ? err_pipe[0] : -1;
        fds[1].events = POLLIN;
        int pr = poll(fds, 2, 100);
        if (pr < 0) {
            if (errno == EINTR) continue;
            break;
        }
        uint8_t chunk[8192];
        if (open_out && (fds[0].revents & (POLLIN | POLLHUP))) {
            ssize_t n = read(out_pipe[0], chunk, sizeof(chunk));
            if (n > 0) buf_append(&r->out_buf, &r->out_len, chunk, (size_t)n, &r->out_total, &r->out_trunc);
            else if (n == 0) open_out = 0;
        }
        if (open_err && (fds[1].revents & (POLLIN | POLLHUP))) {
            ssize_t n = read(err_pipe[0], chunk, sizeof(chunk));
            if (n > 0) buf_append(&r->err_buf, &r->err_len, chunk, (size_t)n, &r->err_total, &r->err_trunc);
            else if (n == 0) open_err = 0;
        }
    }
    close(out_pipe[0]);
    close(err_pipe[0]);
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) break;
    }
    struct timespec mono_end;
    clock_gettime(CLOCK_MONOTONIC, &mono_end);
    r->elapsed_ms = (long)((mono_end.tv_sec - mono_start.tv_sec) * 1000 +
                           (mono_end.tv_nsec - mono_start.tv_nsec) / 1000000);
    if (WIFEXITED(status)) {
        r->exit_status = WEXITSTATUS(status);
        r->signaled = 0;
        r->sig = 0;
    } else if (WIFSIGNALED(status)) {
        r->signaled = 1;
        r->sig = WTERMSIG(status);
        r->exit_status = 128 + r->sig;
    } else {
        r->exit_status = 1;
        r->signaled = 0;
        r->sig = 0;
    }
    if (!r->out_buf) { r->out_buf = xmalloc(1); }
    if (!r->err_buf) { r->err_buf = xmalloc(1); }
}

/* Run a fixed git command (no user input) and return trimmed stdout or NULL. */
static char *git_query(const char *subarg1, const char *subarg2) {
    char *args[6];
    int i = 0;
    args[i++] = (char *)"git";
    if (subarg1) args[i++] = (char *)subarg1;
    if (subarg2) args[i++] = (char *)subarg2;
    args[i] = NULL;
    capture_result r;
    run_capture(args, 10, -1, &r);
    char *res = NULL;
    if (r.exit_status == 0 && r.out_len > 0) {
        while (r.out_len > 0 && (r.out_buf[r.out_len - 1] == '\n' || r.out_buf[r.out_len - 1] == '\r'))
            r.out_len--;
        res = xmalloc(r.out_len + 1);
        memcpy(res, r.out_buf, r.out_len);
        res[r.out_len] = '\0';
    }
    free(r.out_buf);
    free(r.err_buf);
    return res;
}

static void add_argv_lines(linelist *l, const char *prefix, char *const argv[], int argc) {
    ll_printf(l, "%s.argv_count=%d", prefix, argc);
    for (int i = 0; i < argc; i++) {
        char *h = hex_encode(argv[i]);
        ll_printf(l, "%s.argv.%d.hex=%s", prefix, i, h);
        free(h);
    }
}

static void add_capture_lines(linelist *l, const char *bundle, capture_result *r,
                              const char *prefix, const char *role_out, const char *role_err) {
    char oh[65], eh[65];
    store_blob_mem(bundle, r->out_buf, r->out_len, oh);
    store_blob_mem(bundle, r->err_buf, r->err_len, eh);
    ll_printf(l, "%s.started_unix=%lld", prefix, r->started_unix);
    ll_printf(l, "%s.elapsed_ms=%ld", prefix, r->elapsed_ms);
    ll_printf(l, "%s.exit_status=%d", prefix, r->exit_status);
    ll_printf(l, "%s.signaled=%d", prefix, r->signaled);
    ll_printf(l, "%s.signal=%d", prefix, r->sig);
    ll_printf(l, "%s.stdout_sha256=%s", prefix, oh);
    ll_printf(l, "%s.stdout_size=%zu", prefix, r->out_len);
    ll_printf(l, "%s.stdout_truncated=%d", prefix, r->out_trunc);
    ll_printf(l, "%s.stderr_sha256=%s", prefix, eh);
    ll_printf(l, "%s.stderr_size=%zu", prefix, r->err_len);
    ll_printf(l, "%s.stderr_truncated=%d", prefix, r->err_trunc);
    ll_add_blob(l, oh, (unsigned long long)r->out_len, role_out);
    ll_add_blob(l, eh, (unsigned long long)r->err_len, role_err);
}

/* Load an existing manifest (without header) for add-test / import-test. */
static void load_manifest(const char *bundle, linelist *l) {
    char mpath[PATH_MAX];
    snprintf(mpath, sizeof(mpath), "%s/manifest.txt", bundle);
    FILE *f = fopen(mpath, "rb");
    if (!f) die("bundle %s has no readable manifest.txt", bundle);
    char line[16384];
    int first = 1;
    while (fgets(line, sizeof(line), f)) {
        size_t n = strlen(line);
        while (n && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = '\0';
        if (first) {
            if (strcmp(line, "FUNES-BUNDLE-1") != 0) { fclose(f); die("bundle manifest header is not FUNES-BUNDLE-1"); }
            first = 0;
            continue;
        }
        if (n == 0) continue;
        if (strncmp(line, "test_count=", 11) == 0) continue;
        ll_add(l, line);
    }
    fclose(f);
}

static int count_tests(linelist *l) {
    int mx = -1;
    for (size_t i = 0; i < l->count; i++) {
        int idx = -1;
        char org[32];
        if (sscanf(l->lines[i], "test.%d.origin=%31s", &idx, org) == 2 && idx > mx) mx = idx;
    }
    return mx + 1;
}

static bool has_artifact_digest(linelist *l, const char *digest) {
    for (size_t i = 0; i < l->count; i++) {
        const char *eq = strchr(l->lines[i], '=');
        if (!eq) continue;
        if (strstr(l->lines[i], ".sha256=") && strcmp(eq + 1, digest) == 0 &&
            strncmp(l->lines[i], "artifact.", 9) == 0) return true;
    }
    return false;
}

/* --- Ed25519 via libsodium, loaded at runtime (no custom primitives). ---
 * Guarantee provided: authenticity of the manifest commitment under a key.
 * It does not prove an execution occurred. The algorithm is fixed in code;
 * bundle metadata never selects it, so there is no downgrade path. */
typedef int (*sign_seed_keypair_fn)(uint8_t *, uint8_t *, const uint8_t *);
typedef int (*sign_detached_fn)(uint8_t *, unsigned long long *, const uint8_t *,
                                unsigned long long, const uint8_t *);
static sign_seed_keypair_fn g_seed_keypair = NULL;
static sign_detached_fn g_sign_detached = NULL;

static void load_sodium_sign(void) {
    if (g_seed_keypair && g_sign_detached) return;
    /* Absolute system paths first: a bare dlopen name honors LD_LIBRARY_PATH,
     * which let a fake libsodium receive key material (round 1, RT-03). */
    void *h = dlopen("/lib/x86_64-linux-gnu/libsodium.so.23", RTLD_NOW | RTLD_LOCAL);
    if (!h) h = dlopen("/usr/lib/x86_64-linux-gnu/libsodium.so.23", RTLD_NOW | RTLD_LOCAL);
    if (!h) h = dlopen("/usr/lib64/libsodium.so.23", RTLD_NOW | RTLD_LOCAL);
    if (!h) h = dlopen("/usr/local/lib/libsodium.so.23", RTLD_NOW | RTLD_LOCAL);
    /* No bare-name fallback on the key-handling path: fail closed. */
    if (!h) die("libsodium is unavailable (needed only for keygen/sign); install libsodium or skip signing. Integrity-only bundles remain fully usable");
    g_seed_keypair = (sign_seed_keypair_fn)dlsym(h, "crypto_sign_seed_keypair");
    g_sign_detached = (sign_detached_fn)dlsym(h, "crypto_sign_detached");
    if (!g_seed_keypair || !g_sign_detached) die("libsodium does not expose the Ed25519 signing API");
}

static void hex_encode_bytes(const uint8_t *in, size_t n, char *out) {
    static const char H[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[i * 2] = H[in[i] >> 4]; out[i * 2 + 1] = H[in[i] & 0xf]; }
    out[n * 2] = '\0';
}

static int hex_decode_bytes(const char *hex, uint8_t *out, size_t want) {
    if (strlen(hex) != want * 2) return -1;
    for (size_t i = 0; i < want; i++) {
        char a = hex[i * 2], b = hex[i * 2 + 1];
        int va = (a >= '0' && a <= '9') ? a - '0' : (a >= 'a' && a <= 'f') ? a - 'a' + 10 : -1;
        int vb = (b >= '0' && b <= '9') ? b - '0' : (b >= 'a' && b <= 'f') ? b - 'a' + 10 : -1;
        if (va < 0 || vb < 0) return -1;
        out[i] = (uint8_t)(va * 16 + vb);
    }
    return 0;
}

/* Seed file: header line + 64 hex chars. Written 0600, never overwritten. */
static void read_seed_file(const char *path, uint8_t seed[32], uint8_t pk[32]) {
    FILE *f = fopen(path, "rb");
    if (!f) die("cannot open signing key %s: %s", path, strerror(errno));
    char line1[128] = "", line2[256] = "";
    if (!fgets(line1, sizeof(line1), f) || !fgets(line2, sizeof(line2), f)) {
        fclose(f);
        die("signing key %s is malformed", path);
    }
    fclose(f);
    if (strcmp(line1, "FUNES-ED25519-SEED-1\n") != 0) die("signing key %s has a bad header", path);
    line2[strcspn(line2, "\r\n")] = '\0';
    if (hex_decode_bytes(line2, seed, 32) != 0) die("signing key %s does not contain a 32-byte hex seed", path);
    uint8_t sk[64];
    load_sodium_sign();
    if (g_seed_keypair(pk, sk, seed) != 0) die("cannot derive keypair from seed");
    memset(sk, 0, sizeof(sk));
}

static void pubkey_fingerprint(const uint8_t pk[32], char out[65]) {
    hash_bytes(pk, 32, out);
}

static int cmd_keygen(int argc, char **argv) {
    const char *out = NULL, *pubout = NULL;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) out = argv[++i];
        else if (strcmp(argv[i], "--pub-out") == 0 && i + 1 < argc) pubout = argv[++i];
        else die("keygen: unknown or incomplete option %s", argv[i]);
    }
    if (!out || !pubout) die("keygen: --out SEEDFILE --pub-out PUBFILE are required");
    if (access(out, F_OK) == 0 || access(pubout, F_OK) == 0)
        die("keygen: refusing to overwrite an existing key file");
    uint8_t seed[32];
    ssize_t got = getrandom(seed, sizeof(seed), 0);
    if (got != (ssize_t)sizeof(seed)) die("getrandom failed: %s", strerror(errno));
    uint8_t pk[32], sk[64];
    load_sodium_sign();
    if (g_seed_keypair(pk, sk, seed) != 0) die("libsodium keypair derivation failed");
    memset(sk, 0, sizeof(sk));
    int fd = open(out, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) die("cannot create seed file %s: %s", out, strerror(errno));
    char seedhex[65];
    hex_encode_bytes(seed, 32, seedhex);
    char sbuf[256];
    int sn = snprintf(sbuf, sizeof(sbuf), "FUNES-ED25519-SEED-1\n%s\n", seedhex);
    if (write(fd, sbuf, (size_t)sn) != sn) { close(fd); die("cannot write seed file"); }
    if (close(fd) != 0) die("cannot close seed file: %s", strerror(errno));
    memset(seed, 0, sizeof(seed));
    char pkhex[65];
    hex_encode_bytes(pk, 32, pkhex);
    FILE *pf = fopen(pubout, "wx");
    if (!pf) die("cannot create public key file %s: %s", pubout, strerror(errno));
    fprintf(pf, "%s\n", pkhex);
    if (fclose(pf) != 0) die("cannot close public key file: %s", strerror(errno));
    char fp[65];
    pubkey_fingerprint(pk, fp);
    printf("signer_pubkey_hex=%s\n", pkhex);
    printf("signer_fingerprint_sha256=%s\n", fp);
    printf("warning: seed file %s is unencrypted (mode 0600). Protect it like a password; anyone holding it can sign as this key. It is never copied into a bundle.\n", out);
    return 0;
}

static int cmd_sign(int argc, char **argv) {
    const char *bundle = NULL, *key = NULL;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--bundle") == 0 && i + 1 < argc) bundle = argv[++i];
        else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) key = argv[++i];
        else die("sign: unknown or incomplete option %s", argv[i]);
    }
    if (!bundle || !key) die("sign: --bundle DIR --key SEEDFILE are required");
    uint8_t seed[32], pk[32];
    read_seed_file(key, seed, pk);
    char mpath[PATH_MAX];
    snprintf(mpath, sizeof(mpath), "%s/manifest.txt", bundle);
    FILE *mf = fopen(mpath, "rb");
    if (!mf) die("bundle %s has no readable manifest.txt", bundle);
    strbuf mb;
    sb_init(&mb);
    char chunk[8192];
    size_t n;
    while ((n = fread(chunk, 1, sizeof(chunk), mf)) > 0) sb_addn(&mb, chunk, n);
    fclose(mf);
    char mdigest[65];
    hash_bytes((const uint8_t *)mb.buf, mb.len, mdigest);
    free(mb.buf);
    /* Domain-separated payload: exactly FUNES-SIGN-1\n<manifest sha256 hex>\n */
    char payload[128];
    int plen = snprintf(payload, sizeof(payload), "FUNES-SIGN-1\n%s\n", mdigest);
    uint8_t sk[64];
    if (g_seed_keypair(pk, sk, seed) != 0) die("cannot derive keypair from seed");
    memset(seed, 0, sizeof(seed));
    uint8_t sig[64];
    unsigned long long siglen = 0;
    if (g_sign_detached(sig, &siglen, (const uint8_t *)payload, (unsigned long long)plen, sk) != 0 || siglen != 64)
        die("libsodium signing failed");
    memset(sk, 0, sizeof(sk));
    char sdir[PATH_MAX];
    snprintf(sdir, sizeof(sdir), "%s/signatures", bundle);
    if (mkdir(sdir, 0755) != 0 && errno != EEXIST) die("cannot create %s: %s", sdir, strerror(errno));
    /* O_NOFOLLOW writes: a pre-planted symlink in the bundle must not turn
     * signing into an overwrite of an outside file (round 1, RT-05). */
    char sigpath[PATH_MAX + 64];
    snprintf(sigpath, sizeof(sigpath), "%s/ed25519.sig", sdir);
    int sfd = open(sigpath, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0644);
    if (sfd < 0) die("cannot write signature %s: %s", sigpath, strerror(errno));
    FILE *sf = fdopen(sfd, "wb");
    if (!sf) { close(sfd); die("cannot write signature: %s", strerror(errno)); }
    if (fwrite(sig, 1, 64, sf) != 64) { fclose(sf); die("short write on signature"); }
    if (fclose(sf) != 0) die("cannot close signature: %s", strerror(errno));
    char pkhex[65], fp[65];
    hex_encode_bytes(pk, 32, pkhex);
    pubkey_fingerprint(pk, fp);
    char txtpath[PATH_MAX + 64];
    snprintf(txtpath, sizeof(txtpath), "%s/signer.txt", sdir);
    int tfd = open(txtpath, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0644);
    if (tfd < 0) die("cannot write signer.txt %s: %s", txtpath, strerror(errno));
    FILE *tf = fdopen(tfd, "wb");
    if (!tf) { close(tfd); die("cannot write signer.txt: %s", strerror(errno)); }
    fprintf(tf, "algorithm=ed25519\nmanifest_sha256=%s\npayload_domain=FUNES-SIGN-1\nsigner_fingerprint_sha256=%s\nsigner_pubkey_hex=%s\n", mdigest, fp, pkhex);
    if (fclose(tf) != 0) die("cannot close signer.txt: %s", strerror(errno));
    printf("signed bundle %s manifest_sha256=%s signer_fingerprint_sha256=%s\n", bundle, mdigest, fp);
    printf("note: a valid signature proves control of this key, not that any execution occurred.\n");
    return 0;
}

static void usage(FILE *out) {
    fprintf(out,
        "funes - host collector for FUNES evidence bundles (format v1)\n"
        "usage:\n"
        "  funes doctor [--json]\n"
        "  funes capture --out DIR [--source FILE]... [--artifact PATH:ROLE]...\n"
        "                [--timeout-sec N] [--epoch N] -- CMD [ARGS...]\n"
        "  funes add-test --bundle DIR --artifact-sha256 HEX\n"
        "                [--timeout-sec N] [--epoch N] -- CMD [ARGS...]\n"
        "  funes import-test --bundle DIR --artifact-sha256 HEX --report FILE\n"
        "  funes keygen --out SEEDFILE --pub-out PUBFILE\n"
        "  funes sign --bundle DIR --key SEEDFILE\n"
        "  funes compare [--json] BUNDLE_A BUNDLE_B\n"
        "  funes --help\n"
        "capture/add-test exit status mirrors the executed command; the bundle\n"
        "is sealed even when that command fails. See docs/spec/.\n");
}

static int cmd_doctor(int json) {
    struct utsname u;
    uname(&u);
    const char *qh = getenv("QNX_HOST");
    const char *qt = getenv("QNX_TARGET");
    int qcc_found = 0;
    char qcc_path[PATH_MAX] = "";
    const char *path = getenv("PATH");
    if (path) {
        char *copy = xstrdup(path);
        char *save = NULL;
        for (char *tok = strtok_r(copy, ":", &save); tok; tok = strtok_r(NULL, ":", &save)) {
            char cand[PATH_MAX];
            snprintf(cand, sizeof(cand), "%s/qcc", tok);
            if (access(cand, X_OK) == 0) { qcc_found = 1; snprintf(qcc_path, sizeof(qcc_path), "%s", cand); break; }
        }
        free(copy);
    }
    const char *tstat = qcc_found ? "FOUND_ON_PATH_UNVERIFIED" : "NOT_FOUND";
    if (json) {
        printf("{\"host_os\":\"%s\",\"host_arch\":\"%s\",\"qnx_host_present\":%s,"
               "\"qnx_target_present\":%s,\"qcc_found\":%s,"
               "\"qnx_toolchain_status\":\"%s\",\"limitations\":\"doctor reports "
               "presence and paths only; it does not authenticate a toolchain\"}\n",
               u.sysname, u.machine, qh ? "true" : "false", qt ? "true" : "false",
               qcc_found ? "true" : "false", tstat);
    } else {
        printf("host_os=%s\n", u.sysname);
        printf("host_arch=%s\n", u.machine);
        printf("host_release=%s\n", u.release);
        printf("qnx_host_present=%s\n", qh ? "1" : "0");
        printf("qnx_target_present=%s\n", qt ? "1" : "0");
        printf("qcc_found=%s\n", qcc_found ? "1" : "0");
        if (qcc_found) printf("qcc_path=%s\n", qcc_path);
        printf("qnx_toolchain_status=%s\n", tstat);
        if (!qcc_found)
            printf("note=QNX SDP 8.0 toolchain not found on PATH; QNX build status is BLOCKED, not simulated. See docs/QNX-SETUP.md\n");
        else
            printf("note=qcc presence is unauthenticated; version text is evidence, not proof of a genuine QNX SDP. See docs/QNX-SETUP.md\n");
    }
    return 0;
}

static int cmd_capture(int argc, char **argv) {
    const char *out = NULL;
    const char *sources[128];
    int nsrc = 0;
    const char *arts[128];
    int nart = 0;
    int timeout_sec = DEFAULT_TIMEOUT_SEC;
    long long epoch = -1;
    int i = 0;
    while (i < argc) {
        if (strcmp(argv[i], "--") == 0) { i++; break; }
        if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) out = argv[++i];
        else if (strcmp(argv[i], "--source") == 0 && i + 1 < argc) {
            if (nsrc >= 128) die("too many --source files (max 128)");
            sources[nsrc++] = argv[++i];
        } else if (strcmp(argv[i], "--artifact") == 0 && i + 1 < argc) {
            if (nart >= 128) die("too many --artifact files (max 128)");
            arts[nart++] = argv[++i];
        } else if (strcmp(argv[i], "--timeout-sec") == 0 && i + 1 < argc) timeout_sec = atoi(argv[++i]);
        else if (strcmp(argv[i], "--epoch") == 0 && i + 1 < argc) epoch = atoll(argv[++i]);
        else die("capture: unknown or incomplete option %s", argv[i]);
        i++;
    }
    if (!out) die("capture: --out DIR is required");
    if (i >= argc) die("capture: missing command after --");
    char **cmd = &argv[i];
    int cmdargc = argc - i;
    mkdirs_for_bundle(out);
    linelist l;
    ll_init(&l);
    ll_add(&l, "schema_version=1");
    ll_add(&l, "build.origin=OBSERVED");
    /* Source state before the build runs. */
    char *head = git_query("rev-parse", "HEAD");
    ll_printf(&l, "source.git_head=%s", (head && strlen(head) == 40) ? head : "NONE");
    free(head);
    char *porc = git_query("status", "--porcelain");
    ll_printf(&l, "source.git_dirty=%d", porc ? 1 : 0);
    free(porc);
    ll_printf(&l, "source.file_count=%d", nsrc);
    strbuf comb;
    sb_init(&comb);
    /* Sort source paths by byte order for a stable combined digest. */
    for (int a = 0; a < nsrc; a++) {
        for (int b = a + 1; b < nsrc; b++) {
            if (strcmp(sources[a], sources[b]) > 0) {
                const char *t = sources[a]; sources[a] = sources[b]; sources[b] = t;
            }
        }
    }
    for (int s = 0; s < nsrc; s++) {
        char hex[65];
        uint64_t sz = 0;
        if (hash_file(sources[s], hex, &sz) != 0) die("capture: cannot read source file %s", sources[s]);
        char *ph = hex_encode(sources[s]);
        ll_printf(&l, "source.file.%d.path.hex=%s", s, ph);
        ll_printf(&l, "source.file.%d.sha256=%s", s, hex);
        sb_printf(&comb, "%s  %s\n", hex, ph);
        free(ph);
    }
    if (nsrc == 0) ll_add(&l, "source.digest=NONE");
    else {
        char dh[65];
        hash_bytes((const uint8_t *)comb.buf, comb.len, dh);
        ll_printf(&l, "source.digest=%s", dh);
    }
    free(comb.buf);
    struct utsname u;
    uname(&u);
    char *oh = hex_encode(u.sysname);
    char *ah = hex_encode(u.machine);
    ll_printf(&l, "env.host_os.hex=%s", oh);
    ll_printf(&l, "env.host_arch.hex=%s", ah);
    free(oh); free(ah);
    ll_printf(&l, "qnx.host_present=%d", getenv("QNX_HOST") ? 1 : 0);
    ll_printf(&l, "qnx.target_present=%d", getenv("QNX_TARGET") ? 1 : 0);
    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd))) die("cannot read working directory");
    char *ch = hex_encode(cwd);
    ll_printf(&l, "build.cwd.hex=%s", ch);
    free(ch);
    add_argv_lines(&l, "build", cmd, cmdargc);
    capture_result r;
    run_capture(cmd, timeout_sec, epoch, &r);
    add_capture_lines(&l, out, &r, "build", "stdout", "stderr");
    ll_printf(&l, "artifact_count=%d", nart);
    for (int a = 0; a < nart; a++) {
        const char *colon = strrchr(arts[a], ':');
        if (!colon || colon == arts[a] || !colon[1]) die("capture: --artifact must be PATH:ROLE, got %s", arts[a]);
        char apath[PATH_MAX];
        size_t plen = (size_t)(colon - arts[a]);
        if (plen >= sizeof(apath)) die("capture: artifact path too long");
        memcpy(apath, arts[a], plen);
        apath[plen] = '\0';
        struct stat st;
        if (stat(apath, &st) != 0) die("capture: artifact %s not found after build (%s)", apath, strerror(errno));
        if (!S_ISREG(st.st_mode)) die("capture: artifact %s is not a regular file", apath);
        char hex[65];
        uint64_t sz = 0;
        store_blob_file(out, apath, hex, &sz);
        char *nh = hex_encode(apath);
        ll_printf(&l, "artifact.%d.name.hex=%s", a, nh);
        free(nh);
        ll_printf(&l, "artifact.%d.role=%s", a, colon + 1);
        ll_printf(&l, "artifact.%d.sha256=%s", a, hex);
        ll_printf(&l, "artifact.%d.size=%llu", a, (unsigned long long)sz);
        ll_add_blob(&l, hex, (unsigned long long)sz, "artifact");
    }
    ll_add(&l, "test_count=0");
    seal_bundle(out, &l);
    int rc = r.exit_status;
    printf("capture exit_status=%d signaled=%d elapsed_ms=%ld\n", r.exit_status, r.signaled, r.elapsed_ms);
    free(r.out_buf);
    free(r.err_buf);
    return rc;
}

static int cmd_add_test(int argc, char **argv, int imported, const char *report) {
    const char *bundle = NULL;
    const char *adigest = NULL;
    int timeout_sec = DEFAULT_TIMEOUT_SEC;
    long long epoch = -1;
    int i = 0;
    while (i < argc) {
        if (strcmp(argv[i], "--") == 0) { i++; break; }
        if (strcmp(argv[i], "--bundle") == 0 && i + 1 < argc) bundle = argv[++i];
        else if (strcmp(argv[i], "--artifact-sha256") == 0 && i + 1 < argc) adigest = argv[++i];
        else if (strcmp(argv[i], "--timeout-sec") == 0 && i + 1 < argc) timeout_sec = atoi(argv[++i]);
        else if (strcmp(argv[i], "--epoch") == 0 && i + 1 < argc) epoch = atoll(argv[++i]);
        else if (!imported) die("add-test: unknown or incomplete option %s", argv[i]);
        else break;
        i++;
    }
    if (!bundle) die("add-test/import-test: --bundle DIR is required");
    if (!adigest || !is_hex64(adigest)) die("--artifact-sha256 must be 64 lowercase hex characters");
    linelist l;
    ll_init(&l);
    load_manifest(bundle, &l);
    if (!has_artifact_digest(&l, adigest))
        die("artifact digest %s is not recorded in bundle %s; refusing to attach test evidence to an unknown artifact", adigest, bundle);
    int idx = count_tests(&l);
    if (imported) {
        if (!report) die("import-test: --report FILE is required");
        char hex[65];
        uint64_t sz = 0;
        store_blob_file(bundle, report, hex, &sz);
        char pfx[64];
        snprintf(pfx, sizeof(pfx), "test.%d", idx);
        ll_printf(&l, "%s.origin=IMPORTED", pfx);
        ll_printf(&l, "%s.artifact_sha256=%s", pfx, adigest);
        ll_printf(&l, "%s.report_sha256=%s", pfx, hex);
        ll_printf(&l, "%s.report_size=%llu", pfx, (unsigned long long)sz);
        ll_add_blob(&l, hex, (unsigned long long)sz, "imported-report");
        ll_printf(&l, "test_count=%d", idx + 1);
        seal_bundle(bundle, &l);
        printf("imported test record %d (origin=IMPORTED, never promoted to OBSERVED)\n", idx);
        return 0;
    }
    if (i >= argc) die("add-test: missing command after --");
    char **cmd = &argv[i];
    int cmdargc = argc - i;
    char pfx[64];
    snprintf(pfx, sizeof(pfx), "test.%d", idx);
    ll_printf(&l, "%s.origin=OBSERVED", pfx);
    ll_printf(&l, "%s.artifact_sha256=%s", pfx, adigest);
    add_argv_lines(&l, pfx, cmd, cmdargc);
    capture_result r;
    run_capture(cmd, timeout_sec, epoch, &r);
    add_capture_lines(&l, bundle, &r, pfx, "test-stdout", "test-stderr");
    ll_printf(&l, "test_count=%d", idx + 1);
    seal_bundle(bundle, &l);
    int rc = r.exit_status;
    printf("test %d exit_status=%d signaled=%d elapsed_ms=%ld\n", idx, r.exit_status, r.signaled, r.elapsed_ms);
    free(r.out_buf);
    free(r.err_buf);
    return rc;
}

/* --- Level 5: forensic comparison. Consumes the independent verifier
 * first; manifest values are only diffed after both bundles verify. --- */
static const char *mv_get(linelist *l, const char *key) {
    size_t klen = strlen(key);
    for (size_t i = 0; i < l->count; i++) {
        if (strncmp(l->lines[i], key, klen) == 0 && l->lines[i][klen] == '=')
            return l->lines[i] + klen + 1;
    }
    return "NONE";
}

static int run_sibling_verify(const char *bundle) {
    char exe[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n <= 0) return -1;
    exe[n] = '\0';
    char *slash = strrchr(exe, '/');
    if (!slash) return -1;
    slash[1] = '\0';
    char vpath[PATH_MAX + 64];
    snprintf(vpath, sizeof(vpath), "%sfunes-verify", exe);
    if (access(vpath, X_OK) != 0) return -1;
    char *args[4];
    args[0] = vpath;
    args[1] = (char *)bundle;
    args[2] = NULL;
    capture_result r;
    run_capture(args, 30, -1, &r);
    int rc = r.exit_status;
    free(r.out_buf);
    free(r.err_buf);
    return rc;
}

static int g_diffs = 0;
static int g_json_mode = 0;
static int g_first_diff = 1;

static void diff_field(const char *name, const char *a, const char *b) {
    if (strcmp(a, b) == 0) return;
    g_diffs++;
    if (g_json_mode) {
        printf("%s{\"field\":\"%s\",\"a\":\"%s\",\"b\":\"%s\"}", g_first_diff ? "" : ",", name, a, b);
        g_first_diff = 0;
    } else {
        printf("DIFF %s: %s -> %s\n", name, a, b);
    }
}

static void collect_by_suffix(linelist *l, const char *marker, strbuf *out) {
    /* Collect values of keys containing marker, sorted by full line. */
    linelist tmp;
    ll_init(&tmp);
    for (size_t i = 0; i < l->count; i++) {
        if (strstr(l->lines[i], marker)) ll_add(&tmp, l->lines[i]);
    }
    qsort(tmp.lines, tmp.count, sizeof(char *), cmp_str);
    for (size_t i = 0; i < tmp.count; i++) {
        const char *eq = strchr(tmp.lines[i], '=');
        sb_add(out, eq ? eq + 1 : tmp.lines[i]);
        sb_add(out, ";");
        free(tmp.lines[i]);
    }
    free(tmp.lines);
}

static int cmd_compare(int argc, char **argv) {
    const char *ba = NULL, *bb = NULL;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--json") == 0) g_json_mode = 1;
        else if (!ba) ba = argv[i];
        else if (!bb) bb = argv[i];
        else die("compare: unexpected argument %s", argv[i]);
    }
    if (!ba || !bb) die("compare: usage: funes compare [--json] BUNDLE_A BUNDLE_B");
    int va = run_sibling_verify(ba);
    int vb = run_sibling_verify(bb);
    if (va < 0 || vb < 0) die("compare: sibling funes-verify not found next to funes; comparison requires authoritative verification first");
    if (va != 0 || vb != 0) {
        if (g_json_mode)
            printf("{\"compare_status\":\"INVALID_INPUT\",\"verify_a_exit\":%d,\"verify_b_exit\":%d}\n", va, vb);
        else
            printf("compare_status=INVALID_INPUT\nverify_a_exit=%d\nverify_b_exit=%d\ndetail=at least one bundle does not verify; refusing to diff unverified claims as fact\n", va, vb);
        return 2;
    }
    linelist la, lb;
    ll_init(&la);
    ll_init(&lb);
    load_manifest(ba, &la);
    load_manifest(bb, &lb);
    if (g_json_mode) printf("{\"compare_status\":\"OK\",\"differences\":[");
    else printf("compare_status=OK\nverify_a=INTEGRITY_VALID\nverify_b=INTEGRITY_VALID\n");
    static const char *fields[] = {
        "schema_version", "source.git_head", "source.git_dirty", "source.digest",
        "build.exit_status", "build.stdout_sha256", "artifact_count",
        "test_count", "qnx.host_present", "qnx.target_present", NULL};
    for (int i = 0; fields[i]; i++) diff_field(fields[i], mv_get(&la, fields[i]), mv_get(&lb, fields[i]));
    strbuf aa, ab;
    sb_init(&aa); sb_init(&ab);
    collect_by_suffix(&la, ".argv.", &aa);
    collect_by_suffix(&lb, ".argv.", &ab);
    /* argv digests are long; report as changed-field only via a hash. */
    {
        char ha[65], hb[65];
        hash_bytes((const uint8_t *)aa.buf, aa.len, ha);
        hash_bytes((const uint8_t *)ab.buf, ab.len, hb);
        diff_field("argv.set_sha256", ha, hb);
    }
    free(aa.buf); free(ab.buf);
    sb_init(&aa); sb_init(&ab);
    collect_by_suffix(&la, "artifact.", &aa);
    collect_by_suffix(&lb, "artifact.", &ab);
    {
        char ha[65], hb[65];
        hash_bytes((const uint8_t *)aa.buf, aa.len, ha);
        hash_bytes((const uint8_t *)ab.buf, ab.len, hb);
        diff_field("artifact.set_sha256", ha, hb);
    }
    free(aa.buf); free(ab.buf);
    sb_init(&aa); sb_init(&ab);
    collect_by_suffix(&la, "test.", &aa);
    collect_by_suffix(&lb, "test.", &ab);
    {
        char ha[65], hb[65];
        hash_bytes((const uint8_t *)aa.buf, aa.len, ha);
        hash_bytes((const uint8_t *)ab.buf, ab.len, hb);
        diff_field("test.set_sha256", ha, hb);
    }
    free(aa.buf); free(ab.buf);
    /* Per-artifact detail for human readers (digest-level, by index). */
    if (!g_json_mode) {
        int na = atoi(mv_get(&la, "artifact_count"));
        int nb = atoi(mv_get(&lb, "artifact_count"));
        int mx = na > nb ? na : nb;
        for (int i = 0; i < mx; i++) {
            char k[128];
            snprintf(k, sizeof(k), "artifact.%d.sha256", i);
            const char *da = mv_get(&la, k), *db = mv_get(&lb, k);
            if (strcmp(da, db) != 0) printf("DIFF artifact.%d.sha256: %s -> %s\n", i, da, db);
            snprintf(k, sizeof(k), "artifact.%d.role", i);
            const char *ra = mv_get(&la, k), *rb = mv_get(&lb, k);
            if (strcmp(ra, rb) != 0) printf("DIFF artifact.%d.role: %s -> %s\n", i, ra, rb);
        }
        int ta = atoi(mv_get(&la, "test_count"));
        int tb = atoi(mv_get(&lb, "test_count"));
        int mt = ta > tb ? ta : tb;
        for (int i = 0; i < mt; i++) {
            char k[128];
            snprintf(k, sizeof(k), "test.%d.exit_status", i);
            const char *ea = mv_get(&la, k), *eb = mv_get(&lb, k);
            if (strcmp(ea, eb) != 0) printf("DIFF test.%d.exit_status: %s -> %s\n", i, ea, eb);
            snprintf(k, sizeof(k), "test.%d.origin", i);
            const char *oa = mv_get(&la, k), *ob = mv_get(&lb, k);
            if (strcmp(oa, ob) != 0) printf("DIFF test.%d.origin: %s -> %s\n", i, oa, ob);
        }
    }
    if (g_json_mode) printf("],\"material_differences\":%d}\n", g_diffs);
    else printf("material_differences=%d\n", g_diffs);
    if (!g_json_mode && g_diffs == 0)
        printf("note=material evidence is identical; timestamps, elapsed time and host paths were ignored\n");
    return g_diffs ? 10 : 0;
}

int main(int argc, char **argv) {
    if (argc < 2) { usage(stderr); return 1; }
    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) { usage(stdout); return 0; }
    if (strcmp(argv[1], "doctor") == 0) {
        int json = (argc > 2 && strcmp(argv[2], "--json") == 0);
        return cmd_doctor(json);
    }
    if (strcmp(argv[1], "keygen") == 0) return cmd_keygen(argc - 2, argv + 2);
    if (strcmp(argv[1], "sign") == 0) return cmd_sign(argc - 2, argv + 2);
    if (strcmp(argv[1], "compare") == 0) return cmd_compare(argc - 2, argv + 2);
    if (strcmp(argv[1], "capture") == 0) return cmd_capture(argc - 2, argv + 2);
    if (strcmp(argv[1], "add-test") == 0) return cmd_add_test(argc - 2, argv + 2, 0, NULL);
    if (strcmp(argv[1], "import-test") == 0) {
        const char *report = NULL;
        int j = 2;
        /* Extract --report first; the rest is parsed by cmd_add_test. */
        for (; j < argc; j++) {
            if (strcmp(argv[j], "--report") == 0 && j + 1 < argc) { report = argv[j + 1]; break; }
        }
        if (!report) die("import-test: --report FILE is required");
        return cmd_add_test(argc - 2, argv + 2, 1, report);
    }
    fprintf(stderr, "funes: unknown command %s\n", argv[1]);
    usage(stderr);
    return 1;
}




