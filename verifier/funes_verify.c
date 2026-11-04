/* funes-verify - independent verifier. Own parser, own SHA-256; shares no
 * object code with the collector (docs/spec/VERIFIER-SEMANTICS.md, ADR-001).
 * Read-only, offline, fail-closed. Never emits SAFE/TRUSTED. */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "sha256.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <dlfcn.h>

#define MAX_MANIFEST_BYTES (1024u * 1024u)
#define MAX_BLOB_BYTES (64ull * 1024ull * 1024ull)
#define MAX_LINES 10000
#define MAX_LINE 8192

static int g_json = 0;
static char g_detail[1024] = "";
static const char *g_code = "";
static int g_exit = 0;
/* Default to NOT_CHECKED, not NOT_PRESENT/NOT_APPLICABLE: these globals hold
 * their default value whenever an earlier check exits before the signature
 * phase below ever runs, and "not present" would misreport a bundle that
 * actually carries a valid signature the verifier simply never got to
 * (Red Team Round 2, RT2-04). The signature phase sets the genuine
 * NOT_PRESENT/NOT_APPLICABLE pair itself, explicitly, only when it actually
 * runs and finds no signatures/ directory. */
static char g_sig[64] = "NOT_CHECKED";
static char g_trust[64] = "NOT_CHECKED";
static char g_fp[65] = "";

static void *xmalloc(size_t n) {
    void *p = malloc(n ? n : 1);
    if (!p) { fprintf(stderr, "funes-verify: out of memory\n"); exit(1); }
    return p;
}

static void *xrealloc(void *p, size_t n) {
    void *q = realloc(p, n ? n : 1);
    if (!q) { fprintf(stderr, "funes-verify: out of memory\n"); exit(1); }
    return q;
}

typedef struct { char *key; char *val; } entry;
static entry *g_entries = NULL;
static size_t g_count = 0, g_cap = 0;

static void add_entry(const char *key, const char *val) {
    if (g_count == g_cap) {
        g_cap = g_cap ? g_cap * 2 : 64;
        g_entries = xrealloc(g_entries, g_cap * sizeof(entry));
    }
    g_entries[g_count].key = strdup(key);
    g_entries[g_count].val = strdup(val);
    if (!g_entries[g_count].key || !g_entries[g_count].val) exit(1);
    g_count++;
}

static const char *get_val(const char *key) {
    for (size_t i = 0; i < g_count; i++) {
        if (strcmp(g_entries[i].key, key) == 0) return g_entries[i].val;
    }
    return NULL;
}

static bool has_key(const char *key) { return get_val(key) != NULL; }

/* Frees every entry and resets the global key-value store. The CLI binary
 * never needs this (the process exits after one bundle), but a libFuzzer
 * harness runs thousands of inputs per process and must not let entries
 * accumulate across iterations (Level 6 fuzzing harness). */
static void reset_manifest_store(void) {
    for (size_t i = 0; i < g_count; i++) {
        free(g_entries[i].key);
        free(g_entries[i].val);
    }
    free(g_entries);
    g_entries = NULL;
    g_count = 0;
    g_cap = 0;
}

static bool is_hex64(const char *s) {
    if (!s || strlen(s) != 64) return false;
    for (int i = 0; i < 64; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

static bool parse_u64(const char *s, unsigned long long *out) {
    if (!s || !*s) return false;
    if (s[0] == '0' && s[1] != '\0') return false;
    for (const char *p = s; *p; p++) if (*p < '0' || *p > '9') return false;
    errno = 0;
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno || !end || *end) return false;
    *out = v;
    return true;
}

static void report_and_exit(const char *integrity, const char *art,
                            const char *testobs, const char *qnxf) {
    if (g_json) {
        printf("{\"integrity_status\":\"%s\",\"signature_status\":\"%s\","
               "\"signer_trust_status\":\"%s\",\"signer_fingerprint_sha256\":\"%s\","
               "\"artifact_status\":\"%s\","
               "\"test_observation_status\":\"%s\",\"qnx_toolchain_status\":\"%s\","
               "\"error_code\":\"%s\",\"detail\":\"%s\","
               "\"limitations\":\"integrity is not authenticity; a valid signature "
               "proves control of a key, not that an execution occurred; validity "
               "does not certify software safety\"}\n",
               integrity, g_sig, g_trust, g_fp, art, testobs, qnxf, g_code, g_detail);
    } else {
        printf("integrity_status=%s\n", integrity);
        printf("signature_status=%s\n", g_sig);
        printf("signer_trust_status=%s\n", g_trust);
        if (g_fp[0]) printf("signer_fingerprint_sha256=%s\n", g_fp);
        printf("artifact_status=%s\n", art);
        printf("test_observation_status=%s\n", testobs);
        printf("qnx_toolchain_status=%s\n", qnxf);
        if (g_code[0]) printf("error_code=%s\n", g_code);
        if (g_detail[0]) printf("detail=%s\n", g_detail);
        printf("limitations=integrity is not authenticity; authenticity would not prove execution; validity does not certify software safety\n");
    }
    exit(g_exit);
}

#define FAIL(code, ex, ...) do { \
    g_code = (code); g_exit = (ex); \
    snprintf(g_detail, sizeof(g_detail), __VA_ARGS__); \
    report_and_exit("INTEGRITY_INVALID", "NOT_CHECKED", "NOT_CHECKED", "NOT_CHECKED"); \
} while (0)

static uint8_t *read_file(const char *path, size_t *len_out) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) { fclose(f); return NULL; }
    uint8_t *buf = xmalloc((size_t)sz + 1);
    if (sz > 0 && fread(buf, 1, (size_t)sz, f) != (size_t)sz) { fclose(f); free(buf); return NULL; }
    fclose(f);
    buf[sz] = '\0';
    *len_out = (size_t)sz;
    return buf;
}

static void hash_bytes(const uint8_t *d, size_t n, char out[65]) {
    funes_sha256_ctx c;
    funes_sha256_init(&c);
    if (n) funes_sha256_update(&c, d, n);
    uint8_t h[32];
    funes_sha256_final(&c, h);
    funes_sha256_hex(h, out);
}

static int hash_file_stream(const char *path, char out[65], unsigned long long *size_out) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    funes_sha256_ctx c;
    funes_sha256_init(&c);
    uint8_t b[8192];
    size_t n;
    unsigned long long t = 0;
    while ((n = fread(b, 1, sizeof(b), f)) > 0) { funes_sha256_update(&c, b, n); t += n; }
    fclose(f);
    uint8_t h[32];
    funes_sha256_final(&c, h);
    funes_sha256_hex(h, out);
    *size_out = t;
    return 0;
}

static bool starts(const char *s, const char *p) { return strncmp(s, p, strlen(p)) == 0; }

/* Ed25519 verification via libsodium, loaded at runtime. The algorithm is
 * fixed here; signer.txt metadata never selects it (no downgrade path). */
typedef int (*verify_detached_fn)(const uint8_t *, const uint8_t *,
                                  unsigned long long, const uint8_t *);
static verify_detached_fn g_verify_detached = NULL;
static int sodium_verify_available(void) {
    if (g_verify_detached) return 1;
    /* Absolute paths first (red-team round 1, RT-03). */
    void *h = dlopen("/lib/x86_64-linux-gnu/libsodium.so.23", RTLD_NOW | RTLD_LOCAL);
    if (!h) h = dlopen("/usr/lib/x86_64-linux-gnu/libsodium.so.23", RTLD_NOW | RTLD_LOCAL);
    if (!h) h = dlopen("/usr/lib64/libsodium.so.23", RTLD_NOW | RTLD_LOCAL);
    if (!h) h = dlopen("/usr/local/lib/libsodium.so.23", RTLD_NOW | RTLD_LOCAL);
    /* No bare-name fallback: a search-path library must not decide trust. */
    if (!h) return 0;
    g_verify_detached = (verify_detached_fn)dlsym(h, "crypto_sign_verify_detached");
    return g_verify_detached != NULL;
}

static int hex_decode(const char *hex, uint8_t *out, size_t want) {
    if (!hex || strlen(hex) != want * 2) return -1;
    for (size_t i = 0; i < want; i++) {
        char a = hex[i * 2], b = hex[i * 2 + 1];
        int va = (a >= '0' && a <= '9') ? a - '0' : (a >= 'a' && a <= 'f') ? a - 'a' + 10 : -1;
        int vb = (b >= '0' && b <= '9') ? b - '0' : (b >= 'a' && b <= 'f') ? b - 'a' + 10 : -1;
        if (va < 0 || vb < 0) return -1;
        out[i] = (uint8_t)(va * 16 + vb);
    }
    return 0;
}

/* Read a trusted public-key file: exactly 64 hex chars plus optional LF. */
static int read_trusted_pubkey(const char *path, uint8_t pk[32]) {
    size_t len = 0;
    uint8_t *buf = read_file(path, &len);
    if (!buf) return -1;
    while (len && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) len--;
    buf[len] = '\0';
    int rc = hex_decode((const char *)buf, pk, 32);
    free(buf);
    return rc;
}

/* Extract key=value from signer.txt content; strict single occurrence. */
static int signer_get(const char *text, const char *key, char *out, size_t outsz) {
    size_t klen = strlen(key);
    int found = 0;
    const char *p = text;
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t linelen = nl ? (size_t)(nl - p) : strlen(p);
        if (linelen > klen && strncmp(p, key, klen) == 0 && p[klen] == '=') {
            if (found) return -1;
            size_t vlen = linelen - klen - 1;
            if (vlen >= outsz) return -1;
            memcpy(out, p + klen + 1, vlen);
            out[vlen] = '\0';
            found = 1;
        }
        if (!nl) break;
        p = nl + 1;
    }
    return found ? 0 : -1;
}

/* Indexed key forms: build.argv.<n>.hex, source.file.<n>.*, artifact.<n>.*, test.<n>.* */
static bool indexed_ok(const char *key, const char *prefix, const char *const *tails, int ntails) {
    if (!starts(key, prefix)) return false;
    const char *p = key + strlen(prefix);
    if (*p < '0' || *p > '9') return false;
    long idx = 0;
    int digits = 0;
    while (*p >= '0' && *p <= '9') { idx = idx * 10 + (*p - '0'); p++; digits++; if (digits > 6) return false; }
    if (idx > 100000) return false;
    if (*p != '.') return false;
    p++;
    for (int i = 0; i < ntails; i++) if (strcmp(p, tails[i]) == 0) return true;
    return false;
}

static bool key_allowed(const char *k) {
    static const char *exact[] = {
        "schema_version", "build.origin", "build.argv_count", "build.cwd.hex",
        "build.started_unix", "build.elapsed_ms", "build.exit_status",
        "build.signaled", "build.signal", "build.stdout_sha256",
        "build.stdout_size", "build.stdout_truncated", "build.stderr_sha256",
        "build.stderr_size", "build.stderr_truncated", "source.git_head",
        "source.git_dirty", "source.file_count", "source.digest",
        "artifact_count", "test_count", "env.host_os.hex", "env.host_arch.hex",
        "qnx.host_present", "qnx.target_present",
        /* Level 4: expected-test declarations (expect-tests). */
        "expected_test_count", NULL};
    for (int i = 0; exact[i]; i++) if (strcmp(k, exact[i]) == 0) return true;
    if (starts(k, "blob.") && is_hex64(k + 5) && strlen(k) == 5 + 64) return true;
    static const char *argv_tails[] = {"hex"};
    if (indexed_ok(k, "build.argv.", argv_tails, 1)) return true;
    static const char *expected_test_tails[] = {"name.hex"};
    if (indexed_ok(k, "expected_test.", expected_test_tails, 1)) return true;
    if (starts(k, "test.") ) {
        static const char *tt[] = {"origin", "artifact_sha256", "report_sha256",
            "report_size", "argv_count", "started_unix", "elapsed_ms",
            "exit_status", "signaled", "signal", "stdout_sha256", "stdout_size",
            "stdout_truncated", "stderr_sha256", "stderr_size", "stderr_truncated",
            /* Level 4: host-vs-target enforcement, optional name, optional
             * structured (JSON) report adapter fields. */
            "runtime", "name.hex", "report_format", "report_passed", "report_case_count"};
        if (indexed_ok(k, "test.", tt, 21)) return true;
        /* test.<n>.argv.<m>.hex */
        const char *p = k + 5;
        if (*p >= '0' && *p <= '9') {
            while (*p >= '0' && *p <= '9') p++;
            if (starts(p, ".argv.")) {
                p += 6;
                if (*p >= '0' && *p <= '9') {
                    while (*p >= '0' && *p <= '9') p++;
                    if (strcmp(p, ".hex") == 0) return true;
                }
            }
        }
        return false;
    }
    static const char *sf_tails[] = {"path.hex", "sha256"};
    if (indexed_ok(k, "source.file.", sf_tails, 2)) return true;
    static const char *art_tails[] = {"name.hex", "role", "sha256", "size"};
    if (indexed_ok(k, "artifact.", art_tails, 4)) return true;
    return false;
}

/* Pure manifest tokenizer: line-splitting, line-length/line-count limits,
 * header capture, duplicate/unknown-key rejection, populating the global
 * key-value store. Returns false and sets out_code / out_exit / err instead
 * of exiting, so it can be driven directly by a libFuzzer harness (Level 6)
 * without killing the fuzzer process after one malformed input -- every
 * other FAIL call site in this file stays exiting, this is the one
 * untrusted-bytes-in boundary carved out on purpose. Caller still owns
 * freeing buf. */
static bool parse_manifest_buffer(const uint8_t *buf, size_t len,
                                   const char **out_code, int *out_exit,
                                   char *err, size_t errsz) {
    if (len == 0 || buf[len - 1] != '\n') {
        *out_code = "BUNDLE_INVALID"; *out_exit = 2;
        snprintf(err, errsz, "manifest must end with LF");
        return false;
    }
    size_t pos = 0;
    int lineno = 0;
    char header[64] = "";
    while (pos < len) {
        size_t start = pos;
        while (pos < len && buf[pos] != '\n') pos++;
        size_t linelen = pos - start;
        if (linelen >= MAX_LINE) {
            *out_code = "RESOURCE_LIMIT_EXCEEDED"; *out_exit = 6;
            snprintf(err, errsz, "manifest line too long");
            return false;
        }
        if (lineno >= MAX_LINES) {
            *out_code = "RESOURCE_LIMIT_EXCEEDED"; *out_exit = 6;
            snprintf(err, errsz, "too many manifest lines");
            return false;
        }
        char *line = xmalloc(linelen + 1);
        memcpy(line, buf + start, linelen);
        line[linelen] = '\0';
        for (size_t c = 0; c < linelen; c++) {
            if (buf[start + c] == '\r' || buf[start + c] == '\0') {
                free(line);
                *out_code = "BUNDLE_INVALID"; *out_exit = 2;
                snprintf(err, errsz, "manifest contains CR or NUL");
                return false;
            }
        }
        if (lineno == 0) {
            snprintf(header, sizeof(header), "%s", line);
        } else {
            char *eq = strchr(line, '=');
            if (!eq || eq == line) {
                free(line);
                *out_code = "BUNDLE_INVALID"; *out_exit = 2;
                snprintf(err, errsz, "manifest line %d is not key=value", lineno + 1);
                return false;
            }
            *eq = '\0';
            if (has_key(line)) {
                *out_code = "BUNDLE_INVALID"; *out_exit = 2;
                snprintf(err, errsz, "duplicate key %s", line);
                free(line);
                return false;
            }
            if (!key_allowed(line)) {
                *out_code = "BUNDLE_INVALID"; *out_exit = 2;
                snprintf(err, errsz, "unknown key %s", line);
                free(line);
                return false;
            }
            add_entry(line, eq + 1);
        }
        free(line);
        lineno++;
        pos++;
    }
    if (strcmp(header, "FUNES-BUNDLE-1") != 0) {
        *out_code = "BUNDLE_INVALID"; *out_exit = 2;
        snprintf(err, errsz, "bad manifest header");
        return false;
    }
    return true;
}

static void require_key(const char *k) {
    if (!has_key(k)) FAIL("BUNDLE_INVALID", 2, "missing required key %s", k);
}

static unsigned long long req_u64(const char *k) {
    const char *v = get_val(k);
    unsigned long long out = 0;
    if (!v || !parse_u64(v, &out)) FAIL("BUNDLE_INVALID", 2, "key %s is not a canonical unsigned integer", k);
    return out;
}

/* Signature phase exit helper: integrity already established by callers. */
static void sig_fail(const char *code, int ex, const char *testobs, const char *qnxf,
                     const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    g_code = code;
    g_exit = ex;
    snprintf(g_detail, sizeof(g_detail), "%s", buf);
    report_and_exit("INTEGRITY_VALID", "ALL_PRESENT", testobs, qnxf);
}

/* Guarded so a libFuzzer harness can #include this file and supply its own
 * main (LLVMFuzzerTestOneInput) without a symbol clash (Level 6). */
#ifndef FUNES_VERIFY_FUZZ_BUILD
int main(int argc, char **argv) {
    reset_manifest_store(); /* no-op here (process just started); keeps the
                              * function genuinely used in both build modes
                              * and exercised by the CLI's own test suite. */
    const char *bundle = NULL;
    const char *trusted_path = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--json") == 0) g_json = 1;
        else if (strcmp(argv[i], "--trusted-key") == 0 && i + 1 < argc) trusted_path = argv[++i];
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("usage: funes-verify [--json] [--trusted-key PUBFILE] BUNDLE_DIR\n");
            return 0;
        } else if (!bundle) bundle = argv[i];
        else { fprintf(stderr, "funes-verify: unexpected argument %s\n", argv[i]); return 1; }
    }
    if (!bundle) { fprintf(stderr, "usage: funes-verify [--json] [--trusted-key PUBFILE] BUNDLE_DIR\n"); return 1; }
    char mpath[PATH_MAX], spath[PATH_MAX], bdir[PATH_MAX];
    snprintf(mpath, sizeof(mpath), "%s/manifest.txt", bundle);
    snprintf(spath, sizeof(spath), "%s/SEAL.txt", bundle);
    snprintf(bdir, sizeof(bdir), "%s/blobs/sha256", bundle);
    struct stat st;
    /* Symlinked bundle structure is rejected: evidence must live in the
     * bundle, not point outside it (red-team round 1, finding RT-02). */
    {
        struct stat lst;
        char bpath[PATH_MAX], bspath[PATH_MAX];
        snprintf(bpath, sizeof(bpath), "%s/blobs", bundle);
        snprintf(bspath, sizeof(bspath), "%s/blobs/sha256", bundle);
        if (lstat(mpath, &lst) != 0) FAIL("BUNDLE_INVALID", 2, "manifest.txt missing in bundle %s", bundle);
        if (S_ISLNK(lst.st_mode) || !S_ISREG(lst.st_mode)) FAIL("BUNDLE_INVALID", 2, "manifest.txt must be a regular file, not a symlink");
        if (lstat(spath, &lst) == 0 && (S_ISLNK(lst.st_mode) || !S_ISREG(lst.st_mode))) FAIL("BUNDLE_INVALID", 2, "SEAL.txt must be a regular file, not a symlink");
        if (lstat(bpath, &lst) == 0 && (S_ISLNK(lst.st_mode) || !S_ISDIR(lst.st_mode))) FAIL("BUNDLE_INVALID", 2, "blobs must be a real directory, not a symlink or other object");
        if (lstat(bspath, &lst) == 0 && (S_ISLNK(lst.st_mode) || !S_ISDIR(lst.st_mode))) FAIL("BUNDLE_INVALID", 2, "blobs/sha256 must be a real directory, not a symlink or other object");
    }
    if (stat(mpath, &st) != 0) FAIL("BUNDLE_INVALID", 2, "manifest.txt missing in bundle %s", bundle);
    if ((unsigned long long)st.st_size > MAX_MANIFEST_BYTES)
        FAIL("RESOURCE_LIMIT_EXCEEDED", 6, "manifest exceeds %u bytes", MAX_MANIFEST_BYTES);
    size_t mlen = 0;
    uint8_t *mbuf = read_file(mpath, &mlen);
    if (!mbuf) FAIL("BUNDLE_INVALID", 2, "manifest.txt unreadable");
    /* Seal first: a tampered manifest is reported as SEAL_MISMATCH. */
    size_t slen = 0;
    uint8_t *sbuf = read_file(spath, &slen);
    if (!sbuf) FAIL("BUNDLE_INVALID", 2, "SEAL.txt missing");
    char mhex[65];
    hash_bytes(mbuf, mlen, mhex);
    if (slen != 64 + 2 + 12 + 1 || memcmp(sbuf, mhex, 64) != 0 ||
        memcmp(sbuf + 64, "  manifest.txt\n", 15) != 0) {
        FAIL("SEAL_MISMATCH", 7, "SEAL.txt does not commit to manifest.txt bytes");
    }
    free(sbuf);
    /* Tokenize: pure function so a libFuzzer harness can drive it directly
     * without the process exiting on malformed input (Level 6). */
    {
        const char *pcode; int pexit; char perr[256];
        bool pok = parse_manifest_buffer(mbuf, mlen, &pcode, &pexit, perr, sizeof(perr));
        free(mbuf);
        if (!pok) FAIL(pcode, pexit, "%s", perr);
    }
    const char *sv = get_val("schema_version");
    if (!sv) FAIL("BUNDLE_INVALID", 2, "missing schema_version");
    if (strcmp(sv, "2") != 0) FAIL("UNSUPPORTED_SCHEMA", 5, "unsupported schema_version %s", sv);
    static const char *req[] = {
        "build.origin", "build.argv_count", "build.cwd.hex", "build.started_unix",
        "build.elapsed_ms", "build.exit_status", "build.signaled", "build.signal",
        "build.stdout_sha256", "build.stdout_size", "build.stdout_truncated",
        "build.stderr_sha256", "build.stderr_size", "build.stderr_truncated",
        "source.git_head", "source.git_dirty", "source.file_count", "source.digest",
        "artifact_count", "test_count", "env.host_os.hex", "env.host_arch.hex",
        "qnx.host_present", "qnx.target_present", NULL};
    for (int i = 0; req[i]; i++) require_key(req[i]);
    if (strcmp(get_val("build.origin"), "OBSERVED") != 0)
        FAIL("BUNDLE_INVALID", 2, "build.origin must be OBSERVED");
    unsigned long long argc_b = req_u64("build.argv_count");
    if (argc_b == 0 || argc_b > 256) FAIL("BUNDLE_INVALID", 2, "build.argv_count out of range");
    for (unsigned long long i = 0; i < argc_b; i++) {
        char k[128];
        snprintf(k, sizeof(k), "build.argv.%llu.hex", i);
        require_key(k);
    }
    if (!is_hex64(get_val("build.stdout_sha256")) || !is_hex64(get_val("build.stderr_sha256")))
        FAIL("BUNDLE_INVALID", 2, "build stdout/stderr digest malformed");
    unsigned long long nart = req_u64("artifact_count");
    unsigned long long ntest = req_u64("test_count");
    if (nart > 1024 || ntest > 1024) FAIL("RESOURCE_LIMIT_EXCEEDED", 6, "artifact/test count too large");
    /* Collect artifact digests for test association checks. */
    char (*art_digests)[65] = xmalloc((nart ? nart : 1) * 65);
    for (unsigned long long i = 0; i < nart; i++) {
        char k[128];
        snprintf(k, sizeof(k), "artifact.%llu.sha256", i);
        require_key(k);
        const char *d = get_val(k);
        if (!is_hex64(d)) FAIL("BUNDLE_INVALID", 2, "artifact digest malformed");
        memcpy(art_digests[i], d, 65);
        snprintf(k, sizeof(k), "artifact.%llu.role", i);
        require_key(k);
        snprintf(k, sizeof(k), "artifact.%llu.name.hex", i);
        require_key(k);
        snprintf(k, sizeof(k), "artifact.%llu.size", i);
        req_u64(k);
    }
    /* Verify every blob line, then scan for unexpected files. */
    int nblobs = 0;
    for (size_t i = 0; i < g_count; i++) {
        if (!starts(g_entries[i].key, "blob.")) continue;
        nblobs++;
        const char *digest = g_entries[i].key + 5;
        unsigned long long sz = 0;
        const char *colon = strchr(g_entries[i].val, ':');
        if (!colon) FAIL("BUNDLE_INVALID", 2, "blob value malformed for %s", digest);
        char szbuf[32];
        size_t sl = (size_t)(colon - g_entries[i].val);
        if (sl == 0 || sl >= sizeof(szbuf)) FAIL("BUNDLE_INVALID", 2, "blob size malformed");
        memcpy(szbuf, g_entries[i].val, sl);
        szbuf[sl] = '\0';
        if (!parse_u64(szbuf, &sz)) FAIL("BUNDLE_INVALID", 2, "blob size malformed");
        const char *role = colon + 1;
        if (strcmp(role, "stdout") && strcmp(role, "stderr") && strcmp(role, "test-stdout") &&
            strcmp(role, "test-stderr") && strcmp(role, "artifact") && strcmp(role, "imported-report"))
            FAIL("BUNDLE_INVALID", 2, "unknown blob role %s", role);
        if (sz > MAX_BLOB_BYTES) FAIL("RESOURCE_LIMIT_EXCEEDED", 6, "blob %s exceeds size limit", digest);
        char bp[PATH_MAX + 128];
        snprintf(bp, sizeof(bp), "%s/%s", bdir, digest);
        struct stat bst;
        if (lstat(bp, &bst) != 0) {
            g_code = "MISSING_ARTIFACT"; g_exit = 4;
            snprintf(g_detail, sizeof(g_detail), "missing blob %s role %s", digest, role);
            report_and_exit("INTEGRITY_INVALID", "MISSING", "NOT_CHECKED", "NOT_CHECKED");
        }
        if (S_ISLNK(bst.st_mode)) FAIL("BUNDLE_INVALID", 2, "blob %s is a symlink", digest);
        if (!S_ISREG(bst.st_mode)) FAIL("BUNDLE_INVALID", 2, "blob %s is not a regular file", digest);
        /* Size from stat first: never stream an unbounded attacker file. */
        if ((unsigned long long)bst.st_size != sz) {
            g_code = "DIGEST_MISMATCH"; g_exit = 3;
            snprintf(g_detail, sizeof(g_detail), "blob %s size %lld does not match recorded %llu", digest, (long long)bst.st_size, sz);
            report_and_exit("INTEGRITY_INVALID", "DIGEST_MISMATCH", "NOT_CHECKED", "NOT_CHECKED");
        }
        char fh[65];
        unsigned long long fsz = 0;
        if (hash_file_stream(bp, fh, &fsz) != 0) FAIL("BUNDLE_INVALID", 2, "blob %s unreadable", digest);
        if (fsz != sz) {
            g_code = "DIGEST_MISMATCH"; g_exit = 3;
            snprintf(g_detail, sizeof(g_detail), "blob %s size %llu does not match recorded %llu", digest, fsz, sz);
            report_and_exit("INTEGRITY_INVALID", "DIGEST_MISMATCH", "NOT_CHECKED", "NOT_CHECKED");
        }
        if (strcmp(fh, digest) != 0) {
            g_code = "DIGEST_MISMATCH"; g_exit = 3;
            snprintf(g_detail, sizeof(g_detail), "blob bytes hash to %s, expected %s role %s", fh, digest, role);
            report_and_exit("INTEGRITY_INVALID", "DIGEST_MISMATCH", "NOT_CHECKED", "NOT_CHECKED");
        }
        (void)nblobs;
    }
    /* Referenced stdout/stderr must have blob lines. */
    char bk[256];
    snprintf(bk, sizeof(bk), "blob.%s", get_val("build.stdout_sha256"));
    if (!has_key(bk)) FAIL("BUNDLE_INVALID", 2, "build stdout blob not referenced");
    snprintf(bk, sizeof(bk), "blob.%s", get_val("build.stderr_sha256"));
    if (!has_key(bk)) FAIL("BUNDLE_INVALID", 2, "build stderr blob not referenced");
    for (unsigned long long i = 0; i < nart; i++) {
        snprintf(bk, sizeof(bk), "blob.%s", art_digests[i]);
        if (!has_key(bk)) FAIL("BUNDLE_INVALID", 2, "artifact %llu blob not referenced", i);
    }
    /* Unexpected files in the blob directory fail closed. Opened via
     * O_DIRECTORY|O_NOFOLLOW and fstat-checked on the resulting fd (not a
     * separate lstat+opendir) so there is no TOCTOU window between "this is
     * a real directory" and "this is what gets scanned" (round 1, RT-02
     * follow-up). */
    int bfd = open(bdir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (bfd < 0) FAIL("BUNDLE_INVALID", 2, "blob directory unreadable or not a directory");
    struct stat bfst;
    if (fstat(bfd, &bfst) != 0 || !S_ISDIR(bfst.st_mode)) {
        close(bfd);
        FAIL("BUNDLE_INVALID", 2, "blob directory is not a regular directory");
    }
    DIR *d = fdopendir(bfd);
    if (!d) { close(bfd); FAIL("BUNDLE_INVALID", 2, "blob directory unreadable"); }
    const struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        char k2[512];
        snprintf(k2, sizeof(k2), "blob.%s", de->d_name);
        if (!is_hex64(de->d_name) || !has_key(k2)) {
            closedir(d);
            FAIL("BUNDLE_INVALID", 2, "unexpected file %s in blob directory", de->d_name);
        }
    }
    closedir(d);
    /* Closed file inventory for the bundle root and signatures/ (round 1,
     * RT-06): nothing else may ride along inside a verified bundle. */
    {
        DIR *rd = opendir(bundle);
        if (!rd) FAIL("BUNDLE_INVALID", 2, "bundle directory unreadable");
        const struct dirent *re;
        while ((re = readdir(rd)) != NULL) {
            if (strcmp(re->d_name, ".") == 0 || strcmp(re->d_name, "..") == 0) continue;
            if (strcmp(re->d_name, "manifest.txt") && strcmp(re->d_name, "SEAL.txt") &&
                strcmp(re->d_name, "blobs") && strcmp(re->d_name, "signatures")) {
                closedir(rd);
                FAIL("BUNDLE_INVALID", 2, "unexpected file %s in bundle root", re->d_name);
            }
        }
        closedir(rd);
        char sdpath[PATH_MAX];
        snprintf(sdpath, sizeof(sdpath), "%s/signatures", bundle);
        /* Same O_NOFOLLOW + fstat(S_ISDIR) + fdopendir atomicity as the blob
         * directory above: a missing signatures/ is fine (unsigned bundle),
         * but anything present that is not a real directory (symlink to
         * outside the bundle, or a plain file) fails closed instead of
         * being silently followed by opendir(). */
        int sfd = open(sdpath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
        if (sfd >= 0) {
            struct stat sfst;
            if (fstat(sfd, &sfst) != 0 || !S_ISDIR(sfst.st_mode)) {
                close(sfd);
                FAIL("BUNDLE_INVALID", 2, "signatures is not a regular directory");
            }
            DIR *sd = fdopendir(sfd);
            if (!sd) { close(sfd); FAIL("BUNDLE_INVALID", 2, "signatures directory unreadable"); }
            const struct dirent *se;
            while ((se = readdir(sd)) != NULL) {
                if (strcmp(se->d_name, ".") == 0 || strcmp(se->d_name, "..") == 0) continue;
                if (strcmp(se->d_name, "ed25519.sig") && strcmp(se->d_name, "signer.txt")) {
                    closedir(sd);
                    FAIL("BUNDLE_INVALID", 2, "unexpected file %s in signatures directory", se->d_name);
                }
            }
            closedir(sd);
        } else if (errno != ENOENT) {
            FAIL("BUNDLE_INVALID", 2, "signatures must be a regular directory, not a symlink or other object");
        }
    }
    /* Test records: origins reported, never promoted; association checked.
     * Level 4 additions (schema v2): every test record must carry a
     * runtime=host|target token (host-vs-target distinction, never
     * inferred or defaulted), and we collect each test's optional
     * name.hex so the expected-test omission check below can cross-
     * reference against them. */
    bool any_test = false, any_observed = false;
    char (*test_names)[MAX_LINE] = NULL;
    unsigned long long ntest_names = 0;
    if (ntest > 0) test_names = xmalloc(ntest * sizeof(*test_names));
    for (unsigned long long i = 0; i < ntest; i++) {
        char k[128];
        snprintf(k, sizeof(k), "test.%llu.origin", i);
        require_key(k);
        const char *org = get_val(k);
        any_test = true;
        snprintf(k, sizeof(k), "test.%llu.artifact_sha256", i);
        require_key(k);
        const char *ad = get_val(k);
        bool linked = false;
        for (unsigned long long a = 0; a < nart; a++) if (strcmp(art_digests[a], ad) == 0) linked = true;
        if (!linked) FAIL("BUNDLE_INVALID", 2, "test %llu references unknown artifact digest", i);
        snprintf(k, sizeof(k), "test.%llu.runtime", i);
        require_key(k);
        const char *rt = get_val(k);
        if (strcmp(rt, "host") != 0 && strcmp(rt, "target") != 0)
            FAIL("BUNDLE_INVALID", 2, "test %llu has unknown runtime %s (must be host or target)", i, rt);
        if (strcmp(org, "OBSERVED") == 0) {
            any_observed = true;
            snprintf(k, sizeof(k), "test.%llu.stdout_sha256", i);
            require_key(k);
            snprintf(k, sizeof(k), "blob.%s", get_val(k));
            if (!has_key(k)) FAIL("BUNDLE_INVALID", 2, "test %llu stdout blob not referenced", i);
        } else if (strcmp(org, "IMPORTED") == 0) {
            snprintf(k, sizeof(k), "test.%llu.report_sha256", i);
            require_key(k);
        } else {
            FAIL("BUNDLE_INVALID", 2, "test %llu has unknown origin %s", i, org);
        }
        snprintf(k, sizeof(k), "test.%llu.report_format", i);
        if (has_key(k) && strcmp(get_val(k), "JSON") != 0)
            FAIL("BUNDLE_INVALID", 2, "test %llu has unknown report_format %s", i, get_val(k));
        snprintf(k, sizeof(k), "test.%llu.name.hex", i);
        if (has_key(k)) {
            snprintf(test_names[ntest_names], sizeof(test_names[ntest_names]), "%s", get_val(k));
            ntest_names++;
        }
    }
    const char *testobs = !any_test ? "NO_TEST_RECORD" : (any_observed ? "OBSERVED" : "IMPORTED_ONLY");
    /* Level 4: expected-test omission detection. A bundle may declare,
     * exactly once (funes expect-tests), the hex-encoded names it expects
     * to see among the test records above. Absence of expected_test_count
     * means no expectations were declared, which is a legitimate state,
     * not a finding. If declared, every one of them must match a
     * collected test name, or the bundle is missing evidence it claims to
     * need -- a hard failure, not a degraded status (fail-closed, same
     * philosophy as every other completeness check in this verifier). */
    if (has_key("expected_test_count")) {
        unsigned long long nexp = req_u64("expected_test_count");
        if (nexp > 1024) FAIL("RESOURCE_LIMIT_EXCEEDED", 6, "expected_test_count too large");
        for (unsigned long long i = 0; i < nexp; i++) {
            char k[128];
            snprintf(k, sizeof(k), "expected_test.%llu.name.hex", i);
            require_key(k);
            const char *want = get_val(k);
            bool found = false;
            for (unsigned long long t = 0; t < ntest_names; t++) {
                if (strcmp(test_names[t], want) == 0) { found = true; break; }
            }
            if (!found) {
                g_code = "MISSING_EXPECTED_TEST"; g_exit = 10;
                snprintf(g_detail, sizeof(g_detail), "expected test %llu (name.hex=%s) was never observed or imported", i, want);
                report_and_exit("INTEGRITY_INVALID", "NOT_CHECKED", testobs, "NOT_CHECKED");
            }
        }
    }
    free(test_names);
    int qh = strcmp(get_val("qnx.host_present"), "1") == 0;
    int qt2 = strcmp(get_val("qnx.target_present"), "1") == 0;
    const char *qnxf = (qh && qt2) ? "RECORDED_PRESENT_FLAGS" : "RECORDED_ABSENT_FLAGS";
    /* --- Signature phase (Level 3). Exactly what is signed: the bytes
     * "FUNES-SIGN-1\n" + manifest sha256 hex + "\n". The manifest in turn
     * binds every blob digest; signatures/ itself is not signed. --- */
    {
        char sigd[PATH_MAX], sigp[PATH_MAX + 64], txtp[PATH_MAX + 64];
        snprintf(sigd, sizeof(sigd), "%s/signatures", bundle);
        snprintf(sigp, sizeof(sigp), "%s/ed25519.sig", sigd);
        snprintf(txtp, sizeof(txtp), "%s/signer.txt", sigd);
        struct stat sst, tst;
        int has_sig = (lstat(sigp, &sst) == 0);
        int has_txt = (lstat(txtp, &tst) == 0);
        if (has_sig || has_txt) {
            if (!has_sig || !has_txt) {
                snprintf(g_sig, sizeof(g_sig), "INVALID");
                snprintf(g_trust, sizeof(g_trust), "UNTRUSTED_SIGNER");
                sig_fail("SIGNATURE_INVALID", 8, testobs, qnxf,
                         "incomplete signature material (need both ed25519.sig and signer.txt)");
            }
            if (S_ISLNK(tst.st_mode) || !S_ISREG(tst.st_mode)) {
                snprintf(g_sig, sizeof(g_sig), "INVALID");
                snprintf(g_trust, sizeof(g_trust), "UNTRUSTED_SIGNER");
                sig_fail("SIGNATURE_INVALID", 8, testobs, qnxf,
                         "signer.txt must be a regular file, not a symlink");
            }
            if (S_ISLNK(sst.st_mode) || !S_ISREG(sst.st_mode) || sst.st_size != 64) {
                snprintf(g_sig, sizeof(g_sig), "INVALID");
                snprintf(g_trust, sizeof(g_trust), "UNTRUSTED_SIGNER");
                sig_fail("SIGNATURE_INVALID", 8, testobs, qnxf,
                         "ed25519.sig must be a regular 64-byte file, not a symlink");
            }
            size_t tlen = 0;
            uint8_t *tbuf = read_file(txtp, &tlen);
            if (!tbuf || tlen > 4096) {
                snprintf(g_sig, sizeof(g_sig), "INVALID");
                sig_fail("SIGNATURE_INVALID", 8, testobs, qnxf, "signer.txt unreadable or oversized");
            }
            char v_alg[32] = "", v_man[128] = "", v_dom[64] = "", v_pk[128] = "", v_fp[128] = "";
            if (signer_get((const char *)tbuf, "algorithm", v_alg, sizeof(v_alg)) != 0 ||
                signer_get((const char *)tbuf, "manifest_sha256", v_man, sizeof(v_man)) != 0 ||
                signer_get((const char *)tbuf, "payload_domain", v_dom, sizeof(v_dom)) != 0 ||
                signer_get((const char *)tbuf, "signer_pubkey_hex", v_pk, sizeof(v_pk)) != 0 ||
                signer_get((const char *)tbuf, "signer_fingerprint_sha256", v_fp, sizeof(v_fp)) != 0) {
                free(tbuf);
                snprintf(g_sig, sizeof(g_sig), "INVALID");
                sig_fail("SIGNATURE_INVALID", 8, testobs, qnxf, "signer.txt is missing required fields");
            }
            free(tbuf);
            if (strcmp(v_alg, "ed25519") != 0 || strcmp(v_dom, "FUNES-SIGN-1") != 0) {
                snprintf(g_sig, sizeof(g_sig), "INVALID");
                sig_fail("SIGNATURE_INVALID", 8, testobs, qnxf,
                         "unsupported signature algorithm or domain (only ed25519/FUNES-SIGN-1 accepted)");
            }
            if (strcmp(v_man, mhex) != 0) {
                snprintf(g_sig, sizeof(g_sig), "INVALID");
                sig_fail("SIGNATURE_INVALID", 8, testobs, qnxf,
                         "signature commits to manifest %s, bundle manifest is %s", v_man, mhex);
            }
            uint8_t pk[32];
            if (hex_decode(v_pk, pk, 32) != 0) {
                snprintf(g_sig, sizeof(g_sig), "INVALID");
                sig_fail("SIGNATURE_INVALID", 8, testobs, qnxf, "signer_pubkey_hex malformed");
            }
            char real_fp[65];
            hash_bytes(pk, 32, real_fp);
            if (strcmp(v_fp, real_fp) != 0) {
                snprintf(g_sig, sizeof(g_sig), "INVALID");
                sig_fail("SIGNATURE_INVALID", 8, testobs, qnxf,
                         "signer fingerprint does not match signer public key");
            }
            snprintf(g_fp, sizeof(g_fp), "%s", real_fp);
            size_t siglen2 = 0;
            uint8_t *sigbuf = read_file(sigp, &siglen2);
            if (!sigbuf || siglen2 != 64) {
                snprintf(g_sig, sizeof(g_sig), "INVALID");
                sig_fail("SIGNATURE_INVALID", 8, testobs, qnxf, "ed25519.sig unreadable");
            }
            if (!sodium_verify_available()) {
                snprintf(g_sig, sizeof(g_sig), "UNVERIFIED");
                snprintf(g_trust, sizeof(g_trust), "UNTRUSTED_SIGNER");
                snprintf(g_detail, sizeof(g_detail),
                         "libsodium unavailable; signature present but not cryptographically verified");
                free(sigbuf);
                /* Integrity stands; authentication explicitly does not. */
                g_code = "";
                g_exit = 0;
                report_and_exit("INTEGRITY_VALID", "ALL_PRESENT", testobs, qnxf);
            }
            char payload[128];
            int plen = snprintf(payload, sizeof(payload), "FUNES-SIGN-1\n%s\n", mhex);
            int vok = g_verify_detached(sigbuf, (const uint8_t *)payload,
                                        (unsigned long long)plen, pk);
            free(sigbuf);
            if (vok != 0) {
                snprintf(g_sig, sizeof(g_sig), "INVALID");
                snprintf(g_trust, sizeof(g_trust), "UNTRUSTED_SIGNER");
                sig_fail("SIGNATURE_INVALID", 8, testobs, qnxf,
                         "Ed25519 signature does not verify under the signer public key in the bundle");
            }
            snprintf(g_sig, sizeof(g_sig), "VALID");
            if (trusted_path) {
                uint8_t tpk[32];
                if (read_trusted_pubkey(trusted_path, tpk) != 0) {
                    fprintf(stderr, "funes-verify: --trusted-key file %s is not 64 hex chars\n", trusted_path);
                    return 1;
                }
                if (memcmp(tpk, pk, 32) != 0) {
                    snprintf(g_trust, sizeof(g_trust), "UNTRUSTED_SIGNER");
                    sig_fail("SIGNER_UNTRUSTED", 9, testobs, qnxf,
                             "signer key does not match the supplied trusted key");
                }
                snprintf(g_trust, sizeof(g_trust), "TRUSTED_SIGNER");
            } else {
                snprintf(g_trust, sizeof(g_trust), "UNTRUSTED_SIGNER");
                snprintf(g_detail, sizeof(g_detail),
                         "signature valid under bundle signer key; no trusted key supplied, so origin is not authenticated");
            }
        } else {
            /* Signature phase genuinely ran and found neither file: this is
             * the one place NOT_PRESENT/NOT_APPLICABLE are actually earned. */
            snprintf(g_sig, sizeof(g_sig), "NOT_PRESENT");
            snprintf(g_trust, sizeof(g_trust), "NOT_APPLICABLE");
        }
    }
    g_code = "";
    g_exit = 0;
    report_and_exit("INTEGRITY_VALID", "ALL_PRESENT", testobs, qnxf);
    return 0;
}
#endif /* FUNES_VERIFY_FUZZ_BUILD */

