/* funes-verify - independent verifier. Own parser, own SHA-256; shares no
 * object code with the collector (docs/spec/VERIFIER-SEMANTICS.md, ADR-001).
 * Read-only, offline, fail-closed. Never emits SAFE/TRUSTED. */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "sha256.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#define MAX_MANIFEST_BYTES (1024u * 1024u)
#define MAX_BLOB_BYTES (64ull * 1024ull * 1024ull)
#define MAX_LINES 10000
#define MAX_LINE 8192

static int g_json = 0;
static char g_detail[1024] = "";
static const char *g_code = "";
static int g_exit = 0;

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
        printf("{\"integrity_status\":\"%s\",\"signature_status\":\"NOT_PRESENT\","
               "\"signer_trust_status\":\"NOT_APPLICABLE\",\"artifact_status\":\"%s\","
               "\"test_observation_status\":\"%s\",\"qnx_toolchain_status\":\"%s\","
               "\"error_code\":\"%s\",\"detail\":\"%s\","
               "\"limitations\":\"integrity is not authenticity; authenticity would "
               "not prove execution; validity does not certify software safety\"}\n",
               integrity, art, testobs, qnxf, g_code, g_detail);
    } else {
        printf("integrity_status=%s\n", integrity);
        printf("signature_status=NOT_PRESENT\n");
        printf("signer_trust_status=NOT_APPLICABLE\n");
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
        "qnx.host_present", "qnx.target_present", NULL};
    for (int i = 0; exact[i]; i++) if (strcmp(k, exact[i]) == 0) return true;
    if (starts(k, "blob.") && is_hex64(k + 5) && strlen(k) == 5 + 64) return true;
    static const char *argv_tails[] = {"hex"};
    if (indexed_ok(k, "build.argv.", argv_tails, 1)) return true;
    if (starts(k, "test.") ) {
        static const char *tt[] = {"origin", "artifact_sha256", "report_sha256",
            "report_size", "argv_count", "started_unix", "elapsed_ms",
            "exit_status", "signaled", "signal", "stdout_sha256", "stdout_size",
            "stdout_truncated", "stderr_sha256", "stderr_size", "stderr_truncated"};
        if (indexed_ok(k, "test.", tt, 16)) return true;
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

static void require_key(const char *k) {
    if (!has_key(k)) FAIL("BUNDLE_INVALID", 2, "missing required key %s", k);
}

static unsigned long long req_u64(const char *k) {
    const char *v = get_val(k);
    unsigned long long out = 0;
    if (!v || !parse_u64(v, &out)) FAIL("BUNDLE_INVALID", 2, "key %s is not a canonical unsigned integer", k);
    return out;
}

int main(int argc, char **argv) {
    const char *bundle = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--json") == 0) g_json = 1;
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("usage: funes-verify [--json] BUNDLE_DIR\n");
            return 0;
        } else if (!bundle) bundle = argv[i];
        else { fprintf(stderr, "funes-verify: unexpected argument %s\n", argv[i]); return 1; }
    }
    if (!bundle) { fprintf(stderr, "usage: funes-verify [--json] BUNDLE_DIR\n"); return 1; }
    char mpath[PATH_MAX], spath[PATH_MAX], bdir[PATH_MAX];
    snprintf(mpath, sizeof(mpath), "%s/manifest.txt", bundle);
    snprintf(spath, sizeof(spath), "%s/SEAL.txt", bundle);
    snprintf(bdir, sizeof(bdir), "%s/blobs/sha256", bundle);
    struct stat st;
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
    /* Split lines strictly. */
    if (mlen == 0 || mbuf[mlen - 1] != '\n') FAIL("BUNDLE_INVALID", 2, "manifest must end with LF");
    size_t pos = 0;
    int lineno = 0;
    char header[64] = "";
    while (pos < mlen) {
        size_t start = pos;
        while (pos < mlen && mbuf[pos] != '\n') pos++;
        size_t linelen = pos - start;
        if (linelen >= MAX_LINE) FAIL("RESOURCE_LIMIT_EXCEEDED", 6, "manifest line too long");
        if (lineno >= MAX_LINES) FAIL("RESOURCE_LIMIT_EXCEEDED", 6, "too many manifest lines");
        char *line = xmalloc(linelen + 1);
        memcpy(line, mbuf + start, linelen);
        line[linelen] = '\0';
        for (size_t c = 0; c < linelen; c++) {
            if (mbuf[start + c] == '\r' || mbuf[start + c] == '\0')
                FAIL("BUNDLE_INVALID", 2, "manifest contains CR or NUL");
        }
        if (lineno == 0) {
            snprintf(header, sizeof(header), "%s", line);
        } else {
            char *eq = strchr(line, '=');
            if (!eq || eq == line) FAIL("BUNDLE_INVALID", 2, "manifest line %d is not key=value", lineno + 1);
            *eq = '\0';
            if (has_key(line)) FAIL("BUNDLE_INVALID", 2, "duplicate key %s", line);
            if (!key_allowed(line)) FAIL("BUNDLE_INVALID", 2, "unknown key %s", line);
            add_entry(line, eq + 1);
        }
        free(line);
        lineno++;
        pos++;
    }
    free(mbuf);
    if (strcmp(header, "FUNES-BUNDLE-1") != 0) FAIL("BUNDLE_INVALID", 2, "bad manifest header");
    const char *sv = get_val("schema_version");
    if (!sv) FAIL("BUNDLE_INVALID", 2, "missing schema_version");
    if (strcmp(sv, "1") != 0) FAIL("UNSUPPORTED_SCHEMA", 5, "unsupported schema_version %s", sv);
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
    /* Unexpected files in the blob directory fail closed. */
    DIR *d = opendir(bdir);
    if (!d) FAIL("BUNDLE_INVALID", 2, "blob directory unreadable");
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') continue;
        char k2[512];
        snprintf(k2, sizeof(k2), "blob.%s", de->d_name);
        if (!is_hex64(de->d_name) || !has_key(k2)) {
            closedir(d);
            FAIL("BUNDLE_INVALID", 2, "unexpected file %s in blob directory", de->d_name);
        }
    }
    closedir(d);
    /* Test records: origins reported, never promoted; association checked. */
    bool any_test = false, any_observed = false;
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
    }
    const char *testobs = !any_test ? "NO_TEST_RECORD" : (any_observed ? "OBSERVED" : "IMPORTED_ONLY");
    int qh = strcmp(get_val("qnx.host_present"), "1") == 0;
    int qt2 = strcmp(get_val("qnx.target_present"), "1") == 0;
    const char *qnxf = (qh && qt2) ? "RECORDED_PRESENT_FLAGS" : "RECORDED_ABSENT_FLAGS";
    g_code = "";
    g_exit = 0;
    report_and_exit("INTEGRITY_VALID", "ALL_PRESENT", testobs, qnxf);
    return 0;
}

