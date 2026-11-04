/* libFuzzer target for the manifest tokenizer (Level 6). Whitebox-includes
 * the verifier's own .c file under FUNES_VERIFY_FUZZ_BUILD, which compiles
 * out main() so this harness's own LLVMFuzzerTestOneInput is the only entry
 * point -- no new public symbols, no library split, same independence
 * contract the verifier already has (docs/spec/VERIFIER-SEMANTICS.md).
 * Scope: only parse_manifest_buffer(), the untrusted-bytes-in tokenizer.
 * Everything after tokenization operates on an already-validated key-value
 * store and is out of scope for this target (see docs/security/FUZZING.md).
 */
#define FUNES_VERIFY_FUZZ_BUILD
#include "../verifier/funes_verify.c"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    reset_manifest_store();
    if (size > MAX_MANIFEST_BYTES) return 0; /* mirrors the real stat-first cap */
    const char *code;
    int ex;
    char err[256];
    parse_manifest_buffer(data, size, &code, &ex, err, sizeof(err));
    return 0;
}
