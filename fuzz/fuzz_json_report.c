/* libFuzzer target for the JSON test-report parser (Level 6). json_min.c has
 * no main() to collide with and json_test_report_parse() is already a pure,
 * non-exiting function (ADR-003) -- no refactor needed, unlike the manifest
 * tokenizer. Extends the hand-run adversarial cases from Red Team Round 2
 * (RT2-02 et al.) with automated mutation; see docs/security/FUZZING.md. */
#include "../src/json_min.c"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    json_test_report out;
    char err[256];
    if (json_test_report_parse((const char *)data, size, &out, err, sizeof(err)))
        json_test_report_free(&out);
    return 0;
}
