/* json_min - minimal, hardened JSON reader for the Level 4 structured test-
 * report adapter (funes import-test --format json). See ADR-003. Compiled
 * only into bin/funes: the verifier never re-parses this JSON, it only
 * validates the plain typed manifest keys the collector extracted from it
 * (docs/spec/EVIDENCE-BUNDLE-v2.md). Strict: generic recursive-descent value
 * parsing with an explicit depth counter (checked before each recursive
 * descent into an array or object, never relying on the OS stack guard
 * page), then a schema-specific pass rejects anything outside the accepted
 * shape (unknown/duplicate keys, wrong types, trailing data). */
#ifndef FUNES_JSON_MIN_H
#define FUNES_JSON_MIN_H

#include <stdbool.h>
#include <stddef.h>

typedef struct {
    char *name;   /* may be NULL if the case had no name -- never true for a
                   * successfully parsed report, since "cases[].name" is
                   * required; kept nullable only for a uniform free(). */
    bool passed;
} json_case;

typedef struct {
    char *name;         /* optional; NULL if the report omitted it */
    bool passed;
    json_case *cases;   /* may be NULL if case_count == 0 */
    size_t case_count;
} json_test_report;

/* Parses buf[0..len) as a strict test-report JSON document:
 *   {"name": "string" (optional), "passed": true|false (required),
 *    "cases": [{"name": "string", "passed": true|false}, ...] (optional)}
 * Top level must be an object; unknown or duplicate keys at any nesting
 * level are rejected; trailing non-whitespace bytes after the top-level
 * value are rejected. On success returns true and fills *out (the caller
 * must call json_test_report_free). On failure returns false and writes a
 * short, stable reason into err (err_size bytes); nothing the caller must
 * free is allocated in that case. */
bool json_test_report_parse(const char *buf, size_t len, json_test_report *out,
                             char *err, size_t err_size);
void json_test_report_free(json_test_report *r);

#endif
